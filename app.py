import os
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import random
import string
import time
import functools
from functools import wraps

# Flask and extensions
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import OperationalError, SQLAlchemyError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
logger.addHandler(handler)

# Initialize Flask app
def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions
app = Flask(__name__)

# Configure app
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///chat.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=os.path.join('static', 'uploads'),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
bcrypt = Bcrypt(app)
mail = Mail(app)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configure token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def retry_on_db_error(max_retries=5, initial_delay=0.1):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    if retries > 0:
                        db.session.remove()
                        db.engine.dispose()
                    return f(*args, **kwargs)
                except (OperationalError, SQLAlchemyError) as e:
                    retries += 1
                    if retries == max_retries:
                        logger.error(f"Database operation failed after {max_retries} retries: {str(e)}")
                        raise
                    delay = initial_delay * (2 ** (retries - 1))
                    logger.warning(f"Database operation failed, attempt {retries} of {max_retries}, retrying in {delay:.2f}s: {str(e)}")
                    time.sleep(delay)
            return None
        return wrapper
    return decorator

# Models
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    permissions = db.relationship('Permission', secondary='role_permissions', back_populates='roles')
    users = db.relationship('User', secondary='user_roles', back_populates='roles')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    roles = db.relationship('Role', secondary='role_permissions', back_populates='permissions')

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id', ondelete='CASCADE'), primary_key=True)
)

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_moderator = db.Column(db.Boolean, default=False)
    
    # Core profile fields
    display_name = db.Column(db.String(50))
    avatar = db.Column(db.String(200))
    accent_color = db.Column(db.String(7), default='#5865F2')
    bio = db.Column(db.String(500))
    
    # Status and Presence
    status = db.Column(db.String(100))
    presence_state = db.Column(db.String(20), default='online')
    
    # Settings
    profile_theme = db.Column(db.String(20), default='dark')
    preferences = db.Column(db.JSON, default={})
    
    # System Fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    muted_until = db.Column(db.DateTime)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100))
    verification_sent_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime)
    warning_count = db.Column(db.Integer, default=0)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    verification_token = db.Column(db.String(100))
    verification_sent_at = db.Column(db.DateTime)
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy='dynamic')

    def set_password(self, password):
        if not self.validate_password_strength(password):
            raise ValueError("Password does not meet strength requirements")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_password_strength(password):
        if len(password) < 6:
            return False
        conditions = [
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password)
        ]
        return sum(conditions) >= 2

    def to_dict(self, include_private=False):
        """Convert user object to dictionary with basic profile structure."""
        data = {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name or self.username,
            'avatar': self.avatar,
            'accent_color': self.accent_color,
            'profile_theme': self.profile_theme,
            'status': self.status,
            'presence_state': self.presence_state,
            'bio': self.bio,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_verified': self.is_verified,
            'roles': [{'id': role.id, 'name': role.name} for role in self.roles]
        }

        if include_private:
            data.update({
                'email': self.email,
                'preferences': self.preferences or {},
            })

        return data
        
    def update_presence(self, state='online'):
        """Update user's presence state."""
        valid_states = {'online', 'idle', 'dnd', 'offline'}
        if state not in valid_states:
            raise ValueError(f"Invalid presence state. Must be one of: {', '.join(valid_states)}")
        self.presence_state = state
        
    def set_status(self, text=None):
        """Set user's status message."""
        if text and len(text) > 100:
            raise ValueError("Status text cannot exceed 100 characters")
        self.status = text

    def is_muted(self):
        if self.muted_until and self.muted_until > datetime.utcnow():
            return True
        return False

    def has_permission(self, permission_name):
        return any(
            any(p.name == permission_name for p in role.permissions)
            for role in self.roles
        )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
        return email
    except:
        return None

def send_password_reset_email(user):
    try:
        token = generate_reset_token(user.email)
        reset_url = url_for('reset_password', token=token, _external=True)
        msg = Message(
            subject='Password Reset Request',
            recipients=[user.email],
            body=f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, please ignore this email.
'''
        )
        mail.send(msg)
        logger.info(f"Password reset email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        return False

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/profile')
@login_required
def profile():
    """Render user's profile page"""
    return render_template('profile.html', user=current_user)

@app.route('/api/profile', methods=['GET', 'PATCH'])
@login_required
def manage_profile():
    """Get or update user profile"""
    if request.method == 'GET':
        return jsonify(current_user.to_dict(include_private=True))
    
    try:
        data = request.get_json()
        
        # Update allowed fields
        allowed_fields = ['display_name', 'bio', 'theme', 'accent_color']
        for field in allowed_fields:
            if field in data:
                setattr(current_user, field, data[field])
        
        db.session.commit()
        return jsonify(current_user.to_dict()), 200
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

@app.route('/api/profile/presence', methods=['PATCH'])
@login_required
def update_presence():
    """Update user's presence state"""
    try:
        data = request.get_json()
        state = data.get('state', 'online')
        current_user.update_presence(state=state)
        db.session.commit()
        return jsonify(current_user.to_dict())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Presence update error: {str(e)}")
        return jsonify({'error': 'Failed to update presence'}), 500

@app.route('/api/profile/status', methods=['PATCH'])
@login_required
def update_status():
    """Update user's custom status"""
    try:
        data = request.get_json()
        text = data.get('status')
        current_user.set_status(text=text)
        db.session.commit()
        return jsonify(current_user.to_dict())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Status update error: {str(e)}")
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/api/profile/avatar', methods=['POST'])
@login_required
def update_avatar():
    """Update user's avatar"""
    if 'avatar' not in request.files:
        return jsonify({'error': 'No avatar file provided'}), 400
        
    file = request.files['avatar']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename, {'png', 'jpg', 'jpeg', 'gif'}):
        try:
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"avatar_{current_user.id}_{timestamp}_{filename}"
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.avatar = url_for('static', filename=f'uploads/{filename}')
            
            db.session.commit()
            return jsonify(current_user.to_dict())
        except Exception as e:
            db.session.rollback()
            logger.error(f"Avatar update error: {str(e)}")
            return jsonify({'error': 'Failed to update avatar'}), 500
            
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        logger.info(f"Login attempt for email: {email}")

        if not all([email, password]):
            logger.warning("Login failed: Missing email or password")
            flash('All fields are required', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user:
            if user.check_password(password):
                login_user(user)
                logger.info(f"User {user.username} logged in successfully")
                return redirect(url_for('index'))
            else:
                logger.warning(f"Login failed: Invalid password for user {user.username}")
        else:
            logger.warning(f"Login failed: No user found with email {email}")

        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@logout_required
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([username, email, password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')

        if not User.validate_password_strength(password):
            flash('Password must be at least 6 characters and contain at least 2 of the following: uppercase letters, lowercase letters, numbers', 'error')
            return render_template('register.html')

        new_user = User(
            username=username,
            email=email,
            presence_state='online',
            status='Available'
        )
        new_user.set_password(password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration.', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
@logout_required
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Please enter a valid email address.', 'error')
            return render_template('forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            if user.verification_sent_at and \
               (datetime.utcnow() - user.verification_sent_at).total_seconds() < 300:
                flash('A reset link was recently sent. Please wait 5 minutes before requesting another.', 'info')
                return render_template('forgot_password.html')
            
            if send_password_reset_email(user):
                user.verification_sent_at = datetime.utcnow()
                db.session.commit()
                flash('If an account exists with this email, you will receive password reset instructions.', 'success')
            else:
                flash('An error occurred while sending the reset email. Please try again later.', 'error')
        else:
            time.sleep(1)  # Security delay
            flash('If an account exists with this email, you will receive password reset instructions.', 'success')
            
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@logout_required
def reset_password(token):
    try:
        email = verify_reset_token(token)
        if not email:
            flash('Invalid or expired reset link. Please request a new one.', 'error')
            return redirect(url_for('forgot_password'))
            
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'error')
            return redirect(url_for('forgot_password'))
            
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not password or not confirm_password:
                flash('Both password fields are required.', 'error')
                return render_template('reset_password.html', token=token)
                
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return render_template('reset_password.html', token=token)
                
            try:
                user.set_password(password)
                db.session.commit()
                flash('Your password has been reset successfully. Please login with your new password.', 'success')
                return redirect(url_for('login'))
            except ValueError as e:
                flash(str(e), 'error')
                return render_template('reset_password.html', token=token)
            except Exception as e:
                logger.error(f"Error resetting password: {str(e)}")
                flash('An error occurred while resetting your password. Please try again.', 'error')
                return render_template('reset_password.html', token=token)
                
        return render_template('reset_password.html', token=token)
        
    except Exception as e:
        logger.error(f"Error processing password reset: {str(e)}")
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('forgot_password'))

@app.route('/api/user/profile')
@login_required
def get_current_user_profile():
    """Get the current user's complete profile"""
    return jsonify(current_user.to_dict(include_private=True))

@app.route('/api/user/profile/<int:user_id>')
@login_required
def get_user_profile_by_id(user_id):
    """Get another user's public profile"""
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict(include_private=False))

# Routes moved and consolidated under /api/profile/ namespace

@app.route('/api/user/update_theme', methods=['POST'])
@login_required
def update_theme():
    data = request.get_json()
    current_user.profile_theme = data.get('profile_theme')
    current_user.accent_color = data.get('accent_color')
    db.session.commit()
    return jsonify(current_user.to_dict())

@app.route('/api/user/update_connections', methods=['POST'])
@login_required
def update_connections():
    data = request.get_json()
    current_user.connections = data
    db.session.commit()
    return jsonify(current_user.to_dict())
class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    type = db.Column(db.String(20), default='text')  # text, voice, announcement
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy='dynamic')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 'public', 'private', 'system', 'voice', 'reply', 'forward'
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # For private messages
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))  # Channel where message was sent
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200))  # For file attachments
    voice_url = db.Column(db.String(200))  # For voice messages
    voice_duration = db.Column(db.Float)  # Duration of voice message in seconds
    reactions = db.Column(db.JSON, default=dict)
    is_encrypted = db.Column(db.Boolean, default=True)  # Whether the message is encrypted
    encryption_key = db.Column(db.Text, nullable=True)  # Encrypted symmetric key for the message
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)  # For reply functionality
    forwarded_from_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)  # For forwarding functionality
    thread_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)  # For message threading
    is_edited = db.Column(db.Boolean, default=False)  # Track if message has been edited

    # Add relationships for replies and forwarded messages
    replies = db.relationship('Message', backref=db.backref('reply_to', remote_side=[id]),
                              foreign_keys=[reply_to_id])
    forwarded_messages = db.relationship('Message', backref=db.backref('forwarded_from', remote_side=[id]),
                                         foreign_keys=[forwarded_from_id])
    thread_messages = db.relationship('Message', backref=db.backref('thread_parent', remote_side=[id]),
                                      foreign_keys=[thread_id])

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'channel_id': self.channel_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration,
            'reactions': {} if self.reactions is None else self.reactions,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key if self.is_encrypted else None,
            'reply_to_id': self.reply_to_id,
            'forwarded_from_id': self.forwarded_from_id,
            'thread_id': self.thread_id,
            'is_edited': self.is_edited,
            'reply_to': self.reply_to.to_dict() if self.reply_to_id and self.reply_to else None,
            'forwarded_from': self.forwarded_from.to_dict() if self.forwarded_from_id and self.forwarded_from else None
        }


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create a test user if none exists
        if not User.query.filter_by(email='test@example.com').first():
            test_user = User(
                username='testuser',
                email='test@example.com',
                presence_state='online',
                bio='Test user account',
                status='Available'
            )
            test_user.set_password('Test123')  # Meets requirements: uppercase, lowercase, and numbers
            db.session.add(test_user)
            try:
                db.session.commit()
                logger.info("Created test user: test@example.com / Test123")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to create test user: {str(e)}")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)