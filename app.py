from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message as MailMessage
from flask_migrate import Migrate
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime, timedelta
import os
import logging
from logging.handlers import RotatingFileHandler

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
mail = Mail(app)

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Application startup')

logger = logging.getLogger(__name__)

# Models
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    users = db.relationship('User', secondary=user_roles, backref=db.backref('roles', lazy='dynamic'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    bio = db.Column(db.Text)
    location = db.Column(db.String(100))
    status = db.Column(db.String(100))
    presence_state = db.Column(db.String(20), default='online')
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, password):
        if not password:
            raise ValueError("Password cannot be empty")
        hashed = bcrypt.generate_password_hash(password)
        self.password_hash = hashed.decode('utf-8') if isinstance(hashed, bytes) else hashed
        logger.info(f"Password hash generated, length: {len(self.password_hash)}")

    def check_password(self, password):
        if not self.password_hash:
            logger.error("No password hash stored for user")
            return False
        try:
            return bcrypt.check_password_hash(self.password_hash, password)
        except Exception as e:
            logger.error(f"Error checking password: {str(e)}")
            return False

    def to_dict(self):
        """Convert user object to dictionary with only existing columns"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'bio': self.bio,
            'location': self.location,
            'status': self.status,
            'presence_state': self.presence_state,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat(),
            'roles': [role.name for role in self.roles]
        }

class Category(db.Model):
    """Category model for organizing channels"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    channels = db.relationship('Channel', backref='category', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'channels': [channel.to_dict() for channel in self.channels],
            'created_at': self.created_at.isoformat()
        }

class Channel(db.Model):
    """Channel model for chat rooms"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category_id': self.category_id,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat()
        }

class Message(db.Model):
    """Message model for chat communication"""
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200))
    voice_url = db.Column(db.String(200))
    voice_duration = db.Column(db.Float)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text)

    # Relationships
    sender = db.relationship('User', backref=db.backref('messages', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'channel_id': self.channel_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat(),
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key
        }

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            logger.info(f"Found user {user.username}, verifying password")
            stored_hash = user.password_hash
            logger.info(f"Stored hash length: {len(stored_hash) if stored_hash else 'None'}")
            
            try:
                is_valid = user.check_password(password)
                logger.info(f"Password verification result: {is_valid}")
                if is_valid:
                    login_user(user)
                    logger.info(f"User {user.username} logged in successfully")
                    return redirect(url_for('index'))
                else:
                    logger.warning(f"Login failed: Invalid password for user {user.username}")
            except Exception as e:
                logger.error(f"Password verification error: {str(e)}")
                flash('An error occurred during login', 'error')
                return redirect(url_for('login'))
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
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during registration: {str(e)}")
            flash('An error occurred during registration', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        try:
            current_user.bio = request.form.get('bio', '')
            current_user.location = request.form.get('location', '')
            db.session.commit()
            flash('Profile updated successfully', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error updating profile: {str(e)}")
            flash('An error occurred while updating your profile', 'error')
    return render_template('profile.html')

@app.route('/update_status', methods=['POST'])
@login_required
def update_status():
    try:
        if 'status' in request.form:
            current_user.status = request.form['status']
        if 'presence_state' in request.form:
            current_user.presence_state = request.form['presence_state']
        
        db.session.commit()
        return jsonify({'message': 'Status updated successfully'})
    except Exception as e:
        logger.error(f"Error updating status: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/update_avatar', methods=['POST'])
@login_required
def update_avatar():
    try:
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                filename = secure_filename(f"avatar_{current_user.id}_{int(datetime.utcnow().timestamp())}.{file.filename.rsplit('.', 1)[1]}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.avatar = f"/static/uploads/{filename}"
                db.session.commit()
                return jsonify({'message': 'Avatar updated successfully'})
        return jsonify({'error': 'No valid image provided'}), 400
    except Exception as e:
        logger.error(f"Error updating avatar: {str(e)}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update avatar'}), 500

# Socket event handlers
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        emit('user_connected', current_user.to_dict())

@socketio.on('get_categories')
def handle_get_categories():
    categories = Category.query.all()
    emit('categories_list', {
        'categories': [category.to_dict() for category in categories]
    })

@socketio.on('join_channel')
def handle_join_channel(data):
    if not current_user.is_authenticated:
        return
    
    channel_id = data.get('channel_id')
    if channel_id:
        channel = Channel.query.get(channel_id)
        if channel:
            join_room(f'channel_{channel_id}')
            messages = Message.query.filter_by(channel_id=channel_id).order_by(Message.timestamp.desc()).limit(50).all()
            emit('channel_history', {
                'channel_id': channel_id,
                'messages': [msg.to_dict() for msg in messages]
            })

@socketio.on('leave_channel')
def handle_leave_channel(data):
    if not current_user.is_authenticated:
        return
    
    channel_id = data.get('channel_id')
    if channel_id:
        leave_room(f'channel_{channel_id}')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
