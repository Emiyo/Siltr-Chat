from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, abort, current_app
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError
import os
import json
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Configure logging
if not os.path.exists('logs'):
    os.makedirs('logs', exist_ok=True)

file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    manage_session=True,
    ping_timeout=5000,
    ping_interval=25000
)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logger.info('Application startup')


# User roles association table
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), nullable=True)
    display_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(200), nullable=True)
    presence_state = db.Column(db.String(20), nullable=False, server_default='online')
    accent_color = db.Column(db.String(7), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                          backref=db.backref('users', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'display_name': self.display_name,
            'status': self.status,
            'presence_state': self.presence_state,
            'accent_color': self.accent_color,
            'bio': self.bio,
            'location': self.location,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat(),
            'roles': [role.name for role in self.roles]
        }

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

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name
        }

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    channels = db.relationship('Channel', backref='category', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) #Retained from original

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'channels': [channel.to_dict() for channel in self.channels],
            'created_at': self.created_at.isoformat() #Retained from original
        }

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='channel', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) #Retained from original

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category_id': self.category_id,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat() #Retained from original
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text, nullable=True)
    file_url = db.Column(db.String(200)) #Retained from original
    voice_url = db.Column(db.String(200)) #Retained from original
    voice_duration = db.Column(db.Float) #Retained from original

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'channel_id': self.channel_id,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key,
            'file_url': self.file_url, #Retained from original
            'voice_url': self.voice_url, #Retained from original
            'voice_duration': self.voice_duration #Retained from original
        }

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Routes (from original)
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
def handle_connect(auth=None):
    """Handle client connection"""
    try:
        logger.info("Client connecting with auth: %s", auth)
        if current_user.is_authenticated:
            logger.info("Authenticated user connecting: %s", current_user.username)
            join_room(f'user_{current_user.id}')
            emit('user_connected', current_user.to_dict())
            
            # Send initial user list
            users = User.query.all()
            logger.info("Sending user list with %d users", len(users))
            emit('user_list', {'users': [user.to_dict() for user in users]})
            
            # Send categories list
            categories = Category.query.all()
            logger.info("Sending categories list with %d categories", len(categories))
            emit('categories_list', {'categories': [category.to_dict() for category in categories]})
            
            logger.info("Client connected successfully: %s", current_user.username)
        else:
            logger.warning("Unauthenticated client attempting to connect")
    except Exception as e:
        logger.error("Error in handle_connect: %s", str(e), exc_info=True)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        if current_user.is_authenticated:
            logger.info("User disconnecting: %s", current_user.username)
            leave_room(f'user_{current_user.id}')
            emit('user_disconnected', current_user.to_dict(), broadcast=True)
            logger.info("User disconnected: %s", current_user.username)
    except Exception as e:
        logger.error("Error in handle_disconnect: %s", str(e), exc_info=True)

@socketio.on('get_categories')
def handle_get_categories():
    """Handle request for categories list"""
    try:
        logger.info("Fetching categories")
        categories = Category.query.all()
        categories_data = [category.to_dict() for category in categories]
        logger.info("Categories query successful, found %d categories", len(categories))
        
        emit('categories_list', {
            'categories': categories_data
        })
        logger.info("Categories list sent successfully")
    except Exception as e:
        logger.error("Error fetching categories: %s", str(e), exc_info=True)
        emit('error', {'message': 'Failed to fetch categories'})

@socketio.on('get_user_list')
def handle_get_user_list():
    """Handle request for user list"""
    try:
        logger.info("Fetching user list")
        if not current_user.is_authenticated:
            logger.warning("Unauthenticated user attempting to fetch user list")
            return
        
        users = User.query.all()
        users_data = [user.to_dict() for user in users]
        logger.info("User list query successful, found %d users", len(users))
        
        emit('user_list', {'users': users_data})
        logger.info("User list sent successfully")
    except Exception as e:
        logger.error("Error fetching user list: %s", str(e), exc_info=True)
        emit('error', {'message': 'Failed to fetch user list'})

@socketio.on('update_presence')
def handle_update_presence(data):
    """Handle user presence update"""
    logger.info("Updating presence for user: %s", current_user.username if current_user.is_authenticated else None)
    if current_user.is_authenticated:
        presence_state = data.get('presence_state', 'online')
        current_user.presence_state = presence_state
        db.session.commit()
        # Broadcast updated user list to all connected clients
        users = User.query.all()
        emit('user_list', {'users': [user.to_dict() for user in users]}, broadcast=True)
        logger.info("Presence updated and broadcast: %s", presence_state)

@socketio.on('join_channel')
def handle_join_channel(data):
    """Handle joining a channel"""
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
    """Handle leaving a channel"""
    if not current_user.is_authenticated:
        return
    
    channel_id = data.get('channel_id')
    if channel_id:
        leave_room(f'channel_{channel_id}')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)