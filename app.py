# Configure eventlet first
import eventlet
eventlet.monkey_patch(os=True, select=True, socket=True, thread=True, time=True)

import logging
import os
import json
from datetime import datetime

# Flask imports after monkey patch
from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, abort, current_app
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
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
# GitHub OAuth Configuration
app.config['GITHUB_CLIENT_ID'] = os.environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_CALLBACK_URL'] = os.environ.get('GITHUB_CALLBACK_URL', 'http://localhost:5000/auth/github/callback')
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
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize SocketIO after Flask app and extensions
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    logger=True,
    engineio_logger=True,
    manage_session=False,
    async_mode='eventlet',
    ping_timeout=5000,
    ping_interval=25000,
    reconnection=True,
    reconnection_attempts=5,
    reconnection_delay=1000,
    reconnection_delay_max=5000
)


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
    accent_color = db.Column(db.String(7), nullable=True)
    theme = db.Column(db.String(20), nullable=False, server_default='dark')
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    banner_color = db.Column(db.String(7), nullable=True, server_default='#5865F2')
    custom_status = db.Column(db.String(128), nullable=True)
    status_emoji = db.Column(db.String(32), nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    
    # Connection integrations
    github_id = db.Column(db.String(100), nullable=True, unique=True)
    github_username = db.Column(db.String(100), nullable=True)
    spotify_id = db.Column(db.String(100), nullable=True, unique=True)
    spotify_display_name = db.Column(db.String(100), nullable=True)
    discord_id = db.Column(db.String(100), nullable=True, unique=True)
    discord_username = db.Column(db.String(100), nullable=True)
    
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                          backref=db.backref('users', lazy=True))
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'display_name': self.display_name or self.username,
            'status': self.status or '',
            'accent_color': self.accent_color or '#5865F2',
            'bio': self.bio or '',
            'location': self.location or '',
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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'channels': [channel.to_dict() for channel in self.channels],
            'created_at': self.created_at.isoformat()
        }

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    messages = db.relationship('Message', backref='channel', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category_id': self.category_id,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat()
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text, nullable=True)
    file_url = db.Column(db.String(200))
    voice_url = db.Column(db.String(200))
    voice_duration = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'channel_id': self.channel_id,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key,
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration
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
    if request.method == 'GET' and request.headers.get('Accept') == 'application/json':
        return jsonify({
            'theme': current_user.theme,
            'accent_color': current_user.accent_color
        })
    elif request.method == 'POST':
        try:
            # Update basic profile information
            current_user.bio = request.form.get('bio', '')
            current_user.location = request.form.get('location', '')
            current_user.display_name = request.form.get('display_name', '')
            current_user.banner_color = request.form.get('banner_color', '#5865F2')
            current_user.accent_color = request.form.get('accent_color', '')
            
            # Update custom status with emoji support
            custom_status = request.form.get('custom_status', '')
            status_emoji = request.form.get('status_emoji', '')
            if custom_status or status_emoji:
                current_user.custom_status = custom_status
                current_user.status_emoji = status_emoji
            
            db.session.commit()
            flash('Profile updated successfully', 'success')
            return jsonify({'success': True, 'message': 'Profile updated successfully'})
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Error updating profile: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred while updating your profile'}), 500
    return render_template('profile.html')

@app.route('/update_status', methods=['POST'])
@app.route('/update_theme', methods=['POST'])
@login_required
def update_theme():
    try:
        data = request.get_json()
        theme = data.get('theme')
        accent_color = data.get('accent_color')
        
        if theme:
            if theme in ['dark', 'light', 'midnight', 'sunset', 'custom']:
                current_user.theme = theme
            else:
                return jsonify({'success': False, 'message': 'Invalid theme'}), 400
                
        if accent_color:
            # Validate hex color format
            if re.match(r'^#(?:[0-9a-fA-F]{3}){1,2}$', accent_color):
                current_user.accent_color = accent_color
            else:
                return jsonify({'success': False, 'message': 'Invalid accent color format'}), 400
        
        db.session.commit()
        logger.info(f"Theme updated for user {current_user.username}: theme={theme}, accent_color={accent_color}")
        return jsonify({'success': True, 'message': 'Theme updated successfully'})
        
    except Exception as e:
        logger.error(f"Error updating theme: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to update theme'}), 500

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
    """Handle client connection"""
    try:
        if not current_user.is_authenticated:
            logger.warning("Unauthenticated client attempting to connect")
            return False
        
        logger.info("Authenticated user connecting: %s", current_user.username)
        
        # Only update last_seen timestamp
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        logger.info(f"Current presence state for {current_user.username}: {current_user.presence_state}")
        
        # Send initial user data without modifying presence
        user_data = current_user.to_dict()
        logger.info("Sending user data: %s", user_data)
        emit('user_connected', user_data)
        
        # Send initial user list
        users = User.query.all()
        users_data = [user.to_dict() for user in users]
        logger.info("Sending user list with %d users", len(users_data))
        emit('user_list', {'users': users_data})
        
        # Send categories list
        categories = Category.query.all()
        categories_data = [category.to_dict() for category in categories]
        logger.info("Sending categories list with %d categories", len(categories_data))
        emit('categories_list', {'categories': categories_data})
        
        # Join user's room
        join_room(f'user_{current_user.id}')
        logger.info("Client connected successfully: %s", current_user.username)
        return True
        
    except Exception as e:
        logger.error("Error in handle_connect: %s", str(e), exc_info=True)
        emit('error', {'message': 'Failed to initialize connection'})
        return False

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
        categories_data = []
        
        for category in categories:
            try:
                category_dict = category.to_dict()
                categories_data.append(category_dict)
            except Exception as e:
                logger.error(f"Error converting category to dict: {str(e)}")
                continue
        
        logger.info("Categories query successful, found %d categories", len(categories))
        
        # Create default category if none exist
        if not categories_data:
            logger.info("No categories found, creating default category")
            try:
                default_category = Category.query.filter_by(name="General").first()
                if not default_category:
                    default_category = Category(name="General")
                    db.session.add(default_category)
                    db.session.commit()
                    logger.info("Created default category")
                categories_data = [default_category.to_dict()]
            except Exception as e:
                logger.error(f"Failed to create default category: {str(e)}")
                db.session.rollback()
                emit('error', {'message': 'Failed to initialize categories'})
                return
        
        emit('categories_list', {
            'categories': categories_data
        })
        logger.info("Categories list sent successfully with %d categories", len(categories_data))
    except Exception as e:
        logger.error(f"Error in handle_get_categories: {str(e)}", exc_info=True)
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
    try:
        # Initialize app context
        with app.app_context():
            db.create_all()
            
            # Initialize default roles and categories if needed
            try:
                default_category = Category.query.filter_by(name="General").first()
                if not default_category:
                    default_category = Category(name="General")
                    db.session.add(default_category)
                    db.session.commit()
                    logger.info("Created default category")
                
                # Log successful initialization
                logger.info("Database initialized successfully")
            except Exception as e:
                logger.error(f"Database initialization error: {str(e)}")
                db.session.rollback()
                # Don't raise, allow server to start even if db init fails
        
        # Start the SocketIO server
        logger.info("Starting SocketIO server...")
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False,  # Disable reloader to prevent monkey patch issues
            log_output=True
        )
    except Exception as e:
        logger.error(f"Server startup error: {str(e)}")
        raise