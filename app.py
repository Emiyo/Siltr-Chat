# Configure eventlet first
import eventlet
eventlet.monkey_patch(os=True, select=True, socket=True, thread=True, time=True)

import os
import logging
import json
from datetime import datetime
from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, abort, current_app
from logging.handlers import RotatingFileHandler
from flask_login import login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse as werkzeug_url_parse
from sqlalchemy.exc import SQLAlchemyError
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError

# Import extensions
from extensions import db, login_manager, bcrypt, mail, Message
import os
import json
from datetime import datetime
import logging

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
logger.info("Flask app initialized")
# GitHub OAuth Configuration
app.config['GITHUB_CLIENT_ID'] = os.environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_CALLBACK_URL'] = os.environ.get('GITHUB_CALLBACK_URL', 'http://localhost:5000/auth/github/callback')
# Configure database URL
try:
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        logger.error("DATABASE_URL environment variable is not set")
        raise ValueError("DATABASE_URL environment variable is required")
        
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    logger.info(f"Configuring database connection...")
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
except Exception as e:
    logger.error(f"Database configuration error: {str(e)}")
    raise
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

# Initialize Flask-SQLAlchemy
db.init_app(app)
login_manager.init_app(app)
bcrypt.init_app(app)
mail.init_app(app)
login_manager.login_view = 'login'

# Initialize migrations
migrate = Migrate(app, db, compare_type=True)

# Import models
from models import User, Role, Category, Channel, Message

with app.app_context():
    try:
        # Create tables
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Verify tables exist
        tables = db.engine.table_names()
        logger.info(f"Available tables: {tables}")
        
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}", exc_info=True)
        raise

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


from models import User, Role, Category, Channel, Message

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
        logger.info("Already authenticated user accessing login page")
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for email: {email}")
        
        if not email or not password:
            logger.warning("Login attempt with missing credentials")
            flash('Please provide both email and password', 'error')
            return redirect(url_for('login'))

        try:
            user = User.query.filter_by(email=email).first()
            if user:
                logger.info(f"Found user {user.username}, verifying password")
                if user.check_password(password):
                    login_user(user, remember=True)
                    logger.info(f"User {user.username} logged in successfully")
                    next_page = request.args.get('next')
                    if not next_page or werkzeug_url_parse(next_page).netloc != '':
                        next_page = url_for('index')
                    return redirect(next_page)
                else:
                    logger.warning(f"Invalid password for user {user.username}")
            else:
                logger.warning(f"No user found with email {email}")
            
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}", exc_info=True)
            flash('An error occurred during login. Please try again.', 'error')
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
        
        # Update last seen
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        
        # Send initial data
        user_data = current_user.to_dict()
        users = User.query.all()
        users_data = [user.to_dict() for user in users]
        
        # Get categories with their channels
        categories = Category.query.all()
        categories_data = []
        for category in categories:
            category_dict = category.to_dict()
            channels = Channel.query.filter_by(category_id=category.id).all()
            category_dict['channels'] = [channel.to_dict() for channel in channels]
            categories_data.append(category_dict)
        
        # Emit initial data
        emit('user_connected', user_data)
        emit('user_list', {'users': users_data})
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

@socketio.on('message')
def handle_message(data):
    """Handle message sent"""
    if not current_user.is_authenticated:
        logger.warning("Unauthenticated user tried to send message")
        return
    
    try:
        logger.info(f"Received message data: {data}")
        content = data.get('text', '').strip()
        channel_id = data.get('channel_id')
        parent_id = data.get('parent_id')
        message_type = data.get('type', 'message')
        
        if not content:
            logger.warning("Empty message content")
            return
            
        if not channel_id:
            logger.warning("No channel_id provided")
            return
            
        logger.info(f"Looking up channel {channel_id}...")
        channel = Channel.query.get(channel_id)
        if not channel:
            logger.error(f"Channel {channel_id} not found")
            return
        
        logger.info(f"Creating message for user {current_user.id} in channel {channel_id}")    
        # Create and save message
        try:
            message = Message(
                content=content,
                user_id=current_user.id,
                channel_id=channel_id,
                parent_id=parent_id,
                type=message_type
            )
            
            logger.info("Adding message to session")
            db.session.add(message)
            logger.info("Committing message to database")
            db.session.commit()
            logger.info(f"Message saved to database with id {message.id}")
try:
    message_data = message.to_dict()
    logger.info(f"Message serialized successfully: {message_data}")
except Exception as e:
    logger.error(f"Error serializing message: {str(e)}")
    return False
            
            message_data = message.to_dict()
            logger.info(f"Emitting message: {message_data}")
            emit('message', message_data, room=f'channel_{channel_id}', broadcast=True)
            logger.info(f"Message broadcasted to channel {channel.name}")
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Database error saving message: {str(e)}", exc_info=True)
            db.session.rollback()
            emit('error', {'message': 'Failed to save message'})
            return False
        
        # Get complete message data
        message_data = message.to_dict()
        logger.info(f"Message data prepared: {message_data}")
        
        # Broadcast to channel
        emit('message', message_data, room=f'channel_{channel_id}', broadcast=True)
        logger.info(f"Message broadcasted to channel {channel.name}")
        
    except Exception as e:
        logger.error(f"Error in handle_message: {str(e)}", exc_info=True)
        db.session.rollback()
        emit('error', {'message': 'Failed to send message'})

@socketio.on('system_message')
def handle_system_message(data):
    """Handle system messages"""
    if not current_user.is_authenticated:
        return
        
    try:
        channel_id = data.get('channel_id')
        content = data.get('content')
        
        if channel_id and content:
            message = Message(
                content=content,
                channel_id=channel_id,
                user_id=current_user.id,
                type='system'
            )
            db.session.add(message)
            db.session.commit()
            
            emit('message', message.to_dict(), room=f'channel_{channel_id}')
            logger.info(f"System message sent in channel {channel_id}: {content}")
            
    except Exception as e:
        logger.error(f"Error sending system message: {str(e)}")
        db.session.rollback()
        emit('error', {'message': 'Failed to send system message'})



@socketio.on('join_channel')
def handle_join_channel(data):
    """Handle joining a channel"""
    if not current_user.is_authenticated:
        logger.warning("Unauthenticated user tried to join channel")
        return
    
    try:
        channel_id = data.get('channel_id')
        if not channel_id:
            logger.error("No channel_id provided")
            return
            
        channel = Channel.query.get(channel_id)
        if not channel:
            logger.error(f"Channel {channel_id} not found")
            return
            
        # Join the channel room
        join_room(f'channel_{channel_id}')
        logger.info(f"User {current_user.username} joined channel {channel.name}")
        
        # Get channel messages
        messages = Message.query.filter_by(channel_id=channel_id).order_by(Message.timestamp.desc()).limit(50).all()
        logger.info(f"Found {len(messages)} messages for channel {channel_id}")
        
        # Send channel history
        message_data = [msg.to_dict() for msg in messages]
        emit('channel_history', {
            'channel_id': channel_id,
            'messages': message_data
        })
        
        # Send system message for user joining
        system_message = Message(
            content=f"{current_user.username} has joined the channel",
            channel_id=channel_id,
            user_id=current_user.id,
            type='system'
        )
        db.session.add(system_message)
        db.session.commit()
        
        emit('message', system_message.to_dict(), room=f'channel_{channel_id}')
        logger.info(f"System message sent for user {current_user.username} joining channel {channel.name}")
        
    except Exception as e:
        logger.error(f"Error in handle_join_channel: {str(e)}")
        db.session.rollback()

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