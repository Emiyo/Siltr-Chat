# Configure eventlet first
import eventlet
eventlet.monkey_patch(os=True, select=True, socket=True, thread=True, time=True)

import os
import re
import logging
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, url_for, flash, redirect, jsonify, session, abort, current_app
from flask_login import login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.urls import url_parse as werkzeug_url_parse
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
from email_validator import validate_email, EmailNotValidError

# Import extensions
from extensions import db, login_manager, bcrypt, mail, init_extensions
from flask_mail import Message

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

# Configure database URL
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    logger.error("DATABASE_URL environment variable is not set")
    raise ValueError("DATABASE_URL environment variable is required")

# Convert postgres:// to postgresql:// if necessary
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql://', 1)

# Configure SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
}

# GitHub OAuth Configuration (if needed)
app.config['GITHUB_CLIENT_ID'] = os.environ.get('GITHUB_CLIENT_ID')
app.config['GITHUB_CLIENT_SECRET'] = os.environ.get('GITHUB_CLIENT_SECRET')
app.config['GITHUB_CALLBACK_URL'] = os.environ.get('GITHUB_CALLBACK_URL', 'http://localhost:5000/auth/github/callback')
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

# Initialize extensions with error handling
init_extensions(app)

# Initialize migrations
migrate = Migrate(app, db, compare_type=True)

# Import models
from models import User, Role, Category, Channel, Message, DirectMessage

with app.app_context():
    try:
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        
        # Create tables if they don't exist
        db.create_all()
        logger.info("Database tables created successfully")
        
        # Verify tables exist
        tables = inspector.get_table_names()
        logger.info(f"Available tables: {tables}")
        
        # Verify essential tables exist
        required_tables = {'user', 'role', 'category', 'channel', 'message', 'user_roles'}
        missing_tables = required_tables - set(tables)
        
        if missing_tables:
            logger.warning(f"Missing required tables: {missing_tables}")
            db.create_all()  # Create any missing tables
            logger.info("Created missing tables")
        else:
            logger.info("All required tables exist")
            
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}", exc_info=True)
        db.session.rollback()
        # Continue execution even if there's an error
        logger.warning("Continuing despite database initialization error")

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
    reconnection_delay_max=5000,
    path='/socket.io'
)

logger.info("SocketIO initialized with configuration: %s", {
    'cors_allowed_origins': "*",
    'async_mode': 'eventlet',
    'ping_timeout': 5000,
    'ping_interval': 25000
})


logger.info('Application startup')


from models import User, Role, Category, Channel, Message

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Routes
@app.route('/')
@login_required
def index():
    logger.info("Rendering index page for user: %s", current_user.username if current_user else 'Anonymous')
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error("Error rendering index page: %s", str(e), exc_info=True)
        return "Error loading chat", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
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
                return render_template('login.html'), 400

            user = User.query.filter_by(email=email).first()
            
            if user and user.check_password(password):
                logger.info(f"User {user.username} authenticated successfully")
                login_user(user, remember=True)
                
                # Handle the next page redirect
                next_page = request.args.get('next')
                if not next_page or werkzeug_url_parse(next_page).netloc != '':
                    next_page = url_for('index')
                
                logger.info(f"Redirecting authenticated user to: {next_page}")
                return redirect(next_page)
            
            logger.warning(f"Failed login attempt for email: {email}")
            flash('Invalid email or password', 'error')
            return render_template('login.html'), 401
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}", exc_info=True)
        flash('An error occurred during login. Please try again.', 'error')
        db.session.rollback()
        return render_template('login.html'), 500

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
        return jsonify(current_user.to_dict())
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

@app.route('/api/user/profile')
@login_required
def get_current_user_profile():
    """Get the current user's profile data"""
    try:
        return jsonify(current_user.to_dict())
    except Exception as e:
        logger.error(f"Error fetching current user profile: {str(e)}")
        return jsonify({'error': 'Failed to fetch profile'}), 500

@app.route('/api/user/by_id/<int:user_id>')
@login_required
def get_user_profile(user_id):
    """Get a specific user's profile data by ID"""
    try:
        logger.info(f"Fetching profile for user ID: {user_id}")
        user = User.query.get(user_id)
        if not user:
            logger.warning(f"User ID {user_id} not found")
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user.to_dict()
        logger.info(f"Successfully fetched profile for user {user.username}")
        logger.debug(f"User data: {user_data}")
        return jsonify(user_data)
        
    except Exception as e:
        logger.error(f"Error fetching user profile {user_id}: {str(e)}", exc_info=True)
        return jsonify({'error': 'Failed to fetch profile'}), 500

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
        logger.info("Socket connection attempt from %s", request.sid)
        
        if not current_user.is_authenticated:
            logger.warning("Unauthenticated client attempting to connect")
            return False
            
        logger.info("Socket connection authenticated for user: %s", current_user.username)
        
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
        return False

    try:
        logger.info(f"Received message data: {data}")
        content = data.get('text', '').strip()
        channel_id = data.get('channel_id')
        parent_id = data.get('parent_id')
        message_type = data.get('type', 'message')
        
        if not content:
            logger.warning("Empty message content")
            return False
            
        if not channel_id:
            logger.warning("No channel_id provided")
            return False
            
        logger.info(f"Looking up channel {channel_id}...")
        channel = Channel.query.get(channel_id)
        if not channel:
            logger.error(f"Channel {channel_id} not found")
            return False
        
        logger.info(f"Creating message for user {current_user.id} in channel {channel_id}")    
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
                emit('message', message_data, room=f'channel_{channel_id}', broadcast=True)
                logger.info(f"Message broadcasted to channel {channel.name}")
                return True
            except Exception as e:
                logger.error(f"Error serializing message: {str(e)}")
                return False
                
        except SQLAlchemyError as e:
            logger.error(f"Database error saving message: {str(e)}", exc_info=True)
            db.session.rollback()
            emit('error', {'message': 'Failed to save message'})
            return False
            
    except Exception as e:
        logger.error(f"Error in handle_message: {str(e)}", exc_info=True)
        db.session.rollback()
        emit('error', {'message': 'Failed to send message'})
        return False

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



@socketio.on('direct_message')
def handle_direct_message(data):
    """Handle direct messages between users"""
    if not current_user.is_authenticated:
        logger.warning("Unauthenticated user tried to send direct message")
        return False

    try:
        content = data.get('text', '').strip()
        recipient_id = data.get('recipient_id')
        
        if not content or not recipient_id:
            logger.warning("Missing content or recipient_id in direct message")
            return False
            
        # Check if recipient exists
        recipient = User.query.get(recipient_id)
        if not recipient:
            logger.error(f"Recipient {recipient_id} not found")
            return False
            
        # Create and save the direct message
        message = DirectMessage(
            content=content,
            sender_id=current_user.id,
            recipient_id=recipient_id
        )
        
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data
        message_data = message.to_dict()
        
        # Emit to both sender and recipient
        emit('direct_message', message_data, room=f'user_{current_user.id}')
        emit('direct_message', message_data, room=f'user_{recipient_id}')
        
        # Send notification to recipient
        notification_data = {
            'type': 'new_dm',
            'sender': current_user.username,
            'message': content[:50] + '...' if len(content) > 50 else content
        }
        emit('notification', notification_data, room=f'user_{recipient_id}')
        
        return True
        
    except Exception as e:
        logger.error(f"Error in handle_direct_message: {str(e)}", exc_info=True)
        db.session.rollback()
        emit('error', {'message': 'Failed to send direct message'})
        return False

@socketio.on('typing_indicator')
def handle_typing_indicator(data):
    """Handle typing indicator updates for both DMs and channels"""
    if not current_user.is_authenticated:
        return False
        
    try:
        recipient_id = data.get('recipient_id')
        channel_id = data.get('channel_id')
        is_typing = data.get('is_typing', False)
        
        indicator_data = {
            'user_id': current_user.id,
            'username': current_user.username,
            'is_typing': is_typing
        }
        
        if recipient_id:
            # Emit typing status to DM recipient
            emit('user_typing', indicator_data, room=f'user_{recipient_id}')
        elif channel_id:
            # Emit typing status to channel
            emit('user_typing', indicator_data, room=f'channel_{channel_id}')
            
        return True
        
    except Exception as e:
        logger.error(f"Error in handle_typing_indicator: {str(e)}", exc_info=True)
        return False
@socketio.on('get_dm_history')
def handle_get_dm_history(data):
    """Handle request for DM history with a specific user"""
    if not current_user.is_authenticated:
        return
        
    try:
        other_user_id = data.get('user_id')
        if not other_user_id:
            return
            
        # Get messages between the two users
        messages = DirectMessage.query.filter(
            db.or_(
                db.and_(DirectMessage.sender_id == current_user.id, 
                       DirectMessage.recipient_id == other_user_id),
                db.and_(DirectMessage.sender_id == other_user_id, 
                       DirectMessage.recipient_id == current_user.id)
            )
        ).order_by(DirectMessage.timestamp.desc()).limit(50).all()
        
        # Mark received messages as read
        unread_messages = [msg for msg in messages 
                          if msg.recipient_id == current_user.id and not msg.is_read]
        for msg in unread_messages:
            msg.is_read = True
        
        if unread_messages:
            db.session.commit()
        
        # Send history to user
        emit('dm_history', {
            'user_id': other_user_id,
            'messages': [msg.to_dict() for msg in reversed(messages)]
        })
        
    except Exception as e:
        logger.error(f"Error fetching DM history: {str(e)}")
        emit('error', {'message': 'Failed to fetch message history'})

@socketio.on('mark_dm_read')
def handle_mark_dm_read(data):
    """Mark direct messages as read"""
    if not current_user.is_authenticated:
        return
        
    try:
        message_id = data.get('message_id')
        if message_id:
            message = DirectMessage.query.get(message_id)
            if message and message.recipient_id == current_user.id:
                message.is_read = True
                db.session.commit()
                
    except Exception as e:
        logger.error(f"Error marking message as read: {str(e)}")

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