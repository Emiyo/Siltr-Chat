import os
import time
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask
from flask_login import LoginManager

# Initialize Flask app
app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize LoginManager first
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.init_app(app)

# Import extensions and models after app creation
from extensions import db, socketio, bcrypt, mail, init_app
from models import User, Message, Channel

# Import remaining Flask modules after initialization
from flask import request, jsonify, render_template, redirect, url_for, flash, send_from_directory, session
from flask_login import UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from email_validator import validate_email, EmailNotValidError
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.exc import SQLAlchemyError
from flask_mail import Message

# Load configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'your-secret-key'),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///chat.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={'pool_pre_ping': True},  # Add connection validation
    UPLOAD_FOLDER=os.path.join('static', 'uploads'),
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50MB max file size
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER'),
    SESSION_TYPE='filesystem',
    SESSION_PERMANENT=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)

# Initialize extensions
from extensions import db, migrate, socketio, bcrypt, mail, login_manager, init_app
from models import User

# Initialize the application and its extensions
try:
    # Ensure the upload directory exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Initialize all Flask extensions
    if init_app(app):
        logger.info("Flask extensions initialized successfully")
    
    # Configure token serializer for password reset
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    # Create database tables within app context if they don't exist
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")
        
except Exception as e:
    logger.error(f"Application initialization failed: {str(e)}")
    raise

# Configure login manager
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def logout_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt='password-reset-salt',
            max_age=expiration
        )
        return email
    except:
        return None

def send_password_reset_email(user):
    token = generate_reset_token(user.email)
    reset_url = url_for('reset_password', token=token, _external=True)
    
    try:
        msg = Message('Password Reset Request',
                     recipients=[user.email])
        msg.body = f'''To reset your password, visit the following link:
{reset_url}

If you did not make this request, simply ignore this email and no changes will be made.
'''
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        return False

# Profile routes
@app.route('/api/profile', methods=['GET', 'PATCH'])
@login_required
def manage_profile():
    """Get or update user profile with enhanced customization"""
    try:
        if request.method == 'GET':
            return jsonify(current_user.to_dict(include_private=True))
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # Update allowed fields with enhanced customization
        allowed_fields = [
            'display_name', 'bio', 'theme', 'accent_color',
            'banner_color', 'preferences', 'privacy_settings'
        ]
        
        updated_fields = []
        for field in allowed_fields:
            if field in data:
                if field == 'privacy_settings':
                    current_user.update_privacy_settings(data[field])
                elif field == 'preferences':
                    if not isinstance(data[field], dict):
                        return jsonify({'error': 'Preferences must be an object'}), 400
                    current_user.preferences.update(data[field])
                else:
                    setattr(current_user, field, data[field])
                updated_fields.append(field)
        
        if not updated_fields:
            return jsonify({'error': 'No valid fields to update'}), 400
            
        db.session.commit()
        logger.info(f"Profile updated for user {current_user.username}: {', '.join(updated_fields)}")
        return jsonify(current_user.to_dict()), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Profile update error: {str(e)}")
        return jsonify({'error': 'Failed to update profile'}), 500

@app.route('/api/profile/presence', methods=['POST'])
@login_required
def update_presence():
    """Update user's presence and activity status with rich presence support"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        state = data.get('state', 'online')
        details = data.get('details', {})
        activity_type = data.get('activity_type')
        activity_status = data.get('activity_status')
        
        # Validate presence state
        valid_states = {'online', 'idle', 'dnd', 'offline', 'invisible'}
        if state not in valid_states:
            return jsonify({'error': f'Invalid state. Must be one of: {", ".join(valid_states)}'}), 400
            
        # Validate activity type if provided
        if activity_type:
            valid_activities = {'playing', 'listening', 'watching', 'streaming'}
            if activity_type not in valid_activities:
                return jsonify({'error': f'Invalid activity type. Must be one of: {", ".join(valid_activities)}'}), 400
        
        current_user.update_presence(
            state=state,
            details=details,
            activity_type=activity_type,
            activity_status=activity_status
        )
        db.session.commit()
        logger.info(f"Presence updated for user {current_user.username}: {state} ({activity_type or 'no activity'})")
        return jsonify(current_user.to_dict())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Presence update error: {str(e)}")
        return jsonify({'error': 'Failed to update presence'}), 500

@app.route('/api/profile/status', methods=['POST'])
@login_required
def update_status():
    """Update user's custom status with emoji and expiration support"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        text = data.get('status')
        emoji = data.get('emoji')
        expires_at = None
        
        if 'expires_in' in data:
            try:
                expires_in = int(data['expires_in'])
                if expires_in > 0:
                    expires_at = datetime.utcnow() + timedelta(minutes=expires_in)
            except (TypeError, ValueError):
                return jsonify({'error': 'Invalid expiration time'}), 400
        
        current_user.set_status(text=text, emoji=emoji, expires_at=expires_at)
        db.session.commit()
        logger.info(f"Status updated for user {current_user.username}")
        return jsonify(current_user.to_dict())
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Status update error: {str(e)}")
        return jsonify({'error': 'Failed to update status'}), 500

@app.route('/api/profile/connections', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_connections():
    """Manage user's platform connections"""
    if request.method == 'GET':
        return jsonify(current_user.connections or {})
    
    try:
        data = request.get_json()
        if request.method == 'POST':
            platform = data.get('platform')
            connection_data = data.get('connection_data')
            if not platform or not connection_data:
                return jsonify({'error': 'Platform and connection data required'}), 400
            
            current_user.update_connection(platform, connection_data)
            db.session.commit()
            return jsonify(current_user.connections)
            
        elif request.method == 'DELETE':
            platform = data.get('platform')
            if not platform:
                return jsonify({'error': 'Platform required'}), 400
            
            if platform in current_user.connections:
                del current_user.connections[platform]
                db.session.commit()
            return jsonify(current_user.connections)
            
    except Exception as e:
        db.session.rollback()
        logger.error(f"Connection management error: {str(e)}")
        return jsonify({'error': 'Failed to manage connections'}), 500

@app.route('/api/profile/badges', methods=['GET', 'POST'])
@login_required
def manage_badges():
    """Manage user's profile badges"""
    if request.method == 'GET':
        return jsonify(current_user.profile_badges or [])
    
    try:
        data = request.get_json()
        badge_id = data.get('badge_id')
        badge_data = data.get('badge_data')
        
        if not badge_id or not badge_data:
            return jsonify({'error': 'Badge ID and data required'}), 400
        
        current_user.add_badge(badge_id, badge_data)
        db.session.commit()
        return jsonify(current_user.profile_badges)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Badge management error: {str(e)}")
        return jsonify({'error': 'Failed to manage badges'}), 500

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

# Authentication routes
# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    if current_user.is_authenticated:
        current_user.update_presence(state='online')
        db.session.commit()
        logger.info(f"User {current_user.username} connected")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    if current_user.is_authenticated:
        current_user.update_presence(state='offline')
        db.session.commit()
        logger.info(f"User {current_user.username} disconnected")

@socketio.on('join')
def handle_join(data):
    """Handle user joining a channel"""
    if current_user.is_authenticated:
        # Emit active users list
        active_users = User.query.filter(
            User.last_seen >= (datetime.utcnow() - timedelta(minutes=5))
        ).all()
        socketio.emit('active_users', {
            'users': [user.to_dict() for user in active_users]
        })
        
        # Emit categories and channels with proper structure
        channels = Channel.query.all()
        categories_data = []
        seen_categories = set()
        
        for channel in channels:
            if channel.category_id not in seen_categories:
                seen_categories.add(channel.category_id)
                category_channels = [ch for ch in channels if ch.category_id == channel.category_id]
                categories_data.append({
                    'id': channel.category_id,
                    'name': channel.category.name if channel.category else 'General',
                    'channels': [{
                        'id': ch.id,
                        'name': ch.name,
                        'description': ch.description,
                        'type': ch.type,
                        'is_private': ch.is_private
                    } for ch in category_channels]
                })
        
        socketio.emit('categories_list', {'categories': categories_data})
        
        logger.info(f"Sent initial data to user {current_user.username}")

# Main routes
@app.route('/')
@app.route('/index')
@login_required
def index():
    """Main dashboard page after login"""
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login with proper redirection"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            remember = request.form.get('remember', False)

            logger.info(f"Login attempt for email: {email}")

            if not all([email, password]):
                logger.warning("Login failed: Missing email or password")
                flash('Please fill in both email and password.', 'error')
                return render_template('login.html')

            user = User.query.filter_by(email=email).first()

            if user is None:
                logger.warning(f"Login failed: No user found with email {email}")
                time.sleep(1)  # Security delay
                flash('Invalid email or password.', 'error')
                return render_template('login.html')

            if not user.is_active:
                logger.warning(f"Login attempt for inactive user: {email}")
                flash('This account has been deactivated.', 'error')
                return render_template('login.html')

            if user.check_password(password):
                login_user(user, remember=bool(remember))
                user.last_seen = datetime.utcnow()
                user.update_presence(state='online')
                db.session.commit()
                
                logger.info(f"User {user.username} logged in successfully")
                flash(f'Welcome back, {user.username}!', 'success')
                
                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('index'))

            logger.warning(f"Login failed: Invalid password for user {user.username}")
            flash('Invalid email or password.', 'error')

        except SQLAlchemyError as e:
            logger.error(f"Database error during login: {str(e)}")
            db.session.rollback()
            flash('A database error occurred. Please try again.', 'error')
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            flash('An error occurred. Please try again.', 'error')

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

        new_user = User(
            username=username,
            email=email
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

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
