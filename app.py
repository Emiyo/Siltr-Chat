import os
import base64
import json
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message as FlaskMessage
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, request, render_template, jsonify, url_for, flash, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from pydub import AudioSegment
from email_validator import validate_email, EmailNotValidError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store user public keys and channel encryption keys
public_keys = {}  # userId -> public_key
channel_keys = {}  # channelId -> encryption_key

# Encryption Configuration
RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048
RSA_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

def generate_channel_key():
    """Generate a new AES-GCM key for channel encryption"""
    return AESGCM.generate_key(bit_length=256)

def encrypt_channel_key(channel_key, recipient_public_key):
    """Encrypt a channel key for a specific recipient"""
    try:
        # Decode and load the recipient's public key
        public_key = serialization.load_pem_public_key(
            base64.b64decode(recipient_public_key),
            backend=default_backend()
        )
        
        # Encrypt the channel key
        encrypted_key = public_key.encrypt(channel_key, RSA_PADDING)
        return base64.b64encode(encrypted_key).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting channel key: {str(e)}")
        raise

def encrypt_message(plaintext, key, associated_data=None):
    """Encrypt a message using AES-GCM"""
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ad = associated_data.encode() if associated_data else None
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), ad)
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    except Exception as e:
        logger.error(f"Error encrypting message: {str(e)}")
        raise

def decrypt_message(encrypted_data, key, associated_data=None):
    """Decrypt a message using AES-GCM"""
    try:
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        ad = associated_data.encode() if associated_data else None
        plaintext = aesgcm.decrypt(nonce, ciphertext, ad)
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Error decrypting message: {str(e)}")
        raise
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask_mail import Mail
from flask_mail import Message as FlaskMessage
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import os
from flask import Flask, request, render_template, jsonify, url_for, flash, redirect
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from pydub import AudioSegment
from email_validator import validate_email, EmailNotValidError
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', os.environ.get('DATABASE_URL')) #Using os.getenv as per modified code, but keeping original method as fallback
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload folder exists
# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

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
        
        msg = FlaskMessage(
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

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info' # Retained from original


# Constants
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'wav', 'txt', 'pdf'} #Combined allowed extensions
MAX_MESSAGES = 50
active_users = {}

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

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    channels = db.relationship('Channel', backref='category', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'channels': [channel.to_dict() for channel in self.channels] if self.channels else []
        }

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'category_id': self.category_id,
            'name': self.name,
            'description': self.description,
            'is_private': self.is_private
        }


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
    password_hash = db.Column(db.String(60), nullable=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    status = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime)
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        return any(
            any(p.name == permission_name for p in role.permissions)
            for role in self.roles
        )

    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

    def add_role(self, role_name):
        role = Role.query.filter_by(name=role_name).first()
        if role and role not in self.roles:
            self.roles.append(role)
            return f'Role {role_name} added to {self.username}'
        return f'Role {role_name} not found or already assigned'

    def remove_role(self, role_name):
        role = Role.query.filter_by(name=role_name).first()
        if role and role in self.roles:
            self.roles.remove(role)
            return f'Role {role_name} removed from {self.username}'
        return f'Role {role_name} not found or not assigned'

    def is_muted(self):
        if self.muted_until and self.muted_until > datetime.utcnow():
            return True
        return False

    def mute_user(self, minutes=10):
        if not self.has_permission('mute_users'):
            return 'Permission denied'
        self.muted_until = datetime.utcnow() + timedelta(minutes=minutes)
        return f'User {self.username} has been muted for {minutes} minutes'

    def unmute_user(self):
        if not self.has_permission('mute_users'):
            return 'Permission denied'
        self.muted_until = None
        return f'User {self.username} has been unmuted'

    def promote_to_moderator(self):
        if not self.has_permission('manage_roles'):
            return 'Permission denied'
        return self.add_role('moderator')

    def demote_from_moderator(self):
        if not self.has_permission('manage_roles'):
            return 'Permission denied'
        return self.remove_role('moderator')

    def update_profile(self, status=None, avatar=None):
        if status is not None:
            self.status = status[:100]  # Limit status length
        if avatar is not None:
            self.avatar = avatar
        return f'Profile updated successfully'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'is_muted': self.is_muted()
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 'public', 'private', 'system', 'voice'
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # For private messages
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))  # Channel where message was sent
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200))  # For file attachments
    voice_url = db.Column(db.String(200))  # For voice messages
    voice_duration = db.Column(db.Float)  # Duration of voice message in seconds
    reactions = db.Column(db.JSON, default=dict)

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
            'reactions': {} if self.reactions is None else self.reactions
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([username, email, password]):
            flash('All fields are required', 'error')
            return redirect(url_for('register'))
        
        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        
        # Assign default user role
        default_role = Role.query.filter_by(name='user').first()
        if default_role:
            user.roles.append(default_role)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not all([email, password]):
            flash('All fields are required', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            if send_password_reset_email(user):
                flash('An email has been sent with instructions to reset your password.', 'info')
                return redirect(url_for('login'))
            else:
                flash('There was an error sending the password reset email. Please try again later.', 'error')
        else:
            flash('No account found with that email address.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not password or not confirm_password:
            flash('Please fill in all fields', 'error')
        elif password != confirm_password:
            flash('Passwords do not match', 'error')
        else:
            user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            flash('Your password has been updated! You can now log in', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/profile', methods=['GET'])
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and file.filename:
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            
            if filename.split('.')[-1].lower() in {'png', 'jpg', 'jpeg', 'gif'}:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                current_user.avatar = url_for('static', filename=f'uploads/{filename}')
    
    username = request.form.get('username')
    status = request.form.get('status')
    
    if username and username != current_user.username:
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'error')
            return redirect(url_for('profile'))
        current_user.username = username
    
    if status is not None:
        current_user.status = status[:100]  # Limit status to 100 characters
    
    try:
        db.session.commit()
        flash('Profile updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error updating profile', 'error')
        logger.error(f"Profile update error: {str(e)}")
    
    return redirect(url_for('profile'))


@app.route('/admin/roles', methods=['GET'])
@login_required
def list_roles():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    roles = Role.query.all()
    return render_template('admin/roles.html', roles=roles)

@app.route('/admin/roles/assign', methods=['POST'])
@login_required
def assign_role():
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    user_id = request.form.get('user_id')
    role_name = request.form.get('role_name')
    
    if not all([user_id, role_name]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    result = user.add_role(role_name)
    db.session.commit()
    
    return jsonify({'message': result})

@app.route('/admin/roles/remove', methods=['POST'])
@login_required
def remove_role():
    if not current_user.has_role('admin'):
        return jsonify({'error': 'Access denied'}), 403
    
    user_id = request.form.get('user_id')
    role_name = request.form.get('role_name')
    
    if not all([user_id, role_name]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    result = user.remove_role(role_name)
    db.session.commit()
    
    return jsonify({'message': result})

@app.route('/admin/users', methods=['GET'])
@login_required
def list_users():
    if not current_user.has_role('admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    users = User.query.all()
    roles = Role.query.all()
    return render_template('admin/users.html', users=users, roles=roles)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Handle audio files
        if file.mimetype.startswith('audio/'):
            file.save(filepath)
            try:
                audio = AudioSegment.from_file(filepath)
                duration = len(audio) / 1000.0  # Convert to seconds
                return jsonify({
                    'voice_url': f'/static/uploads/{filename}',
                    'voice_duration': duration
                })
            except Exception as e:
                logger.error(f"Error processing audio file: {e}")
                return jsonify({'error': 'Error processing audio file'}), 500
        
        # Handle other files
        if filename.split('.')[-1] in ALLOWED_EXTENSIONS:
            file.save(filepath)
            return jsonify({'file_url': url_for('static', filename=f'uploads/{filename}')})
        else:
            return jsonify({'error': 'File type not allowed'}), 400

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey

# Encryption Configuration
RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048
RSA_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

# Key Management
public_keys = {}  # Store user public keys (format: {user_id: serialized_public_key})
channel_keys = {}  # Store channel encryption keys (format: {channel_id: bytes})

def generate_channel_key():
    """Generate a new AES key for channel encryption"""
    return AESGCM.generate_key(bit_length=256)

def encrypt_channel_key(channel_key, public_key_pem):
    """Encrypt a channel key with a user's public key"""
    try:
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_pem),
            backend=default_backend()
        )
        encrypted_key = public_key.encrypt(channel_key, RSA_PADDING)
        return base64.b64encode(encrypted_key).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encrypting channel key: {str(e)}")
        raise

def decrypt_message(encrypted_data, key, associated_data=None):
    """Decrypt a message using AES-GCM"""
    try:
        aesgcm = AESGCM(key)
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        ad = associated_data.encode() if associated_data else None
        plaintext = aesgcm.decrypt(nonce, ciphertext, ad)
        return plaintext.decode()
    except Exception as e:
        logger.error(f"Error decrypting message: {str(e)}")
        raise

def encrypt_message(plaintext, key, associated_data=None):
    """Encrypt a message using AES-GCM"""
    try:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ad = associated_data.encode() if associated_data else None
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), ad)
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    except Exception as e:
        logger.error(f"Error encrypting message: {str(e)}")
        raise

@socketio.on('share_public_key')
def handle_public_key(data):
    try:
        if request.sid not in active_users:
            logger.error(f"User not found for session {request.sid}")
            return
        
        user_id = active_users[request.sid]['id']
        public_key = data.get('publicKey')
        
        if not public_key:
            logger.error(f"No public key provided by user {user_id}")
            return
        
        # Validate the public key format
        try:
            decoded_key = base64.b64decode(public_key)
            serialization.load_pem_public_key(decoded_key, backend=default_backend())
            logger.info(f"Valid public key received from user {user_id}")
        except Exception as e:
            logger.error(f"Invalid public key format from user {user_id}: {str(e)}")
            return
        
        # Store and share the public key
        public_keys[user_id] = public_key
        logger.info(f"Stored public key for user {user_id}")
        
        # Share this user's public key with others
        emit('public_key_shared', {
            'userId': user_id,
            'publicKey': public_key
        }, broadcast=True)
        
        # Share existing public keys with this user
        for uid, key in public_keys.items():
            if uid != user_id:
                emit('public_key_shared', {
                    'userId': uid,
                    'publicKey': key
                })
        logger.info(f"Successfully shared public keys for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling public key: {str(e)}")
        emit('error', {'message': 'Error processing public key'})

@socketio.on('request_channel_key')
def handle_channel_key_request(data):
    """Handle channel key requests from users"""
    if request.sid not in active_users:
        logger.error("Unauthorized channel key request")
        emit('error', {'message': 'Unauthorized'})
        return
    
    channel_id = data.get('channelId')
    if not channel_id:
        logger.error("Missing channel ID in key request")
        emit('error', {'message': 'Invalid channel ID'})
        return
    
    user_data = active_users[request.sid]
    
    # Generate new channel key if it doesn't exist
    if channel_id not in channel_keys:
        channel_keys[channel_id] = generate_channel_key()
        logger.info(f"Generated new key for channel {channel_id}")
    
    # Get user's public key
    public_key = public_keys.get(user_data['id'])
    if not public_key:
        logger.error(f"Public key not found for user {user_data['id']}")
        emit('error', {'message': 'Public key not found'})
        return
    
    try:
        encrypted_key = encrypt_channel_key(channel_keys[channel_id], public_key)
        emit('channel_key', {
            'channelId': channel_id,
            'encryptedKey': encrypted_key
        })
        logger.info(f"Successfully shared channel key with user {user_data['id']}")
    except Exception as e:
        logger.error(f"Error sharing channel key: {str(e)}")
        emit('error', {'message': 'Error sharing channel key'})
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('share_public_key')
def handle_public_key(data):
    try:
        if request.sid not in active_users:
            logger.error(f"User not found for session {request.sid}")
            return
        
        user_id = active_users[request.sid]['id']
        public_key = data.get('publicKey')
        
        if not public_key:
            logger.error(f"No public key provided by user {user_id}")
            return
        
        # Validate the public key format
        try:
            decoded_key = base64.b64decode(public_key)
            serialization.load_pem_public_key(decoded_key, backend=default_backend())
            logger.info(f"Valid public key received from user {user_id}")
        except Exception as e:
            logger.error(f"Invalid public key format from user {user_id}: {str(e)}")
            return
        
        # Store and share the public key
        public_keys[user_id] = public_key
        logger.info(f"Stored public key for user {user_id}")
        
        # Share this user's public key with others
        emit('public_key_shared', {
            'userId': user_id,
            'publicKey': public_key
        }, broadcast=True)
        
        # Share existing public keys with this user
        for uid, key in public_keys.items():
            if uid != user_id:
                emit('public_key_shared', {
                    'userId': uid,
                    'publicKey': key
                })
        logger.info(f"Successfully shared public keys for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling public key: {str(e)}")
        emit('error', {'message': 'Error processing public key'})

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if not username:
        return
    
    # Get or create user
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username)
        db.session.add(user)
        db.session.commit()
    
    # Store user in active users
    active_users[request.sid] = {
        'id': user.id,
        'username': user.username,
        'is_moderator': user.is_moderator,
        'status': user.status
    }
    
    # Send join message
    join_message = Message(
        type='system',
        text=f'{username} has joined the chat',
        timestamp=datetime.now()
    )
    db.session.add(join_message)
    db.session.commit()
    
    # Send recent messages and current user list
    recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(MAX_MESSAGES).all()
    recent_messages.reverse()
    
    emit('message_history', {
        'messages': [msg.to_dict() for msg in recent_messages],
        'user_id': user.id
    })
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    emit('new_message', join_message.to_dict(), broadcast=True)

@socketio.on('message')
def handle_message(data):
    """Handle incoming chat messages with encryption support"""
    logger.debug(f"Received message data: {data}")
    
    if request.sid not in active_users:
        logger.error(f"User session {request.sid} not found in active_users")
        return
    
    user_data = active_users[request.sid]
    if not user_data:
        logger.error(f"User data not found for session {request.sid}")
        return
    
    logger.info(f"Processing message from user: {user_data['username']}")
    encrypted_data = data.get('encrypted_data')
    channel_id = data.get('channel_id')
    file_url = data.get('file_url')
    voice_url = data.get('voice_url')
    voice_duration = float(data.get('voice_duration', 0)) if data.get('voice_duration') else None
    
    # Process encrypted messages
    text = '[Encrypted message]'
    if encrypted_data:
        try:
            # Validate encrypted data format
            if not isinstance(encrypted_data, dict) or not all(k in encrypted_data for k in ('nonce', 'ciphertext')):
                logger.error("Invalid encrypted message format")
                emit('error', {'message': 'Invalid encrypted message format'})
                return
            
            # Store the encrypted data as JSON string for forwarding
            text = json.dumps(encrypted_data)
            logger.debug("Successfully processed encrypted message")
            
            # Check if user is muted
            user = User.query.get(user_data['id'])
            if user.is_muted():
                emit('error', {'message': f'You are muted until {user.muted_until}'})
                return
            
            # Handle commands (decrypt first for command processing)
            if encrypted_data.get('isCommand'):
                try:
                    channel_key = channel_keys.get(channel_id)
                    if not channel_key:
                        logger.error("Channel key not found")
                        emit('error', {'message': 'Channel key not found'})
                        return
                    
                    decrypted_text = decrypt_message(encrypted_data, channel_key)
                    if decrypted_text.startswith('/'):
                        handle_command(decrypted_text, user_data, user)
                        return
                except Exception as e:
                    logger.error(f"Error processing command: {str(e)}")
                    emit('error', {'message': 'Error processing command'})
                    return
            
            # Create and save message with encrypted content
            message = Message(
                type='public',
                sender_id=user_data['id'],
                channel_id=channel_id,
                text=text,  # Store encrypted data
                file_url=file_url,
                voice_url=voice_url,
                voice_duration=voice_duration,
                reactions={},
                is_encrypted=True
            )
            db.session.add(message)
            db.session.commit()
    
    # Prepare message for broadcast
    message_dict = message.to_dict()
    message_dict['sender_username'] = user_data['username']
    
    # Broadcast to channel if specified, otherwise broadcast to all
    if channel_id:
        emit('new_message', message_dict, room=f'channel_{channel_id}')
    else:
        emit('new_message', message_dict, broadcast=True)

@socketio.on('add_reaction')
def handle_reaction(data):
    if request.sid not in active_users:
        return
    
    user = active_users[request.sid]
    message_id = data.get('message_id')
    reaction = data.get('reaction')
    
    if not all([message_id, reaction]):
        return
    
    message = Message.query.get(message_id)
    if not message:
        return
    
    # Initialize reactions if None
    if message.reactions is None:
        message.reactions = {}
    
    # Initialize reaction array if not exists
    if reaction not in message.reactions:
        message.reactions[reaction] = []
    
    # Toggle user's reaction
    user_id = str(user['id'])
    if user_id in message.reactions[reaction]:
        message.reactions[reaction].remove(user_id)
    else:
        message.reactions[reaction].append(user_id)
    
    # Remove reaction if no users
    if not message.reactions[reaction]:
        del message.reactions[reaction]
    
    db.session.commit()
    
    # Broadcast updated message
    message_dict = message.to_dict()
    message_dict['sender_username'] = User.query.get(message.sender_id).username
    if message.receiver_id:
        message_dict['receiver_username'] = User.query.get(message.receiver_id).username
    
    # Broadcast to channel if specified, otherwise broadcast to all
    if message.channel_id:
        emit('new_message', message_dict, room=f'channel_{message.channel_id}')
    else:
        emit('new_message', message_dict, broadcast=True)

@socketio.on('join_channel')
def handle_join_channel(data):
    """Handle channel join requests with encryption key distribution"""
    if request.sid not in active_users:
        logger.error("Unauthorized channel join attempt")
        emit('error', {'message': 'Unauthorized'})
        return
    
    channel_id = data.get('channel_id')
    channel = Channel.query.get(channel_id)
    if not channel:
        logger.error(f"Channel not found: {channel_id}")
        emit('error', {'message': 'Channel not found'})
        return
    
    # Join the channel room
    join_room(f'channel_{channel_id}')
    logger.info(f"User joined channel {channel_id}")
    
    # Ensure channel has an encryption key
    if channel_id not in channel_keys:
        channel_keys[channel_id] = generate_channel_key()
        logger.info(f"Generated new encryption key for channel {channel_id}")
    
    # Share channel key with the joining user
    user_id = active_users[request.sid]['id']
    if user_id in public_keys:
        try:
            encrypted_key = encrypt_channel_key(channel_keys[channel_id], public_keys[user_id])
            emit('channel_key', {
                'channelId': channel_id,
                'encryptedKey': encrypted_key
            })
            logger.info(f"Shared channel key with user {user_id}")
        except Exception as e:
            logger.error(f"Error sharing channel key: {str(e)}")
            emit('error', {'message': 'Error sharing channel key'})
    
    # Share channel key with the joining user
    user_id = active_users[request.sid]['id']
    if user_id in public_keys:
        try:
            # Load the user's public key
            public_key = serialization.load_pem_public_key(
                base64.b64decode(public_keys[user_id]),
                backend=default_backend()
            )
            
            # Encrypt the channel key with the user's public key
            encrypted_key = public_key.encrypt(
                channel_keys[channel_id],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Send encrypted channel key to the user
            emit('channel_key', {
                'channelId': channel_id,
                'encryptedKey': base64.b64encode(encrypted_key).decode('utf-8')
            })
        except Exception as e:
            logger.error(f"Error sharing channel key: {str(e)}")
            emit('error', {'message': 'Error sharing channel key'})
    
    # Get recent messages for this channel
    recent_messages = Message.query\
        .filter_by(channel_id=channel_id)\
        .order_by(Message.timestamp.desc())\
        .limit(MAX_MESSAGES)\
        .all()
    recent_messages.reverse()
    
    emit('channel_history', {
        'channel_id': channel_id,
        'messages': [msg.to_dict() for msg in recent_messages]
    })

@socketio.on('leave_channel')
def handle_leave_channel(data):
    if request.sid not in active_users:
        return
    
    channel_id = data.get('channel_id')
    leave_room(f'channel_{channel_id}')

@socketio.on('get_categories')
def handle_get_categories():
    if request.sid not in active_users:
        logger.warning(f"Unauthorized request for categories from {request.sid}")
        return
    
    try:
        categories = Category.query.all()
        logger.info(f"Found {len(categories)} categories")
        emit('categories_list', {
            'categories': [category.to_dict() for category in categories]
        })
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}")
        emit('error', {'message': 'Error loading categories'})

@socketio.on('create_category')
def handle_create_category(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    user = User.query.get(user_data['id'])
    if not user.has_permission('manage_channels'):
        emit('error', {'message': 'Permission denied: Cannot create categories'})
        return
    
    name = data.get('name')
    description = data.get('description')
    
    if not name:
        emit('error', {'message': 'Category name is required'})
        return
    
    category = Category(name=name, description=description)
    db.session.add(category)
    db.session.commit()
    
    emit('category_created', category.to_dict(), broadcast=True)

@socketio.on('create_channel')
def handle_create_channel(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    user = User.query.get(user_data['id'])
    if not user.has_permission('create_channels'):
        emit('error', {'message': 'Permission denied: Cannot create channels'})
        return
    
    category_id = data.get('category_id')
    name = data.get('name')
    description = data.get('description')
    is_private = data.get('is_private', False)
    
    if not all([category_id, name]):
        emit('error', {'message': 'Category ID and channel name are required'})
        return
    
    channel = Channel(
        category_id=category_id,
        name=name,
        description=description,
        is_private=is_private
    )
    db.session.add(channel)
    db.session.commit()
    
    emit('channel_created', channel.to_dict(), broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        username = active_users[request.sid]['username']
        del active_users[request.sid]
        
        leave_message = Message(
            type='system',
            text=f'{username} has left the chat',
            timestamp=datetime.now()
        )
        db.session.add(leave_message)
        db.session.commit()
        
        emit('user_list', {'users': list(active_users.values())}, broadcast=True)
        emit('new_message', leave_message.to_dict(), broadcast=True)

def handle_command(text, user_data, db_user):
    command_parts = text.lower().split()
    command = command_parts[0]
    
    if command == '/help':
        help_text = 'Available commands:\n' + \
                   '/help - Show this message\n' + \
                   '/clear - Clear your chat history\n' + \
                   '/status <message> - Update your status\n'
        if user_data['is_moderator']:
            help_text += 'Moderator commands:\n' + \
                        '/mute @user <minutes> - Mute a user\n' + \
                        '/unmute @user - Unmute a user\n' + \
                        '/promote @user - Promote user to moderator\n' + \
                        '/demote @user - Demote user from moderator'
        help_message = {
            'type': 'system',
            'text': help_text,
            'timestamp': datetime.now().isoformat()
        }
        emit('new_message', help_message)
    elif command == '/clear':
        emit('clear_chat')
    elif command == '/status' and len(command_parts) > 1:
        status = ' '.join(command_parts[1:])
        result = db_user.update_profile(status=status)
        emit('new_message', {
            'type': 'system',
            'text': result,
            'timestamp': datetime.now().isoformat()
        })
        # Update active users with new status
        active_users[request.sid]['status'] = status
        emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    elif user_data['is_moderator']:
        if command in ['/mute', '/unmute', '/promote', '/demote'] and len(command_parts) > 1:
            target_username = command_parts[1].lstrip('@')
            target_user = User.query.filter_by(username=target_username).first()
            
            if not target_user:
                emit('new_message', {
                    'type': 'system',
                    'text': f'User {target_username} not found',
                    'timestamp': datetime.now().isoformat()
                })
                return
            
            result = None
            if command == '/mute':
                duration = int(command_parts[2]) if len(command_parts) > 2 else 10
                result = target_user.mute_user(duration)
            elif command == '/unmute':
                result = target_user.unmute_user()
            elif command == '/promote':
                result = target_user.promote_to_moderator()
            elif command == '/demote':
                result = target_user.demote_from_moderator()
            
            if result:
                db.session.commit()
                emit('new_message', {
                    'type': 'system',
                    'text': result,
                    'timestamp': datetime.now().isoformat()
                }, broadcast=True)
                # Update user list to reflect changes
                emit('user_list', {'users': list(active_users.values())}, broadcast=True)

if __name__ == '__main__':
    with app.app_context():
        from flask_migrate import Migrate
        migrate = Migrate(app, db)
        db.create_all()  # Create tables based on models
        
        try:
            # Run the Flask-SocketIO server with appropriate configuration
            socketio.run(
                app,
                host='0.0.0.0',
                port=5000,
                debug=True,
                allow_unsafe_werkzeug=True,
                use_reloader=True,
                log_output=True
            )
        except Exception as e:
            logger.error(f"Failed to start server: {str(e)}")
            raise