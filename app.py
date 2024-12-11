from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_bcrypt import Bcrypt
from pydub import AudioSegment
from email_validator import validate_email, EmailNotValidError
from flask_socketio import SocketIO, emit, join_room, leave_room
import json
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///chat.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
mail = Mail(app)

# Active users storage
active_users = {}

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_moderator = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(100), default='')
    # Messages sent by this user
    messages = db.relationship('Message',
                             foreign_keys='Message.sender_id',
                             backref='author',
                             lazy=True)
    # Messages received by this user
    received_messages = db.relationship('Message',
                                      foreign_keys='Message.receiver_id',
                                      backref='recipient',
                                      lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def has_permission(self, permission_name):
        # Placeholder - needs implementation based on roles and permissions
        return False

    def has_role(self, role_name):
        # Placeholder - needs implementation based on roles and permissions
        return False

    def add_role(self, role_name):
        # Placeholder - needs implementation based on roles and permissions
        return ""

    def remove_role(self, role_name):
        # Placeholder - needs implementation based on roles and permissions
        return ""

    def is_muted(self):
        # Placeholder - needs implementation based on mute status
        return False

    def mute_user(self, minutes=10):
        # Placeholder - needs implementation
        return ""

    def unmute_user(self):
        # Placeholder - needs implementation
        return ""

    def promote_to_moderator(self):
        # Placeholder - needs implementation
        return ""

    def demote_from_moderator(self):
        # Placeholder - needs implementation
        return ""

    def update_profile(self, status=None, avatar=None):
        if status is not None:
            self.status = status[:100]  # Limit status length
        # Avatar handling needs to be added back in
        return f'Profile updated successfully'

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_moderator': self.is_moderator,
            'status': self.status
        }


class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    is_private = db.Column(db.Boolean, default=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    messages = db.relationship('Message', backref='channel', lazy=True)
    category = db.relationship('Category', back_populates='channels')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'is_private': self.is_private,
            'category_id': self.category_id
        }

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    channels = db.relationship('Channel', back_populates='category', lazy=True)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'channels': [channel.to_dict() for channel in self.channels]
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=True)
    type = db.Column(db.String(20), default='text')  # text, system, private
    file_url = db.Column(db.String(200), nullable=True)
    voice_url = db.Column(db.String(200), nullable=True)
    voice_duration = db.Column(db.Float, nullable=True)
    reactions = db.Column(db.JSON, default=dict)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat(),
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'channel_id': self.channel_id,
            'type': self.type,
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration,
            'reactions': self.reactions,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key,
            'username': self.author.username if self.author else None
        }

# Create database tables and initial data
with app.app_context():
    db.create_all()
    
    # Create default categories if they don't exist
    if not Category.query.first():
        general = Category(name='General', description='General discussion')
        announcements = Category(name='Announcements', description='Important announcements')
        
        # Create general channel in General category
        general_channel = Channel(
            name='general',
            description='General chat channel',
            category=general,
            is_private=False
        )
        
        db.session.add(general)
        db.session.add(announcements)
        db.session.commit()

# Socket event handlers
@socketio.on('connect')
def handle_connect():
    if not current_user.is_authenticated:
        return False
    
    user_data = {
        'id': current_user.id,
        'username': current_user.username,
        'is_moderator': current_user.is_moderator,
        'status': current_user.status
    }
    active_users[request.sid] = user_data
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        username = active_users[request.sid]['username']
        del active_users[request.sid]
        
        leave_message = Message(
            type='system',
            text=f'{username} has left the chat',
            timestamp=datetime.now(),
            sender_id=None,
            channel_id=None
        )
        db.session.add(leave_message)
        db.session.commit()
        
        emit('user_list', {'users': list(active_users.values())}, broadcast=True)
        emit('new_message', leave_message.to_dict(), broadcast=True)

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
        # Password reset functionality needs to be added back in
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    # Password reset functionality needs to be added back in
    
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
    # Placeholder - admin role check and role listing needs implementation
    return "Roles"

@app.route('/admin/roles/assign', methods=['POST'])
@login_required
def assign_role():
    # Placeholder - role assignment needs implementation
    return "Role Assignment"

@app.route('/admin/roles/remove', methods=['POST'])
@login_required
def remove_role():
    # Placeholder - role removal needs implementation
    return "Role Removal"

@app.route('/admin/users', methods=['GET'])
@login_required
def list_users():
    # Placeholder - user listing needs implementation
    return "Users"


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


# Socket Events (rest of the socket events from the original code)

@socketio.on('message')
def handle_message(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    if not user_data:
        return
    
    text = data.get('text', '').strip()
    channel_id = data.get('channel_id')
    file_url = data.get('file_url')
    voice_url = data.get('voice_url')
    voice_duration = float(data.get('voice_duration', 0)) if data.get('voice_duration') else None
    
    # Check if user is muted
    user = User.query.get(user_data['id'])
    if user.is_muted():
        emit('error', {'message': f'You are muted until {user.muted_until}'})
        return
    
    # Handle commands
    if text.startswith('/'):
        handle_command(text, user_data, user)
        return
    
    # Create and save message
    message = Message(
        type='public',
        user_id=user_data['id'],
        channel_id=channel_id,
        text=text,
        file_url=file_url,
        voice_url=voice_url,
        voice_duration=voice_duration
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
    message_dict['sender_username'] = User.query.get(message.user_id).username
    
    # Broadcast to channel if specified, otherwise broadcast to all
    if message.channel_id:
        emit('new_message', message_dict, room=f'channel_{message.channel_id}')
    else:
        emit('new_message', message_dict, broadcast=True)

@socketio.on('join_channel')
def handle_join_channel(data):
    if request.sid not in active_users:
        return
    
    channel_id = data.get('channel_id')
    
    channel = Channel.query.get(channel_id)
    if not channel:
        emit('error', {'message': 'Channel not found'})
        return
    
    join_room(f'channel_{channel_id}')
    
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
    print(f"Received get_categories request from {request.sid}")
    if request.sid not in active_users:
        print(f"Unauthorized request for categories from {request.sid}")
        return
    
    try:
        categories = Category.query.all()
        print(f"Found {len(categories)} categories")
        categories_data = {
            'categories': [category.to_dict() for category in categories]
        }
        print(f"Sending categories data: {categories_data}")
        emit('categories_list', categories_data)
    except Exception as e:
        print(f"Error fetching categories: {str(e)}")
        emit('error', {'message': 'Error loading categories'})

@socketio.on('create_category')
def handle_create_category(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    # Category creation requires permission check and implementation
    
    name = data.get('name')
    description = data.get('description')
    
    if not name:
        emit('error', {'message': 'Category name is required'})
        return
    
    # Category creation needs implementation
    
    emit('category_created', category.to_dict(), broadcast=True)

@socketio.on('create_channel')
def handle_create_channel(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    # Channel creation requires permission check and implementation
    
    category_id = data.get('category_id')
    name = data.get('name')
    description = data.get('description')
    is_private = data.get('is_private', False)
    
    if not all([category_id, name]):
        emit('error', {'message': 'Category ID and channel name are required'})
        return
    
    # Channel creation needs implementation
    
    emit('channel_created', channel.to_dict(), broadcast=True)



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

# Initialize Flask-Migrate (This part is added back)
from flask_migrate import Migrate
migrate = Migrate(app, db)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables based on models
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)