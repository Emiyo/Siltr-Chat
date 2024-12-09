import os
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, jsonify, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from pydub import AudioSegment
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'} # Added from original

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Active users storage
active_users = {}
MAX_MESSAGES = 100

# Models (Mostly from modified, with some adjustments from original)
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
            'channels': [channel.to_dict() for channel in self.channels]
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

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))
    status = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime, nullable=True)

    def is_muted(self):
        if self.muted_until and self.muted_until > datetime.utcnow():
            return True
        return False

    def mute_user(self, minutes=10):
        self.muted_until = datetime.utcnow() + timedelta(minutes=minutes)
        return f'User {self.username} has been muted for {minutes} minutes'

    def unmute_user(self):
        self.muted_until = None
        return f'User {self.username} has been unmuted'

    def promote_to_moderator(self):
        if not self.is_moderator:
            self.is_moderator = True
            return f'User {self.username} has been promoted to moderator'
        return f'User {self.username} is already a moderator'

    def demote_from_moderator(self):
        if self.is_moderator:
            self.is_moderator = False
            return f'User {self.username} has been demoted from moderator'
        return f'User {self.username} is not a moderator'

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
            'is_muted': self.is_muted() # added from original
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
            'timestamp': self.timestamp.isoformat(),
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration,
            'reactions': self.reactions or {}
        }

# Routes (Mostly from modified)
@app.route('/')
def index():
    return render_template('index.html')

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
        if filename.split('.')[-1] in ALLOWED_EXTENSIONS: #Added from original
            file.save(filepath)
            return jsonify({'file_url': url_for('static', filename=f'uploads/{filename}')}) #Modified from original
        else:
            return jsonify({'error': 'File type not allowed'}), 400

# Socket Events (Mostly from modified)
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

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
    logger.debug(f"Received message data: {data}")
    
    if request.sid not in active_users:
        logger.error(f"User session {request.sid} not found in active_users")
        return
    
    user_data = active_users[request.sid]
    if not user_data:
        logger.error(f"User data not found for session {request.sid}")
        return
    
    logger.info(f"Processing message from user: {user_data['username']}")
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
        sender_id=user_data['id'],
        channel_id=channel_id,
        text=text,
        file_url=file_url,
        voice_url=voice_url,
        voice_duration=voice_duration,
        reactions={}
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
    if request.sid not in active_users:
        return
    
    channel_id = data.get('channel_id')
    channel = Channel.query.get(channel_id)
    if not channel:
        emit('error', {'message': 'Channel not found'})
        return
    
    # Join the channel room
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
    if request.sid not in active_users:
        return
    
    categories = Category.query.all()
    emit('categories_list', {
        'categories': [category.to_dict() for category in categories]
    })

@socketio.on('create_category')
def handle_create_category(data):
    if request.sid not in active_users:
        return
    
    user = active_users[request.sid]
    if not user.get('is_moderator'):
        emit('error', {'message': 'Only moderators can create categories'})
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
    
    user = active_users[request.sid]
    if not user.get('is_moderator'):
        emit('error', {'message': 'Only moderators can create channels'})
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
        # Migration handling is missing from the modified code and needs to be added back from original
        from flask_migrate import upgrade
        upgrade()
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)