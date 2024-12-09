import os
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, jsonify, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Log SQL queries
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
# Ensure proper PostgreSQL URL format
# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
database_url = os.environ['DATABASE_URL']
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app)

# Store active users in memory
active_users = {}
MAX_MESSAGES = 100

# Message Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200))  # URL to user avatar
    status = db.Column(db.String(100))  # User status message
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime, nullable=True)  # Timestamp until user is muted

    # Moderation actions
    def mute_user(self, duration_minutes=10):
        self.muted_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        return f"User {self.username} has been muted for {duration_minutes} minutes"

    def unmute_user(self):
        self.muted_until = None
        return f"User {self.username} has been unmuted"

    def promote_to_moderator(self):
        self.is_moderator = True
        return f"User {self.username} has been promoted to moderator"

    def demote_from_moderator(self):
        self.is_moderator = False
        return f"User {self.username} has been demoted from moderator"

    def update_profile(self, status=None, avatar=None):
        if status is not None:
            self.status = status
        if avatar is not None:
            self.avatar = avatar
        return "Profile updated successfully"

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'is_muted': self.muted_until and self.muted_until > datetime.utcnow()
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # 'public', 'private', 'system'
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # For private messages
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200))  # For file attachments
    reactions = db.Column(db.JSON, default=dict)  # Store reactions as {user_id: reaction_type}

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat(),
            'file_url': self.file_url,
            'reactions': self.reactions
        }

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    logging.debug(f"Client connected: {request.sid}")

@socketio.on('join')
def handle_join(data):
    username = data.get('username')
    if not username:
        return
    logger.debug(f"User joining: {username}")
    
    # Create or get user
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username)
        db.session.add(user)
        db.session.commit()
    
    # Store user information in active users
    active_users[request.sid] = {
        'id': user.id,
        'username': username,
        'is_moderator': user.is_moderator,
        'avatar': user.avatar,
        'status': user.status,
        'joined_at': datetime.now().isoformat()
    }
    
    # Create and store join message
    join_message = Message(
        type='system',
        sender_id=user.id,
        text=f'{username} has joined the chat',
        timestamp=datetime.now()
    )
    db.session.add(join_message)
    db.session.commit()
    
    # Send active users and message history
    try:
        recent_messages = Message.query\
            .filter((Message.type == 'public') | 
                   (Message.type == 'system') | 
                   ((Message.type == 'private') & 
                    ((Message.sender_id == user.id) | (Message.receiver_id == user.id))))\
            .order_by(Message.timestamp.desc())\
            .limit(MAX_MESSAGES)\
            .all()
        logger.debug(f"Retrieved {len(recent_messages)} messages from database")
        recent_messages.reverse()
    except Exception as e:
        logger.error(f"Error retrieving messages: {str(e)}")
        recent_messages = []
    
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    emit('message_history', {
        'messages': [msg.to_dict() for msg in recent_messages],
        'user_id': user.id
    })
    emit('new_message', join_message.to_dict(), broadcast=True)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file:
        # Save file with secure filename
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        file_url = url_for('static', filename=f'uploads/{filename}')
        return jsonify({'file_url': file_url})

@socketio.on('message')
def handle_message(data):
    if request.sid not in active_users:
        return
    
    user_data = active_users[request.sid]
    if not user_data:
        logger.error("User data not found")
        return
    text = data.get('text', '').strip()
    file_url = data.get('file_url')
    
    # Check if user is muted
    db_user = User.query.get(user_data['id'])
    if not db_user:
        emit('new_message', {
            'type': 'system',
            'text': 'Error: User not found',
            'timestamp': datetime.now().isoformat()
        })
        return
        
    if db_user.muted_until and db_user.muted_until > datetime.utcnow():
        emit('new_message', {
            'type': 'system',
            'text': f'You are muted until {db_user.muted_until.strftime("%H:%M:%S")}',
            'timestamp': datetime.now().isoformat()
        })
        return
    
    try:
        # Handle commands
        if text.startswith('/'):
            handle_command(text, user_data, db_user)
            return
        
        message = Message(
            type='public',
            sender_id=user_data['id'],
            text=text,
            file_url=file_url,
            timestamp=datetime.now()
        )
        db.session.add(message)
        db.session.commit()
        
        message_dict = message.to_dict()
        message_dict['sender_username'] = user_data['username']
        emit('new_message', message_dict, broadcast=True)
        logger.debug(f"Message sent: {message_dict}")
    except Exception as e:
        logger.error(f"Error sending message: {str(e)}")
        emit('new_message', {
            'type': 'system',
            'text': 'Error sending message',
            'timestamp': datetime.now().isoformat()
        })

@socketio.on('private_message')
def handle_private_message(data):
    if request.sid not in active_users:
        return
    
    sender = active_users[request.sid]
    recipient_username = data.get('recipient')
    text = data.get('text', '').strip()
    
    # Find recipient user
    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        emit('new_message', {
            'type': 'system',
            'text': f'User {recipient_username} not found',
            'timestamp': datetime.now().isoformat()
        })
        return
    
    message = Message(
        type='private',
        sender_id=sender['id'],
        receiver_id=recipient.id,
        text=text,
        timestamp=datetime.now()
    )
    db.session.add(message)
    db.session.commit()
    
    message_dict = message.to_dict()
    message_dict.update({
        'sender_username': sender['username'],
        'receiver_username': recipient_username
    })
    
    # Send to sender and recipient only
    for sid, user in active_users.items():
        if user['id'] in (sender['id'], recipient.id):
            emit('new_message', message_dict, room=sid)

@socketio.on('add_reaction')
def handle_reaction(data):
    if request.sid not in active_users:
        return
    
    user = active_users[request.sid]
    message_id = data.get('message_id')
    reaction = data.get('reaction')
    
    message = Message.query.get(message_id)
    if not message:
        return
    
    if not message.reactions:
        message.reactions = {}
    
    # Initialize reaction if it doesn't exist
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
    emit('new_message', message_dict, broadcast=True)

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
