import os
from datetime import datetime
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room
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
database_url = os.environ['DATABASE_URL']
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)

# Store active users in memory
active_users = {}
MAX_MESSAGES = 100

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    username = db.Column(db.String(50))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'type': self.type,
            'username': self.username,
            'text': self.text,
            'timestamp': self.timestamp.isoformat()
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
    
    # Store user information
    active_users[request.sid] = {
        'username': username,
        'joined_at': datetime.now().isoformat()
    }
    
    # Create and store join message
    join_message = Message(
        type='system',
        text=f'{username} has joined the chat',
        timestamp=datetime.now()
    )
    db.session.add(join_message)
    db.session.commit()
    
    # Send active users and message history
    try:
        recent_messages = Message.query.order_by(Message.timestamp.desc()).limit(MAX_MESSAGES).all()
        logger.debug(f"Retrieved {len(recent_messages)} messages from database")
        recent_messages.reverse()
    except Exception as e:
        logger.error(f"Error retrieving messages: {str(e)}")
        recent_messages = []
    
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    emit('message_history', {'messages': [msg.to_dict() for msg in recent_messages]})
    emit('new_message', join_message.to_dict(), broadcast=True)

@socketio.on('message')
def handle_message(data):
    if request.sid not in active_users:
        return
    
    username = active_users[request.sid]['username']
    text = data.get('text', '').strip()
    
    # Handle commands
    if text.startswith('/'):
        handle_command(text, username)
        return
    
    message = Message(
        type='message',
        username=username,
        text=text,
        timestamp=datetime.now()
    )
    db.session.add(message)
    db.session.commit()
    
    emit('new_message', message.to_dict(), broadcast=True)

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

def handle_command(text, username):
    command = text.lower().split()[0]
    
    if command == '/help':
        help_message = {
            'type': 'system',
            'text': 'Available commands: /help - Show this message, /clear - Clear your chat history',
            'timestamp': datetime.now().isoformat()
        }
        emit('new_message', help_message)
    elif command == '/clear':
        emit('clear_chat')
