import os
from datetime import datetime
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "a secret key"
socketio = SocketIO(app)

# Store active users and messages in memory
active_users = {}
messages = []
MAX_MESSAGES = 100

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
    
    # Store user information
    active_users[request.sid] = {
        'username': username,
        'joined_at': datetime.now().isoformat()
    }
    
    # Send join notification
    join_message = {
        'type': 'system',
        'text': f'{username} has joined the chat',
        'timestamp': datetime.now().isoformat()
    }
    messages.append(join_message)
    if len(messages) > MAX_MESSAGES:
        messages.pop(0)
    
    # Send active users and message history
    emit('user_list', {'users': list(active_users.values())}, broadcast=True)
    emit('message_history', {'messages': messages})
    emit('new_message', join_message, broadcast=True)

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
    
    message = {
        'type': 'message',
        'username': username,
        'text': text,
        'timestamp': datetime.now().isoformat()
    }
    messages.append(message)
    if len(messages) > MAX_MESSAGES:
        messages.pop(0)
    
    emit('new_message', message, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in active_users:
        username = active_users[request.sid]['username']
        del active_users[request.sid]
        
        leave_message = {
            'type': 'system',
            'text': f'{username} has left the chat',
            'timestamp': datetime.now().isoformat()
        }
        messages.append(leave_message)
        if len(messages) > MAX_MESSAGES:
            messages.pop(0)
        
        emit('user_list', {'users': list(active_users.values())}, broadcast=True)
        emit('new_message', leave_message, broadcast=True)

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
