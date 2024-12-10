from datetime import datetime
from flask import request, render_template
from flask_socketio import emit, join_room, leave_room
from flask_login import current_user
from utils.encryption import EncryptionWrapper

# Import from main.py
from main import socketio, db, logger
from models import User, Message, Channel, Category

# Initialize encryption wrapper
encryption = EncryptionWrapper()

# Global variables
active_users = {}  # sid -> user_data
user_keys = {}    # user_id -> encryption_key
MAX_MESSAGES = 100

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    file_url = db.Column(db.String(200))
    voice_url = db.Column(db.String(200))
    voice_duration = db.Column(db.Float)
    reactions = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'sender_id': self.sender_id,
            'channel_id': self.channel_id,
            'receiver_id': self.receiver_id,
            'text': self.text,
            'file_url': self.file_url,
            'voice_url': self.voice_url,
            'voice_duration': self.voice_duration,
            'reactions': self.reactions,
            'timestamp': self.timestamp.isoformat()
        }

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200))
    is_private = db.Column(db.Boolean, default=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

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
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

# SocketIO event handlers
@socketio.on("connect")
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on("request_channel_key")
def handle_channel_key_request(data):
    """Handle channel key requests from users"""
    try:
        if request.sid not in active_users:
            logger.error("Unauthorized channel key request")
            emit("error", {"message": "Unauthorized"})
            return

        channel_id = data.get("channelId")
        if not channel_id:
            logger.error("Missing channel ID in key request")
            emit("error", {"message": "Invalid channel ID"})
            return

        user_id = active_users[request.sid]["id"]
        
        # Get or generate channel key
        channel_key = encryption.get_key(channel_id, user_id)
        if not channel_key:
            channel_key = encryption.generate_key()
            encryption.store_key(channel_id, user_id, channel_key)
            logger.info(f"Generated new key for channel {channel_id}")
        
        # Send key to user
        emit("channel_key", {
            "channelId": channel_id,
            "key": channel_key,
            "forChannel": True
        })

    except Exception as e:
        logger.error(f"Error handling channel key request: {str(e)}")
        emit("error", {"message": "Error processing channel key request"})

@socketio.on("message")
def handle_message(data):
    """Handle incoming chat messages with encryption support"""
    try:
        if request.sid not in active_users:
            logger.error(f"User session {request.sid} not found in active_users")
            return

        user_data = active_users[request.sid]
        channel_id = data.get("channel_id")
        encrypted_content = data.get("encrypted_content")
        file_url = data.get("file_url")
        voice_url = data.get("voice_url")
        voice_duration = float(data.get("voice_duration", 0)) if data.get("voice_duration") else None

        # Check if user is muted
        user = User.query.get(user_data["id"])
        if user.is_muted():
            emit("error", {"message": f"You are muted until {user.muted_until}"})
            return

        # Create and save message
        message = Message(
            type="public",
            sender_id=user_data["id"],
            channel_id=channel_id,
            text=encrypted_content if encrypted_content else data.get("text", ""),
            file_url=file_url,
            voice_url=voice_url,
            voice_duration=voice_duration,
            reactions={},
            timestamp=datetime.utcnow(),
        )
        db.session.add(message)
        db.session.commit()

        # Broadcast message
        message_dict = message.to_dict()
        message_dict["encrypted"] = bool(encrypted_content)
        emit("new_message", message_dict, to=f"channel_{channel_id}")
        logger.info(f"Successfully broadcasted message to channel {channel_id}")

    except Exception as e:
        logger.error(f"Error in message handler: {str(e)}")
        emit("error", {"message": "Internal server error"})

@socketio.on("join")
def handle_join(data):
    """Handle user joining the chat"""
    try:
        username = data.get("username")
        if not username:
            logger.error("No username provided")
            emit("error", {"message": "Username is required"})
            return

        # Get or create user
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()

        # Store user in active users
        active_users[request.sid] = {
            "id": user.id,
            "username": user.username,
            "is_moderator": user.is_moderator,
            "status": user.status,
        }

        # Send join message
        join_message = Message(
            type="system",
            text=f"{username} has joined the chat",
            timestamp=datetime.utcnow(),
        )
        db.session.add(join_message)
        db.session.commit()

        # Broadcast join message
        emit(
            "user_joined",
            {"username": username, "timestamp": join_message.timestamp.isoformat()},
            broadcast=True,
        )

        logger.info(f"User {username} joined successfully")
    except Exception as e:
        logger.error(f"Error in handle_join: {str(e)}")
        emit("error", {"message": "Error joining chat"})

@socketio.on("join_channel")
def handle_join_channel(data):
    """Handle channel join requests"""
    if request.sid not in active_users:
        logger.error("Unauthorized channel join attempt")
        emit("error", {"message": "Unauthorized"})
        return

    channel_id = data.get("channel_id")
    channel = Channel.query.get(channel_id)
    if not channel:
        logger.error(f"Channel not found: {channel_id}")
        emit("error", {"message": "Channel not found"})
        return

    # Join the channel room
    join_room(f"channel_{channel_id}")
    logger.info(f"User joined channel {channel_id}")

    # Get recent messages for this channel
    recent_messages = (
        Message.query.filter_by(channel_id=channel_id)
        .order_by(Message.timestamp.desc())
        .limit(MAX_MESSAGES)
        .all()
    )
    recent_messages.reverse()

    emit(
        "channel_history",
        {
            "channel_id": channel_id,
            "messages": [msg.to_dict() for msg in recent_messages],
        },
    )

@socketio.on("disconnect")
def handle_disconnect():
    if request.sid in active_users:
        username = active_users[request.sid]["username"]
        del active_users[request.sid]

        leave_message = Message(
            type="system",
            text=f"{username} has left the chat",
            timestamp=datetime.utcnow(),
        )
        db.session.add(leave_message)
        db.session.commit()

        emit("user_list", {"users": list(active_users.values())}, broadcast=True)
        emit("new_message", leave_message.to_dict(), broadcast=True)

with app.app_context():
    db.create_all()
    # Ensure we have at least one channel
    if not Channel.query.first():
        default_channel = Channel(name="General", description="General chat channel")
        db.session.add(default_channel)
        db.session.commit()
