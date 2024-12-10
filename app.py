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
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
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

# Initialize Flask app and extensions
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL", os.environ.get("DATABASE_URL")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size

# Email Configuration
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER")

# Ensure upload folder exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Store user public keys and channel encryption keys
public_keys = {}  # userId -> public_key
channel_keys = {}  # channelId -> encryption_key

# Encryption Configuration
RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048
RSA_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
)


def generate_rsa_keypair():
    """Generate a new RSA key pair"""
    try:
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=RSA_KEY_SIZE,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return {
            "private_key": base64.b64encode(private_pem).decode("utf-8"),
            "public_key": base64.b64encode(public_pem).decode("utf-8"),
        }
    except Exception as e:
        logger.error(f"Error generating RSA key pair: {str(e)}")
        raise


def generate_channel_key():
    """Generate a new AES key for channel encryption"""
    return AESGCM.generate_key(bit_length=256)


def encrypt_channel_key(channel_key, public_key_pem):
    """Encrypt a channel key with a user's public key"""
    try:
        public_key = serialization.load_pem_public_key(
            base64.b64decode(public_key_pem), backend=default_backend()
        )
        encrypted_key = public_key.encrypt(channel_key, RSA_PADDING)
        return base64.b64encode(encrypted_key).decode("utf-8")
    except Exception as e:
        logger.error(f"Error encrypting channel key: {str(e)}")
        raise


def decrypt_message(encrypted_data, key, associated_data=None):
    """Decrypt a message using AES-GCM"""
    try:
        if not isinstance(encrypted_data, dict) or not all(
            k in encrypted_data for k in ("nonce", "ciphertext")
        ):
            raise ValueError("Invalid encrypted message format")

        aesgcm = AESGCM(key)
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
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
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }
    except Exception as e:
        logger.error(f"Error encrypting message: {str(e)}")
        raise


# ... [keeping all the existing models and routes] ...


@socketio.on("connect")
def handle_connect():
    logger.info(f"Client connected: {request.sid}")


@socketio.on("share_public_key")
def handle_public_key(data):
    """Handle the sharing of public keys between users"""
    try:
        if request.sid not in active_users:
            logger.error(f"User not found for session {request.sid}")
            return

        user_id = active_users[request.sid]["id"]
        public_key = data.get("publicKey")

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
        emit(
            "public_key_shared",
            {"userId": user_id, "publicKey": public_key},
            broadcast=True,
        )

        # Share existing public keys with this user
        for uid, key in public_keys.items():
            if uid != user_id:
                emit("public_key_shared", {"userId": uid, "publicKey": key})
        logger.info(f"Successfully shared public keys for user {user_id}")
    except Exception as e:
        logger.error(f"Error handling public key: {str(e)}")
        emit("error", {"message": "Error processing public key"})


@socketio.on("request_channel_key")
def handle_channel_key_request(data):
    """Handle channel key requests from users"""
    if request.sid not in active_users:
        logger.error("Unauthorized channel key request")
        emit("error", {"message": "Unauthorized"})
        return

    channel_id = data.get("channelId")
    if not channel_id:
        logger.error("Missing channel ID in key request")
        emit("error", {"message": "Invalid channel ID"})
        return

    user_data = active_users[request.sid]

    # Generate new channel key if it doesn't exist
    if channel_id not in channel_keys:
        channel_keys[channel_id] = generate_channel_key()
        logger.info(f"Generated new key for channel {channel_id}")

    # Get user's public key
    public_key = public_keys.get(user_data["id"])
    if not public_key:
        logger.error(f"Public key not found for user {user_data['id']}")
        emit("error", {"message": "Public key not found"})
        return

    try:
        encrypted_key = encrypt_channel_key(channel_keys[channel_id], public_key)
        emit("channel_key", {"channelId": channel_id, "encryptedKey": encrypted_key})
        logger.info(f"Successfully shared channel key with user {user_data['id']}")
    except Exception as e:
        logger.error(f"Error sharing channel key: {str(e)}")
        emit("error", {"message": "Error sharing channel key"})


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

        # Generate and store RSA keypair
        keypair = generate_rsa_keypair()
        emit("encryption_keys", keypair)

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


@socketio.on("message")
def handle_message(data):
    """Handle incoming chat messages with encryption support"""
    try:
        logger.debug(f"Received message data: {data}")

        if request.sid not in active_users:
            logger.error(f"User session {request.sid} not found in active_users")
            return

        user_data = active_users[request.sid]
        if not user_data:
            logger.error(f"User data not found for session {request.sid}")
            return

        logger.info(f"Processing message from user: {user_data['username']}")
        encrypted_data = data.get("encrypted_data")
        channel_id = data.get("channel_id")
        file_url = data.get("file_url")
        voice_url = data.get("voice_url")
        voice_duration = (
            float(data.get("voice_duration", 0)) if data.get("voice_duration") else None
        )

        # Check if user is muted
        user = User.query.get(user_data["id"])
        if user.is_muted():
            emit("error", {"message": f"You are muted until {user.muted_until}"})
            return

        # Process encrypted messages
        if encrypted_data:
            # Validate encrypted data format
            if not isinstance(encrypted_data, dict) or not all(
                k in encrypted_data for k in ("nonce", "ciphertext")
            ):
                logger.error("Invalid encrypted message format")
                emit("error", {"message": "Invalid message format"})
                return

            # Verify channel key exists
            if channel_id not in channel_keys:
                logger.error(f"Channel key not found for channel {channel_id}")
                emit("error", {"message": "Channel key not found"})
                return

            # Create and save message with encrypted content
            message = Message(
                type="public",
                sender_id=user_data["id"],
                channel_id=channel_id,
                text=json.dumps(encrypted_data),
                file_url=file_url,
                voice_url=voice_url,
                voice_duration=voice_duration,
                reactions={},
                timestamp=datetime.utcnow(),
            )
            db.session.add(message)
            db.session.commit()

            # Broadcast the encrypted message
            message_dict = message.to_dict()
            message_dict["timestamp"] = message.timestamp.isoformat()
            message_dict["encrypted"] = True
            room = f"channel_{channel_id}"
            emit("new_message", message_dict, room=room)
            logger.info(
                f"Successfully broadcasted encrypted message to channel {channel_id}"
            )

        else:
            # Handle unencrypted messages (system messages, etc.)
            message = Message(
                type="public",
                sender_id=user_data["id"],
                channel_id=channel_id,
                text=data.get("text", ""),
                file_url=file_url,
                voice_url=voice_url,
                voice_duration=voice_duration,
                reactions={},
                timestamp=datetime.utcnow(),
            )
            db.session.add(message)
            db.session.commit()

            # Broadcast unencrypted message
            message_dict = message.to_dict()
            message_dict["timestamp"] = message.timestamp.isoformat()
            room = f"channel_{channel_id}"
            emit("new_message", message_dict, room=room)
            logger.info(f"Successfully broadcasted message to channel {channel_id}")

    except Exception as e:
        logger.error(f"Error in message handler: {str(e)}")
        emit("error", {"message": "Internal server error"})


@socketio.on("add_reaction")
def handle_reaction(data):
    if request.sid not in active_users:
        return

    user = active_users[request.sid]
    message_id = data.get("message_id")
    reaction = data.get("reaction")

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
    user_id = str(user["id"])
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
    message_dict["sender_username"] = User.query.get(message.sender_id).username
    if message.receiver_id:
        message_dict["receiver_username"] = User.query.get(message.receiver_id).username

    # Broadcast to channel if specified, otherwise broadcast to all
    if message.channel_id:
        emit("new_message", message_dict, room=f"channel_{message.channel_id}")
    else:
        emit("new_message", message_dict, broadcast=True)


@socketio.on("join_channel")
def handle_join_channel(data):
    """Handle channel join requests with encryption key distribution"""
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

    # Ensure channel has an encryption key
    if channel_id not in channel_keys:
        channel_keys[channel_id] = generate_channel_key()
        logger.info(f"Generated new encryption key for channel {channel_id}")

    # Share channel key with the joining user
    user_id = active_users[request.sid]["id"]
    if user_id in public_keys:
        try:
            encrypted_key = encrypt_channel_key(
                channel_keys[channel_id], public_keys[user_id]
            )
            emit(
                "channel_key", {"channelId": channel_id, "encryptedKey": encrypted_key}
            )
            logger.info(f"Shared channel key with user {user_id}")
        except Exception as e:
            logger.error(f"Error sharing channel key: {str(e)}")
            emit("error", {"message": "Error sharing channel key"})

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


@socketio.on("leave_channel")
def handle_leave_channel(data):
    if request.sid not in active_users:
        return

    channel_id = data.get("channel_id")
    leave_room(f"channel_{channel_id}")


@socketio.on("get_categories")
def handle_get_categories():
    if request.sid not in active_users:
        logger.warning(f"Unauthorized request for categories from {request.sid}")
        return

    try:
        categories = Category.query.all()
        logger.info(f"Found {len(categories)} categories")
        emit(
            "categories_list",
            {"categories": [category.to_dict() for category in categories]},
        )
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}")
        emit("error", {"message": "Error loading categories"})


@socketio.on("create_category")
def handle_create_category(data):
    if request.sid not in active_users:
        return

    user_data = active_users[request.sid]
    user = User.query.get(user_data["id"])
    if not user.has_permission("manage_channels"):
        emit("error", {"message": "Permission denied: Cannot create categories"})
        return

    name = data.get("name")
    description = data.get("description")

    if not name:
        emit("error", {"message": "Category name is required"})
        return

    category = Category(name=name, description=description)
    db.session.add(category)
    db.session.commit()

    emit("category_created", category.to_dict(), broadcast=True)


@socketio.on("create_channel")
def handle_create_channel(data):
    if request.sid not in active_users:
        return

    user_data = active_users[request.sid]
    user = User.query.get(user_data["id"])
    if not user.has_permission("create_channels"):
        emit("error", {"message": "Permission denied: Cannot create channels"})
        return

    category_id = data.get("category_id")
    name = data.get("name")
    description = data.get("description")
    is_private = data.get("is_private", False)

    if not all([category_id, name]):
        emit("error", {"message": "Category ID and channel name are required"})
        return

    channel = Channel(
        category_id=category_id,
        name=name,
        description=description,
        is_private=is_private,
    )
    db.session.add(channel)
    db.session.commit()

    emit("channel_created", channel.to_dict(), broadcast=True)


@socketio.on("disconnect")
def handle_disconnect():
    if request.sid in active_users:
        username = active_users[request.sid]["username"]
        del active_users[request.sid]

        leave_message = Message(
            type="system",
            text=f"{username} has left the chat",
            timestamp=datetime.now(),
        )
        db.session.add(leave_message)
        db.session.commit()

        emit("user_list", {"users": list(active_users.values())}, broadcast=True)
        emit("new_message", leave_message.to_dict(), broadcast=True)


def handle_command(text, user_data, db_user):
    command_parts = text.lower().split()
    command = command_parts[0]

    if command == "/help":
        help_text = (
            "Available commands:\n"
            + "/help - Show this message\n"
            + "/clear - Clear your chat history\n"
            + "/status <message> - Update your status\n"
        )
        if user_data["is_moderator"]:
            help_text += (
                "Moderator commands:\n"
                + "/mute @user <minutes> - Mute a user\n"
                + "/unmute @user - Unmute a user\n"
                + "/promote @user - Promote user to moderator\n"
                + "/demote @user - Demote user from moderator"
            )
        help_message = {
            "type": "system",
            "text": help_text,
            "timestamp": datetime.now().isoformat(),
        }
        emit("new_message", help_message)
    elif command == "/clear":
        emit("clear_chat")
    elif command == "/status" and len(command_parts) > 1:
        status = " ".join(command_parts[1:])
        result = db_user.update_profile(status=status)
        emit(
            "new_message",
            {"type": "system", "text": result, "timestamp": datetime.now().isoformat()},
        )
        # Update active users with new status
        active_users[request.sid]["status"] = status
        emit("user_list", {"users": list(active_users.values())}, broadcast=True)
    elif user_data["is_moderator"]:
        if (
            command in ["/mute", "/unmute", "/promote", "/demote"]
            and len(command_parts) > 1
        ):
            target_username = command_parts[1].lstrip("@")
            target_user = User.query.filter_by(username=target_username).first()

            if not target_user:
                emit(
                    "new_message",
                    {
                        "type": "system",
                        "text": f"User {target_username} not found",
                        "timestamp": datetime.now().isoformat(),
                    },
                )
                return

            result = None
            if command == "/mute":
                duration = int(command_parts[2]) if len(command_parts) > 2 else 10
                result = target_user.mute_user(duration)
            elif command == "/unmute":
                result = target_user.unmute_user()
            elif command == "/promote":
                result = target_user.promote_to_moderator()
            elif command == "/demote":
                result = target_user.demote_from_moderator()

            if result:
                db.session.commit()
                emit(
                    "new_message",
                    {
                        "type": "system",
                        "text": result,
                        "timestamp": datetime.now().isoformat(),
                    },
                    broadcast=True,
                )
                # Update user list to reflect changes
                emit(
                    "user_list", {"users": list(active_users.values())}, broadcast=True
                )


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
