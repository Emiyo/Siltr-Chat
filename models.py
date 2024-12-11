from flask_login import UserMixin
from datetime import datetime
from extensions import db, bcrypt
import logging

logger = logging.getLogger(__name__)

# User roles association table
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    is_moderator = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), nullable=True)
    display_name = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(200), nullable=True)
    accent_color = db.Column(db.String(7), nullable=True, server_default='#5865F2')
    theme = db.Column(db.String(20), nullable=False, server_default='dark')
    bio = db.Column(db.Text, nullable=True)
    location = db.Column(db.String(100), nullable=True)
    banner_color = db.Column(db.String(7), nullable=True, server_default='#5865F2')
    last_seen = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    
    # Connection integrations
    github_id = db.Column(db.String(100), nullable=True, unique=True)
    github_username = db.Column(db.String(100), nullable=True)
    spotify_id = db.Column(db.String(100), nullable=True, unique=True)
    spotify_display_name = db.Column(db.String(100), nullable=True)
    discord_id = db.Column(db.String(100), nullable=True, unique=True)
    discord_username = db.Column(db.String(100), nullable=True)
    
    roles = db.relationship('Role', secondary=user_roles, lazy='subquery',
                          backref=db.backref('users', lazy=True))
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
        
    def set_password(self, password):
        """Set the password hash for the user."""
        if password:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def check_password(self, password):
        """Check if the provided password matches the hash."""
        try:
            if not password or not self.password_hash:
                logger.warning("Missing password or password hash")
                return False
            logger.info(f"Stored hash length: {len(self.password_hash)}")
            return bcrypt.check_password_hash(self.password_hash.encode('utf-8'), password)
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_verified': self.is_verified,
            'is_moderator': self.is_moderator,
            'avatar': self.avatar,
            'display_name': self.display_name or self.username,
            'status': self.status or '',
            'accent_color': self.accent_color or '#5865F2',
            'bio': self.bio or '',
            'location': self.location or '',
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat(),
            'roles': [role.name for role in self.roles]
        }

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name
        }

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    channels = db.relationship('Channel', backref='category', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'channels': [channel.to_dict() for channel in self.channels],
            'created_at': self.created_at.isoformat()
        }

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Messages will be accessed through the backref from Message model

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category_id': self.category_id,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat()
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id', ondelete='CASCADE'), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_key = db.Column(db.Text, nullable=True)
    file_url = db.Column(db.String(200), nullable=True)
    audio_url = db.Column(db.String(200), nullable=True)
    audio_duration = db.Column(db.Float, nullable=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('message.id', ondelete='SET NULL'), nullable=True)
    type = db.Column(db.String(20), nullable=False, server_default='message')  # 'system', 'message', 'private'
    
    # Add relationships for User, Channel and threading
    user = db.relationship('User', backref=db.backref('messages', lazy=True, cascade='all, delete-orphan'))
    channel = db.relationship('Channel', backref=db.backref('messages', lazy=True))
    parent = db.relationship('Message', remote_side=[id], backref=db.backref('replies', lazy=True))

    def to_dict(self):
        data = {
            'id': self.id,
            'content': self.content,
            'text': self.content,  # For frontend compatibility
            'timestamp': self.timestamp.isoformat(),
            'user_id': self.user_id,
            'channel_id': self.channel_id,
            'is_encrypted': self.is_encrypted,
            'encryption_key': self.encryption_key,
            'file_url': self.file_url,
            'audio_url': self.audio_url,
            'audio_duration': self.audio_duration,
            'type': self.type,
            'parent_id': self.parent_id
        }
        
        # Include user data for regular messages
        if not self.type == 'system':
            data['user'] = self.user.to_dict() if self.user else None
            
        # Include parent message data for replies
        if self.parent_id:
            data['parent'] = {
                'id': self.parent.id,
                'content': self.parent.content,
                'user': self.parent.user.to_dict() if self.parent.user else None
            }
            
        return data
