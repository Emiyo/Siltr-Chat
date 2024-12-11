from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from extensions import db, logger

# Association tables for roles and permissions
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id', ondelete='CASCADE'), primary_key=True)
)

user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', ondelete='CASCADE'), primary_key=True)
)

class Role(db.Model):
    """Role model for user permissions"""
    __tablename__ = 'role'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')
    users = db.relationship('User', secondary=user_roles, back_populates='roles')

class Permission(db.Model):
    """Permission model for granular access control"""
    __tablename__ = 'permission'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')

class User(UserMixin, db.Model):
    """User model with Discord-like profile features"""
    __tablename__ = 'user'
    
    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Profile fields
    display_name = db.Column(db.String(50), nullable=True)
    avatar = db.Column(db.String(200), nullable=True)
    banner = db.Column(db.String(200), nullable=True)
    bio = db.Column(db.String(500), nullable=True)
    
    # Rich presence and status
    status = db.Column(db.String(100), nullable=True)
    status_emoji = db.Column(db.String(20), nullable=True)
    presence_state = db.Column(db.String(20), nullable=False, default='offline')
    presence_details = db.Column(db.JSON, nullable=True)  # For activity details
    last_seen = db.Column(db.DateTime, nullable=True)
    
    # Customization
    theme = db.Column(db.String(20), nullable=False, default='dark')
    accent_color = db.Column(db.String(7), nullable=True, default='#5865F2')
    preferences = db.Column(db.JSON, nullable=True, default=lambda: {
        'notifications': True,
        'message_display': 'cozy',
        'emoji_style': 'native',
        'language': 'en'
    })
    
    # System fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    warning_count = db.Column(db.Integer, nullable=False, default=0)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id',
                                   backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id',
                                       backref='receiver', lazy='dynamic')
    
    def __init__(self, username, email, password=None):
        self.username = username
        self.email = email
        if password:
            self.set_password(password)

    def set_password(self, password):
        """Set password with proper hashing"""
        try:
            if not self.validate_password_strength(password):
                raise ValueError("Password must be at least 8 characters and include numbers and letters")
            self.password_hash = generate_password_hash(password)
        except Exception as e:
            logger.error(f"Error setting password for user {self.username}: {str(e)}")
            raise

    def check_password(self, password):
        """Verify password hash"""
        try:
            return check_password_hash(self.password_hash, password)
        except Exception as e:
            logger.error(f"Error checking password for user {self.username}: {str(e)}")
            return False

    @staticmethod
    def validate_password_strength(password):
        """Ensure password meets security requirements"""
        if len(password) < 8:
            return False
        has_digit = any(c.isdigit() for c in password)
        has_alpha = any(c.isalpha() for c in password)
        return has_digit and has_alpha

    def update_presence(self, state='online', details=None):
        """Update user's presence state and details"""
        try:
            valid_states = {'online', 'idle', 'dnd', 'offline', 'invisible'}
            if state not in valid_states:
                raise ValueError(f"Invalid presence state. Must be one of: {', '.join(valid_states)}")
            
            self.presence_state = state
            if details:
                self.presence_details = details
            self.last_seen = datetime.utcnow()
            
            logger.info(f"Updated presence for user {self.username}: {state}")
        except Exception as e:
            logger.error(f"Error updating presence for user {self.username}: {str(e)}")
            raise

    def set_status(self, text=None, emoji=None):
        """Set custom status message with emoji support"""
        try:
            if text and len(text) > 100:
                raise ValueError("Status message cannot exceed 100 characters")
            
            self.status = text
            if emoji:
                self.status_emoji = emoji
                
            logger.info(f"Updated status for user {self.username}")
        except Exception as e:
            logger.error(f"Error setting status for user {self.username}: {str(e)}")
            raise

    def has_permission(self, permission_name):
        """Check if user has a specific permission through any of their roles"""
        try:
            return any(
                any(p.name == permission_name for p in role.permissions)
                for role in self.roles
            )
        except Exception as e:
            logger.error(f"Error checking permissions for user {self.username}: {str(e)}")
            return False

    def to_dict(self, include_private=False):
        """Convert user object to dictionary with profile structure"""
        data = {
            'id': self.id,
            'username': self.username,
            'display_name': self.display_name or self.username,
            'avatar': self.avatar,
            'bio': self.bio,
            'status': self.status,
            'presence_state': self.presence_state,
            'theme': self.theme,
            'accent_color': self.accent_color,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_verified': self.is_verified,
            'is_active': self.is_active,
            'roles': [{'id': role.id, 'name': role.name} for role in self.roles]
        }
        
        if include_private:
            data.update({
                'email': self.email,
                'preferences': self.preferences or {},
                'warning_count': self.warning_count
            })
    def customize_profile(self, **kwargs):
        """Update user profile customization options"""
        try:
            valid_fields = {
                'theme', 'accent_color', 'banner', 'display_name',
                'bio', 'avatar', 'preferences'
            }
            
            for field, value in kwargs.items():
                if field not in valid_fields:
                    continue
                    
                if field == 'preferences' and isinstance(value, dict):
                    current_prefs = self.preferences or {}
                    current_prefs.update(value)
                    setattr(self, field, current_prefs)
                else:
                    setattr(self, field, value)
            
            logger.info(f"Updated profile customization for user {self.username}")
        except Exception as e:
            logger.error(f"Error customizing profile for user {self.username}: {str(e)}")
            raise
    
    def to_dict(self, include_private=False):
        """Convert user object to dictionary with rich profile structure"""
        try:
            data = {
                'id': self.id,
                'username': self.username,
                'display_name': self.display_name or self.username,
                'avatar': self.avatar,
                'banner': self.banner,
                'bio': self.bio,
                'status': self.status,
                'status_emoji': self.status_emoji,
                'presence_state': self.presence_state,
                'presence_details': self.presence_details,
                'theme': self.theme,
                'accent_color': self.accent_color,
                'created_at': self.created_at.isoformat() if self.created_at else None,
                'last_seen': self.last_seen.isoformat() if self.last_seen else None,
                'is_verified': self.is_verified,
                'roles': [{'id': role.id, 'name': role.name} for role in self.roles]
            }
            
            if include_private:
                data.update({
                    'email': self.email,
                    'preferences': self.preferences,
                    'warning_count': self.warning_count,
                    'is_active': self.is_active
                })
                
            return data
        except Exception as e:
            logger.error(f"Error converting user {self.username} to dict: {str(e)}")
            raise

            
        return data

class Message(db.Model):
    """Message model for user communications"""
    __tablename__ = 'message'
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)  # public, private, system
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'))
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id', ondelete='CASCADE'))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200), nullable=True)
    voice_url = db.Column(db.String(200), nullable=True)
    voice_duration = db.Column(db.Float, nullable=True)
    reactions = db.Column(db.JSON, default=dict)
    
    def to_dict(self):
        """Convert message to dictionary"""
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
            'reactions': self.reactions or {}
        }

class Channel(db.Model):
    """Channel model for organizing messages"""
    __tablename__ = 'channel'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    type = db.Column(db.String(20), default='text')  # text, voice, announcement
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('Message', backref='channel', lazy='dynamic')
