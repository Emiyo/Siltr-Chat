from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from app import db

class User(UserMixin, db.Model):
    """User model with Discord-like profile features"""
    __tablename__ = 'user'
    
    # Core fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Profile fields
    display_name = db.Column(db.String(50))
    avatar = db.Column(db.String(200))
    bio = db.Column(db.String(500))
    
    # Presence and status
    status = db.Column(db.String(100))
    presence_state = db.Column(db.String(20), default='offline')
    last_seen = db.Column(db.DateTime)
    
    # Customization
    theme = db.Column(db.String(20), default='dark')
    
    # System fields
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_verified = db.Column(db.Boolean, default=False)

    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id',
                                  backref='sender', lazy='dynamic')
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id',
                                      backref='receiver', lazy='dynamic')

    def set_password(self, password):
        """Set password hash"""
        if not self.validate_password_strength(password):
            raise ValueError("Password must be at least 8 characters and include numbers and letters")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password hash"""
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_password_strength(password):
        """Ensure password meets security requirements"""
        if len(password) < 8:
            return False
        return any(c.isdigit() for c in password) and any(c.isalpha() for c in password)

    def update_presence(self, state='online'):
        """Update user's presence state and last seen timestamp"""
        valid_states = {'online', 'idle', 'dnd', 'offline'}
        if state not in valid_states:
            raise ValueError(f"Invalid presence state. Must be one of: {', '.join(valid_states)}")
        self.presence_state = state
        self.last_seen = datetime.utcnow()

    def set_status(self, text=None):
        """Set custom status message"""
        if text and len(text) > 100:
            raise ValueError("Status message cannot exceed 100 characters")
        self.status = text

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
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_verified': self.is_verified
        }
        
        if include_private:
            data.update({
                'email': self.email,
            })
            
        return data

class Message(db.Model):
    """Message model for user communications"""
    __tablename__ = 'message'
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_url = db.Column(db.String(200))

    def to_dict(self):
        """Convert message to dictionary"""
        return {
            'id': self.id,
            'type': self.type,
            'sender_id': self.sender_id,
            'receiver_id': self.receiver_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat(),
            'file_url': self.file_url
        }
