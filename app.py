import os
from datetime import datetime, timedelta
import logging
from logging.handlers import RotatingFileHandler
import random
import string
import time
import functools
from functools import wraps

# Flask and extensions
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import OperationalError, SQLAlchemyError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
))
logger.addHandler(handler)

# Initialize Flask app
app = Flask(__name__)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure app
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex()),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///chat.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max file size
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD')
)

# Initialize extensions
db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")
bcrypt = Bcrypt(app)
mail = Mail(app)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Configure token serializer for password reset
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Initialize Flask-Migrate
from flask_migrate import Migrate
migrate = Migrate(app, db)

class User(UserMixin, db.Model):
    """User model with Discord-like profile features"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    # Discord-like profile customization
    avatar = db.Column(db.String(200))  # URL to avatar image
    banner = db.Column(db.String(200))  # URL to banner image
    accent_color = db.Column(db.String(7), default='#7289DA')  # Discord's default color
    
    # Discord-like presence system
    status = db.Column(db.String(128))  # Custom status message
    presence_state = db.Column(db.String(20), default='online')  # online, idle, dnd, offline
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, onupdate=datetime.utcnow, default=datetime.utcnow)

    def set_password(self, password):
        if not self.validate_password_strength(password):
            raise ValueError("Password does not meet strength requirements")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    @staticmethod
    def validate_password_strength(password):
        if len(password) < 6:
            return False
        conditions = [
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password)
        ]
        return sum(conditions) >= 2

    def to_dict(self, include_private=False):
        data = {
            'id': self.id,
            'username': self.username,
            'avatar': self.avatar,
            'status': self.status,
            'presence_state': self.presence_state,
            'created_at': self.created_at.isoformat()
        }
        if include_private:
            data['email'] = self.email
        return data

class Message(db.Model):
    """Basic message model for profile activity"""
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Relationship with User model
    sender = db.relationship('User', backref=db.backref('messages', lazy=True))

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat()
        }

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        logger.info(f"Login attempt for email: {email}")

        if not all([email, password]):
            logger.warning("Login failed: Missing email or password")
            flash('All fields are required', 'error')
            return redirect(url_for('login'))

        user = User.query.filter_by(email=email).first()
        if user:
            if user.check_password(password):
                login_user(user)
                logger.info(f"User {user.username} logged in successfully")
                return redirect(url_for('index'))
            else:
                logger.warning(f"Login failed: Invalid password for user {user.username}")
        else:
            logger.warning(f"Login failed: No user found with email {email}")

        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')
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
            # Validate email
            validate_email(email)
        except EmailNotValidError:
            flash('Invalid email address', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        try:
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('register'))
        except SQLAlchemyError:
            db.session.rollback()
            flash('Error creating account', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/user/profile')
@login_required
def get_current_user_profile():
    return jsonify(current_user.to_dict(include_private=True))

@app.route('/api/user/by_id/<int:user_id>')
@login_required
def get_user_profile(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.to_dict())

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        # Handle file uploads
        if 'avatar' in request.files:
            avatar_file = request.files['avatar']
            if avatar_file and allowed_file(avatar_file.filename):
                filename = secure_filename(f"avatar_{current_user.id}_{int(time.time())}.{avatar_file.filename.rsplit('.', 1)[1]}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                avatar_file.save(filepath)
                current_user.avatar = f"/static/uploads/{filename}"

        if 'banner' in request.files:
            banner_file = request.files['banner']
            if banner_file and allowed_file(banner_file.filename):
                filename = secure_filename(f"banner_{current_user.id}_{int(time.time())}.{banner_file.filename.rsplit('.', 1)[1]}")
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                banner_file.save(filepath)
                current_user.banner = f"/static/uploads/{filename}"

        # Update other profile fields
        if 'accent_color' in request.form:
            current_user.accent_color = request.form['accent_color']
        if 'status' in request.form:
            current_user.status = request.form['status']
        if 'presence_state' in request.form:
            current_user.presence_state = request.form['presence_state']

        db.session.commit()
        flash('Profile updated successfully!', 'success')
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        flash('Error updating profile', 'error')
        db.session.rollback()

    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)