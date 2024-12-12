from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import logging

logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
bcrypt = Bcrypt()
mail = Mail()

def init_extensions(app):
    """Initialize Flask extensions with better error handling"""
    try:
        db.init_app(app)
        
        # Configure login manager
        login_manager.init_app(app)
        login_manager.login_view = 'login'
        login_manager.login_message = 'Please log in to access this page'
        login_manager.login_message_category = 'info'
        login_manager.session_protection = None  # Disable strict session protection temporarily
        login_manager.refresh_view = 'login'
        login_manager.needs_refresh_message = 'Please login again to confirm your identity'
        login_manager.needs_refresh_message_category = 'info'
        
        bcrypt.init_app(app)
        mail.init_app(app)
        
        logger.info("All extensions initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing extensions: {str(e)}")
        raise
