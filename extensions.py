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
        login_manager.init_app(app)
        bcrypt.init_app(app)
        mail.init_app(app)
        login_manager.login_view = 'login'
        logger.info("All extensions initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing extensions: {str(e)}")
        raise
