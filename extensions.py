from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_login import LoginManager
from flask_socketio import SocketIO
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
mail = Mail()
login_manager = LoginManager()
socketio = SocketIO()

def init_app(app):
    """Initialize Flask extensions"""
    try:
        # Initialize database and migrations
        db.init_app(app)
        migrate.init_app(app, db)
        
        # Initialize authentication
        bcrypt.init_app(app)
        login_manager.init_app(app)
        login_manager.login_view = 'login'
        login_manager.login_message_category = 'info'
        
        # Initialize communication
        mail.init_app(app)
        socketio.init_app(app, async_mode='eventlet', cors_allowed_origins="*")
        
        logger.info('All Flask extensions initialized successfully')
    except Exception as e:
        logger.error(f'Error initializing extensions: {str(e)}')
        raise
