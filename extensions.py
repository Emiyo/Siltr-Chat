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
        # Initialize core database first
        db.init_app(app)
        logger.info('Database initialized')
        
        # Initialize authentication components
        bcrypt.init_app(app)
        login_manager.init_app(app)
        login_manager.login_view = 'login'
        login_manager.login_message_category = 'info'
        login_manager.session_protection = 'strong'
        logger.info('Authentication components initialized')
        
        # Initialize migrations after database
        migrate.init_app(app, db)
        logger.info('Database migrations initialized')
        
        # Initialize communication components last
        mail.init_app(app)
        socketio.init_app(app, async_mode='eventlet', cors_allowed_origins="*", logger=True)
        logger.info('Communication components initialized')
        
        logger.info('All Flask extensions initialized successfully')
        return True
    except Exception as e:
        logger.error(f'Error initializing extensions: {str(e)}')
        raise
