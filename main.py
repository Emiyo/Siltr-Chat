import eventlet
eventlet.monkey_patch()

import logging
from app import app, socketio

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        logger.info("Starting Flask-SocketIO server...")
        socketio.init_app(app, 
                         async_mode='eventlet', 
                         cors_allowed_origins="*", 
                         logger=logger)
        socketio.run(app, 
                    host='0.0.0.0',
                    port=5000,
                    debug=True,
                    use_reloader=False)  # Disable reloader to avoid duplicate processes
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise
