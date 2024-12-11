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
        # Use eventlet as the async_mode
        socketio.init_app(app, async_mode='eventlet', cors_allowed_origins="*")
        socketio.run(app, 
                    host="0.0.0.0", 
                    port=5000,
                    debug=True,
                    use_reloader=True,
                    log_output=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise
