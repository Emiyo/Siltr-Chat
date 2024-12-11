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
        # Configure socketio with proper settings
        socketio.init_app(
            app,
            async_mode='eventlet',
            cors_allowed_origins="*",
            logger=logger,
            engineio_logger=True,
            ping_timeout=5,
            ping_interval=25,
            max_http_buffer_size=100000000
        )
        
        # Run the server
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=True,
            use_reloader=False,  # Disable reloader to avoid duplicate processes
            log_output=True
        )
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        raise
