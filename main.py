import os
import threading
import logging
import asyncio
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_websocket_in_thread():
    """Start the WebSocket server in a background thread"""
    try:
        from websocket_server import main as start_websocket_server
        port = int(os.environ.get('WEBSOCKET_PORT', 8080))
        logger.info(f"🔌 Starting WebSocket server on port {port}")
        
        # Set the port for the websocket server
        os.environ['WEBSOCKET_PORT'] = str(port)
        
        # Create new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Start the websocket server
        loop.run_until_complete(start_websocket_server())
    except Exception as e:
        logger.error(f"❌ WebSocket server error: {e}")

if __name__ == '__main__':
    logger.info("🚀 Starting application...")
    
    # Initialize databases before starting servers
    logger.info("🔧 Initializing databases...")
    try:
        from init_databases import main as init_databases
        init_databases()
        logger.info("✅ Database initialization complete")
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        # Continue anyway - databases might already exist
    
    # Start WebSocket server in background thread
    websocket_thread = threading.Thread(target=run_websocket_in_thread, daemon=True)
    websocket_thread.start()
    logger.info("✅ WebSocket server thread started")
    
    # Start Flask server in main process (for Railway health checks)
    from app import app
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting Flask HTTP server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False) 