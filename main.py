import os
import multiprocessing
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_flask():
    """Start the Flask application"""
    from app import app
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting Flask HTTP server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)

def run_websocket():
    """Start the WebSocket server"""
    import asyncio
    from websocket_server import main as start_websocket_server
    port = int(os.environ.get('WEBSOCKET_PORT', 8080))
    logger.info(f"🔌 Starting WebSocket server on port {port}")
    
    # Set the port for the websocket server
    os.environ['WEBSOCKET_PORT'] = str(port)
    
    # Start the websocket server using asyncio
    asyncio.run(start_websocket_server())

if __name__ == '__main__':
    logger.info("🚀 Starting application with multiprocessing...")
    
    # Start both servers in separate processes
    flask_process = multiprocessing.Process(target=run_flask, name="Flask-Server")
    websocket_process = multiprocessing.Process(target=run_websocket, name="WebSocket-Server")
    
    try:
        flask_process.start()
        logger.info("✅ Flask server process started")
        
        websocket_process.start()
        logger.info("✅ WebSocket server process started")
        
        # Wait for both processes
        flask_process.join()
        websocket_process.join()
        
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down servers...")
        flask_process.terminate()
        websocket_process.terminate()
        flask_process.join()
        websocket_process.join()
        logger.info("✅ Servers stopped")
    except Exception as e:
        logger.error(f"❌ Error starting servers: {e}")
        flask_process.terminate()
        websocket_process.terminate()
        raise 