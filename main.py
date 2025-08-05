import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_application():
    """Start the integrated Flask application with WebSocket support"""
    from app import app
    port = int(os.environ.get('PORT', 5000))
    logger.info(f"🚀 Starting integrated Flask application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)

if __name__ == '__main__':
    logger.info("🚀 Starting integrated application...")
    run_application() 