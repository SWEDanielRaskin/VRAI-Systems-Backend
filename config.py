import os #yaaaaaaaaa

from datetime import datetime

# Business Information
BUSINESS_NAME = "Carla Thomas Med Spa"
BUSINESS_FULL_NAME = "Carla Thomas Med Spa"
BUSINESS_WEBSITE = "https://www.carlathomasmedspa.com/"
BUSINESS_DESCRIPTION = "Med Spa"

# Timezone Configuration
TIMEZONE = "America/New_York"
PYTZ_TIMEZONE = "America/New_York"

# Database Configuration - Support Railway persistent volumes
DATABASE_NAME = os.environ.get('DATABASE_PATH', "radiance_md.db")
SCHEDULED_MESSAGES_DB = os.environ.get('SCHEDULED_MESSAGES_PATH', "scheduled_messages.db")

# File paths for Railway persistence
UPLOADS_PATH = os.environ.get('UPLOADS_PATH', "uploads")
CREDENTIALS_PATH = os.environ.get('CREDENTIALS_PATH', "credentials")

# Ensure database directories exist
def ensure_database_directories():
    """Ensure database directories exist for Railway deployment"""
    db_dir = os.path.dirname(DATABASE_NAME)
    scheduled_dir = os.path.dirname(SCHEDULED_MESSAGES_DB)
    
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    if scheduled_dir and not os.path.exists(scheduled_dir):
        os.makedirs(scheduled_dir, exist_ok=True)
    
    # Ensure uploads and credentials directories exist
    if not os.path.exists(UPLOADS_PATH):
        os.makedirs(UPLOADS_PATH, exist_ok=True)
    
    if not os.path.exists(CREDENTIALS_PATH):
        os.makedirs(CREDENTIALS_PATH, exist_ok=True)

# Initialize directories on import
ensure_database_directories()

# Project Configuration
PROJECT_NAME = "medspa-dashboard"

# Login Configuration
LOGIN_PASSWORD = "radiance2024"

# Page Titles
PAGE_TITLES = {
    "dashboard": "{business_name} - Dashboard",
    "customers": "Manage all {business_name} customers"
} 