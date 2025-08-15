import os #my ahh
from datetime import datetime

# Business Information
BUSINESS_NAME = "VRAI Systems Med Spa"
BUSINESS_FULL_NAME = "VRAI Systems Med Spa"
BUSINESS_WEBSITE = "https://www.vraisystems.org"
BUSINESS_DESCRIPTION = "Med Spa"

# Timezone Configuration
TIMEZONE = "America/New_York"
PYTZ_TIMEZONE = "America/New_York"

# Database Configuration - Support Railway persistent volumes
DATABASE_NAME = os.environ.get('DATABASE_PATH', "/data/radiance_md.db")

# File paths for Railway persistence
UPLOADS_PATH = os.environ.get('UPLOADS_PATH', "/data/uploads")
CREDENTIALS_PATH = os.environ.get('CREDENTIALS_PATH', "/data/credentials")

# Ensure database directories exist
def ensure_database_directories():
    """Ensure database directories exist for Railway deployment"""
    db_dir = os.path.dirname(DATABASE_NAME)
    
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # Ensure uploads and credentials directories exist
    if not os.path.exists(UPLOADS_PATH):
        os.makedirs(UPLOADS_PATH, exist_ok=True)
    
    if not os.path.exists(CREDENTIALS_PATH):
        os.makedirs(CREDENTIALS_PATH, exist_ok=True)
    
    # Ensure customer_photos subdirectory exists
    customer_photos_dir = os.path.join(UPLOADS_PATH, 'customer_photos')
    if not os.path.exists(customer_photos_dir):
        os.makedirs(customer_photos_dir, exist_ok=True)

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