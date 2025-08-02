#!/usr/bin/env python3
"""
Database Initialization Script
Ensures all databases and tables are properly created before application startup.
This is crucial for Railway deployment where databases might not exist initially.
"""

import os
import sqlite3
import logging
from config import DATABASE_NAME, SCHEDULED_MESSAGES_DB, ensure_database_directories

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_main_database():
    """Initialize the main radiance_md.db database"""
    try:
        logger.info(f"🔧 Initializing main database: {DATABASE_NAME}")
        
        # Import and initialize DatabaseService to create all tables
        from database_service import DatabaseService
        
        # This will create all tables and initialize default data
        db_service = DatabaseService()
        logger.info("✅ Main database initialized successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error initializing main database: {str(e)}")
        return False

def init_scheduled_messages_database():
    """Initialize the scheduled_messages.db database"""
    try:
        logger.info(f"🔧 Initializing scheduled messages database: {SCHEDULED_MESSAGES_DB}")
        
        conn = sqlite3.connect(SCHEDULED_MESSAGES_DB)
        cursor = conn.cursor()
        
        # Create table for scheduled messages tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                appointment_id TEXT NOT NULL,
                customer_name TEXT NOT NULL,
                customer_phone TEXT NOT NULL,
                message_type TEXT NOT NULL,
                scheduled_time TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                message_content TEXT,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                error_message TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("✅ Scheduled messages database initialized successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error initializing scheduled messages database: {str(e)}")
        return False

def main():
    """Initialize all databases"""
    logger.info("🚀 Starting database initialization...")
    
    # Ensure database directories exist
    ensure_database_directories()
    
    # Initialize main database
    main_db_success = init_main_database()
    
    # Initialize scheduled messages database
    scheduled_db_success = init_scheduled_messages_database()
    
    if main_db_success and scheduled_db_success:
        logger.info("✅ All databases initialized successfully!")
        return True
    else:
        logger.error("❌ Database initialization failed!")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 