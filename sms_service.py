import requests
import os
import logging
from datetime import datetime
from database_service import DatabaseService
from config import BUSINESS_FULL_NAME

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SMSService:
    def __init__(self, database_service=None):
        self.api_key = os.getenv('API_KEY')
        self.base_url = 'https://api.telnyx.com/v2/messages'
        self.db = database_service or DatabaseService()
        
    def send_sms(self, to_number, from_number, message):
        """Send SMS using Telnyx API"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'from': from_number,
                'to': to_number,
                'text': message
            }
            
            logger.info(f"📱 Sending SMS from {from_number} to {to_number}: {message}")
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                logger.info(f"✅ SMS sent successfully to {to_number}")
                return True
            else:
                # Reduced logging to prevent terminal flooding
                logger.warning(f"⚠️ SMS failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error in send_sms: {str(e)}")
            return False
    
    def send_missed_call_sms(self, caller_number, spa_number):
        """Send a missed call SMS notification"""
        try:
            # Get template from database
            template = self.db.get_message_template('missed_call_notification')
            if not template or not template.get('is_enabled', True):
                logger.info("Missed call notification template disabled or not found, skipping")
                return False
            
            message = template['message_content']
            
            logger.info(f"📞➡️📱 Sending missed call SMS to {caller_number}")
            
            return self.send_sms(
                to_number=caller_number,
                from_number=spa_number,
                message=message
            )
        except Exception as e:
            logger.error(f"❌ Error sending missed call SMS: {str(e)}")
            return False
    
    def send_business_hours_sms(self, caller_number, spa_number):
        """Send business hours information SMS"""
        message = f"Thanks for calling {BUSINESS_FULL_NAME}! We're currently with other clients. Our hours: Mon-Fri 9am-6pm, Sat 9am-6pm appointment only. How can I help?"
        
        logger.info(f"🏢📱 Sending business hours SMS to {caller_number}")
        
        return self.send_sms(
            to_number=caller_number,
            from_number=spa_number,
            message=message
        )