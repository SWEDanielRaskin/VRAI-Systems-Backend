# payment_service.py
import os
import stripe
import logging
import json
from datetime import datetime, timedelta
import uuid

logger = logging.getLogger(__name__)

class PaymentService:
    """Service for handling show-up deposits via Stripe API"""
    
    def __init__(self):
        # Stripe configuration
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
        self.publishable_key = os.getenv('STRIPE_PUBLISHABLE_KEY')
        self.environment = os.getenv('STRIPE_ENVIRONMENT', 'test')  # 'test' or 'live'
        
        # Webhook endpoint secret for verifying Stripe webhooks
        self.webhook_secret = os.getenv('STRIPE_WEBHOOK_SECRET')
        
        # Default deposit amount (in cents)
        self.default_deposit_amount = 5000  # $50.00
        
        # Store payment records locally for tracking
        self.payments_file = 'payments.json'
        
        # Success URL after payment completion
        self.success_url = os.getenv('STRIPE_SUCCESS_URL', 'https://omorfiamedspa.com/deposit-confirmation')
        self.cancel_url = os.getenv('STRIPE_CANCEL_URL', 'https://omorfiamedspa.com/deposit-cancelled')
    
    def create_deposit_payment_link(self, appointment_data):
        """
        Create a Stripe payment link for show-up deposit
        
        Args:
            appointment_data: Dict with appointment details
            
        Returns:
            Dict with payment link and tracking info
        """
        try:
            # Calculate deposit amount (could vary by service in future)
            deposit_amount = self.get_deposit_amount(appointment_data.get('service'))
            
            # Create a product for this deposit
            product = stripe.Product.create(
                name=f"Show-up Deposit - {appointment_data.get('service_name', 'Appointment')}",
                description=f"Deposit for {appointment_data.get('name')} - {appointment_data.get('date')} {appointment_data.get('time')}",
                metadata={
                    'appointment_id': appointment_data.get('id'),
                    'customer_name': appointment_data.get('name'),
                    'customer_phone': appointment_data.get('phone'),
                    'appointment_date': appointment_data.get('date'),
                    'appointment_time': appointment_data.get('time'),
                    'service': appointment_data.get('service')
                }
            )
            
            # Create a price for this product
            price = stripe.Price.create(
                product=product.id,
                unit_amount=deposit_amount,
                currency='usd',
                metadata={
                    'appointment_id': appointment_data.get('id')
                }
            )
            
            # Create payment link
            payment_link = stripe.PaymentLink.create(
                line_items=[{
                    'price': price.id,
                    'quantity': 1,
                }],
                after_completion={
                    'type': 'redirect',
                    'redirect': {
                        'url': self.success_url
                    }
                },
                automatic_tax={'enabled': False},
                billing_address_collection='required',
                phone_number_collection={'enabled': True},
                customer_creation='always',
                metadata={
                    'appointment_id': appointment_data.get('id'),
                    'customer_name': appointment_data.get('name'),
                    'customer_phone': appointment_data.get('phone'),
                    'type': 'show_up_deposit'
                }
            )
            
            # Store payment record for tracking
            payment_record = {
                'payment_link_id': payment_link.id,
                'product_id': product.id,
                'price_id': price.id,
                'appointment_id': appointment_data.get('id'),
                'customer_name': appointment_data.get('name'),
                'customer_phone': appointment_data.get('phone'),
                'amount': deposit_amount,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'appointment_date': appointment_data.get('date'),
                'appointment_time': appointment_data.get('time'),
                'service': appointment_data.get('service')
            }
            
            self.save_payment_record(payment_record)
            
            logger.info(f"✅ Stripe payment link created: {payment_link.url}")
            
            return {
                'success': True,
                'payment_url': payment_link.url,
                'payment_link_id': payment_link.id,
                'product_id': product.id,
                'price_id': price.id,
                'amount': deposit_amount / 100,  # Convert to dollars for display
                'record': payment_record
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"❌ Stripe API error: {str(e)}")
            return {
                'success': False,
                'error': f"Payment link creation failed: {str(e)}"
            }
        except Exception as e:
            logger.error(f"❌ Error creating payment link: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_deposit_amount(self, service):
        """
        Get deposit amount based on service type
        Future: Could vary by service
        """
        # Service-specific deposits (in cents)
        service_deposits = {
            'botox': 5000,           # $50
            'hydrafacial': 5000,     # $50
            'laser_hair_removal': 5000,  # $50
            'microneedling': 5000,   # $50
        }
        
        return service_deposits.get(service, self.default_deposit_amount)
    
    def check_payment_status(self, payment_link_id):
        """Check if payment has been completed"""
        try:
            # Get the payment link
            payment_link = stripe.PaymentLink.retrieve(payment_link_id)
            
            # Check if there are any successful payments for this link
            # We need to search for checkout sessions created from this payment link
            checkout_sessions = stripe.checkout.Session.list(
                payment_link=payment_link_id,
                limit=10
            )
            
            # Look for completed sessions
            for session in checkout_sessions.data:
                if session.payment_status == 'paid':
                    # Get the payment intent to get more details
                    payment_intent = stripe.PaymentIntent.retrieve(session.payment_intent)
                    
                    return {
                        'success': True,
                        'status': 'completed',
                        'session': session,
                        'payment_intent': payment_intent,
                        'amount_received': payment_intent.amount_received
                    }
            
            # No completed payments found
            return {
                'success': True,
                'status': 'pending',
                'payment_link': payment_link
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"❌ Error checking payment status: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def process_refund(self, payment_record, reason="Customer showed up"):
        """
        Process refund for show-up deposit
        
        Args:
            payment_record: Payment record from local storage
            reason: Reason for refund
            
        Returns:
            Dict with refund result
        """
        try:
            # First, check if payment was actually completed
            status_check = self.check_payment_status(payment_record['payment_link_id'])
            
            if not status_check['success'] or status_check['status'] != 'completed':
                return {
                    'success': False,
                    'error': 'Payment not completed, cannot refund'
                }
            
            payment_intent = status_check['payment_intent']
            amount_to_refund = payment_record['amount']
            
            # Create refund
            refund = stripe.Refund.create(
                payment_intent=payment_intent.id,
                amount=amount_to_refund,
                reason='requested_by_customer',
                metadata={
                    'reason': reason,
                    'appointment_id': payment_record['appointment_id'],
                    'customer_name': payment_record['customer_name']
                }
            )
            
            # Update payment record
            payment_record['status'] = 'refunded'
            payment_record['refund_id'] = refund.id
            payment_record['refunded_at'] = datetime.now().isoformat()
            payment_record['refund_reason'] = reason
            
            self.update_payment_record(payment_record)
            
            logger.info(f"✅ Refund processed: {refund.id} - ${amount_to_refund/100}")
            
            return {
                'success': True,
                'refund_id': refund.id,
                'amount_refunded': amount_to_refund / 100,
                'status': refund.status
            }
            
        except stripe.error.StripeError as e:
            logger.error(f"❌ Stripe refund error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"❌ Error processing refund: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def handle_webhook(self, payload, signature):
        """
        Handle Stripe webhook events
        
        Args:
            payload: Raw request body
            signature: Stripe signature header
            
        Returns:
            Dict with processing result
        """
        try:
            # Verify webhook signature
            event = stripe.Webhook.construct_event(
                payload, signature, self.webhook_secret
            )
            
            logger.info(f"🔔 Stripe webhook received: {event['type']}")
            
            # Handle specific event types
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                self._handle_payment_completed(session)
                
            elif event['type'] == 'payment_intent.succeeded':
                payment_intent = event['data']['object']
                self._handle_payment_succeeded(payment_intent)
                
            elif event['type'] == 'charge.dispute.created':
                dispute = event['data']['object']
                self._handle_dispute_created(dispute)
            
            return {'success': True, 'event_type': event['type']}
            
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"❌ Invalid webhook signature: {str(e)}")
            return {'success': False, 'error': 'Invalid signature'}
        except Exception as e:
            logger.error(f"❌ Webhook processing error: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _handle_payment_completed(self, session):
        """Handle successful payment completion"""
        try:
            appointment_id = session.get('metadata', {}).get('appointment_id')
            if appointment_id:
                # Update payment record status
                payment_record = self.get_payment_by_appointment(appointment_id)
                if payment_record:
                    payment_record['status'] = 'completed'
                    payment_record['completed_at'] = datetime.now().isoformat()
                    payment_record['session_id'] = session['id']
                    self.update_payment_record(payment_record)
                    
                    logger.info(f"💰 Payment completed for appointment {appointment_id}")
        except Exception as e:
            logger.error(f"❌ Error handling payment completion: {str(e)}")
    
    def _handle_payment_succeeded(self, payment_intent):
        """Handle payment intent success"""
        logger.info(f"💳 Payment succeeded: {payment_intent['id']}")
    
    def _handle_dispute_created(self, dispute):
        """Handle chargeback/dispute"""
        logger.warning(f"⚠️ Dispute created: {dispute['id']} - Amount: ${dispute['amount']/100}")
    
    def save_payment_record(self, payment_record):
        """Save payment record to local file"""
        try:
            # Load existing records
            records = []
            if os.path.exists(self.payments_file):
                with open(self.payments_file, 'r') as f:
                    records = json.load(f)
            
            # Add new record
            records.append(payment_record)
            
            # Save back to file
            with open(self.payments_file, 'w') as f:
                json.dump(records, f, indent=2)
            
            logger.info(f"💾 Payment record saved for {payment_record['customer_name']}")
            
        except Exception as e:
            logger.error(f"❌ Error saving payment record: {str(e)}")
    
    def update_payment_record(self, updated_record):
        """Update existing payment record"""
        try:
            records = []
            if os.path.exists(self.payments_file):
                with open(self.payments_file, 'r') as f:
                    records = json.load(f)
            
            # Find and update the record
            for i, record in enumerate(records):
                if record['payment_link_id'] == updated_record['payment_link_id']:
                    records[i] = updated_record
                    break
            
            # Save back to file
            with open(self.payments_file, 'w') as f:
                json.dump(records, f, indent=2)
            
            logger.info(f"💾 Payment record updated for {updated_record['customer_name']}")
            
        except Exception as e:
            logger.error(f"❌ Error updating payment record: {str(e)}")
    
    def get_payment_by_appointment(self, appointment_id):
        """Get payment record by appointment ID"""
        try:
            if not os.path.exists(self.payments_file):
                return None
            
            with open(self.payments_file, 'r') as f:
                records = json.load(f)
            
            for record in records:
                if record['appointment_id'] == appointment_id:
                    return record
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Error getting payment record: {str(e)}")
            return None
    
    def get_publishable_key(self):
        """Get publishable key for frontend"""
        return self.publishable_key