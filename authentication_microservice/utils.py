import re
import random
from email_service.email_sender import MailProvider
import redis
from datetime import datetime, timedelta
from twilio.rest import Client
import secrets
import re
from config import TwilioConfig

from common.logger_config import setup_logger

logger = setup_logger()

# Configure Twilio credentials
TWILIO_ACCOUNT_SID = TwilioConfig.TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN = TwilioConfig.TWILIO_AUTH_TOKEN
TWILIO_PHONE_NUMBER = TwilioConfig.TWILIO_PHONE_NUMBER

# Initialize Twilio client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def generate_otp():
    return str(random.randint(100000, 999999))


def is_valid_email(email):
    pattern = r'^[\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    
def is_valid_mobile(mobile):
    pattern = r'^\+91[0-9]{10}$'

    # Check if the provided mobile number matches the pattern
    if re.match(pattern, mobile):
        return True
    else:
        return False

# Initialize Redis connection
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

def store_otp(email, otp):
    expiration_time = datetime.utcnow() + timedelta(minutes=5)
    redis_client.set(email, otp, ex=int((expiration_time - datetime.utcnow()).total_seconds()))

def get_otp(email):
    return redis_client.get(email)

def delete_otp(email):
    redis_client.delete(email)

def is_otp_expired(email):
    """Check if OTP associated with the email is expired (more than 5 minutes old)"""
    stored_otp = redis_client.get(email)
    if not stored_otp:
        return True  # No active OTP found for the email

    # Calculate expiration time
    expiration_seconds = redis_client.ttl(email)
    expiration_time = datetime.utcnow() + timedelta(seconds=expiration_seconds)

    # Check if expiration time is in the past (OTP is expired)
    return expiration_time < datetime.utcnow()

def send_otp_via_sms(phone_number, otp):
    try:
        message = client.messages.create(
            body=f"Your OTP for login is: {otp}",
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"OTP has been sent to {phone_number} via SMS.")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP to {phone_number} via SMS: {e}")
        return False


def generate_reset_token():
    return secrets.token_urlsafe(16)  # Generate a unique reset token

def store_reset_token(email, reset_token, expiration_minutes=5):
    expiration_time_seconds = expiration_minutes * 60  # Convert minutes to seconds
    redis_client.set(email, reset_token, ex=expiration_time_seconds)
    redis_client.set(reset_token,email, ex=expiration_time_seconds)

def get_reset_token(email):
    return redis_client.get(email)

def get_email(token):
    return redis_client.get(token)

def delete_reset_token(email):
    redis_client.delete(email)

def delete_email(token):
    redis_client.delete(token)

def is_reset_token_expired(email):
    """Check if the reset token associated with the email is expired"""
    stored_token = redis_client.get(email)
    if not stored_token:
        return True

    # Retrieve the expiration time of the token
    expiration_time = redis_client.ttl(email)

    # Check if the expiration time is in the past
    return expiration_time <= 0

def get_email_from_reset_token(token):
    try:
        email = get_email(token)
        if email:
            return email.decode('utf-8')
        else:
            return None
    except Exception as e:
        logger.error(f"Error getting email from reset token: {e}")
        return None
    
    