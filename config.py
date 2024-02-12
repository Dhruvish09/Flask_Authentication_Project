import os
from dotenv import load_dotenv
import secrets

# Generate a random secret key using os.urandom
SECRET_KEY = secrets.token_hex(24)

load_dotenv()

class Config:
    DATABASE_URI = os.getenv('DATABASE_URI')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    APP_URL = os.getenv('APP_URL')
    TEMPLATE_FOLDER = 'templates'
    JWT_ACCESS_TOKEN_EXPIRES = 3600
    JWT_SECRET_KEY = SECRET_KEY

class EmailConfig:
    # DEBUG = True
    MAIL_SERVER = os.getenv('MAIL_SERVER')
    MAIL_PORT = os.getenv('MAIL_PORT')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER')
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False

class TwilioConfig:
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')