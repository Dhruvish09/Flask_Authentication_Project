from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from common.db import db
from config import Config,EmailConfig
from email_service.email_sender import MailProvider
from authentication_microservice.routes import auth_bp
import secrets

# Generate a random secret key using os.urandom
SECRET_KEY = secrets.token_hex(24)

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object(Config)
    app.config.from_object(EmailConfig)

    # CORS Configuration
    CORS(app, resources={r"/*": {"origins": "*"}})

    # Initialize Database
    db.init_app(app)
    with app.app_context():
        db.create_all()
    Migrate(app, db)

    # JWT Configuration
    jwt = JWTManager(app)

    # Mail Provider Configuration
    MailProvider.configure_mail(app)

    # Register Blueprints
    app.register_blueprint(auth_bp, url_prefix='/auth')

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', debug=False)
