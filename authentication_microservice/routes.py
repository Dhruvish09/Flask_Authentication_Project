from flask import Blueprint
from authentication_microservice import auth

# Create a blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# --- Authentication Routes ---
# User signup
auth_bp.add_url_rule('/signup', 'auth_signup',
                     auth.signup, methods=['POST'])

# Send verification code for signup
auth_bp.add_url_rule('/signup/send_verification_code', 'send_code',
                     auth.send_verification_code, methods=['POST'])

# Verify email OTP during signup
auth_bp.add_url_rule('/signup/email_otp_verify', 'email_otp_verify',
                     auth.email_otp_verify, methods=['POST'])

# Sign in with email and password
auth_bp.add_url_rule('/signin_email_password', 'signin_email_password',
                     auth.signin_email_password, methods=['POST'])

# Sign in with OTP
auth_bp.add_url_rule('/signin_with_otp', 'signin_with_otp',
                     auth.signin_with_otp, methods=['POST'])

# Verify mobile OTP
auth_bp.add_url_rule('/mobile_otp_verify', 'mobile_otp_verify',
                     auth.mobile_otp_verify, methods=['POST'])

# Forgot password
auth_bp.add_url_rule('/forgot_password', 'forgot_password',
                     auth.forgot_password, methods=['POST'])

# Reset password
auth_bp.add_url_rule('/reset_password', 'reset_password',
                     auth.reset_password, methods=['POST'])

# Render reset password template
auth_bp.add_url_rule('/render_reset_password_template/<token>', 'render_reset_password_template',
                     auth.render_reset_password_template, methods=['GET'])

# Reset password template
auth_bp.add_url_rule('/reset_password_template', 'reset_password_template',
                     auth.reset_password_template, methods=['POST'])

# --- User Routes ---
# Update user contact information
auth_bp.add_url_rule('/user/update_contact_info', 'update_user_contact_info',
                     auth.update_contact_info, methods=["POST"])

# Get user contact information
auth_bp.add_url_rule('/user/get_contact_info', 'get_contact_info',
                     auth.get_contact_info, methods=["GET"])

# Create user role
auth_bp.add_url_rule('/user/create_user_role', 'create_user_role',
                     auth.create_user_role, methods=["POST"])
