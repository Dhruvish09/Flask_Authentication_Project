from flask import request, jsonify, url_for,render_template
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from sqlalchemy.exc import IntegrityError
from common.models.user import User,db,UserRole
from email_service.email_sender import MailProvider
from authentication_microservice.messages import SEND_MESSAGE, ACTIVE_MESSAGE
from authentication_microservice.utils import generate_otp, is_valid_email,is_valid_mobile,store_otp,get_otp,delete_otp,is_otp_expired,send_otp_via_sms,is_reset_token_expired,get_reset_token,generate_reset_token,store_reset_token,delete_reset_token,get_email_from_reset_token
from dotenv import load_dotenv
from config import Config
from common.logger_config import setup_logger
import os
from flask import current_app as app  # Importing current_app to access the application's context
from werkzeug.security import generate_password_hash
from flask_bcrypt import generate_password_hash
from .decorators import auth_role

logger = setup_logger()

load_dotenv()

def signup():
    required_fields = ['first_name', 'last_name', 'email', 'phone_number', 'password']
    # Get user details from request
    user_details = request.json
    # Check if any of the required fields are missing
    missing_fields = [field for field in required_fields if field not in user_details]
    if missing_fields:
        return jsonify({"error": f"The following fields are required: {', '.join(missing_fields)}"}), 400
    
    # Check if the email is in a valid format
    if not is_valid_email(user_details['email']):
        return jsonify({"error": "Invalid email address format."}), 400
    
    # Check if the mobile is in a valid format
    if not is_valid_mobile(user_details['phone_number']):
        return jsonify({"error": "Mobile number must start with '+91' followed by 10 digits."}), 400
    
    try:
        existing_user = User.query.filter_by(email=user_details['email']).first()
        if existing_user:
            return jsonify({"message": f"User already registered with this email address '{user_details['email']}'."}), 409
        if existing_user is None:
            # Create a new user
            new_user = User(
                first_name=user_details['first_name'],
                last_name=user_details['last_name'],
                email=user_details['email'],
                phone_number=user_details['phone_number']
            )
            new_user.set_password(user_details['password'])

            db.session.add(new_user)
            db.session.commit()

        if send_verification_code(user_details['email']):
            return jsonify({"message": SEND_MESSAGE.format(user_details['email'])}), 200
        else:
            return jsonify({"error": "Failed to send verification code."}), 400
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "User already exists."}), 409
    except Exception as e:
        db.session.rollback()
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def send_verification_code(email):
    otp_code = generate_otp()
    store_otp(email, otp_code)
    user_login = User.query.filter_by(email=email).first()

    if user_login:
        try:
            value_map = {
                "otp": otp_code
            }
            MailProvider.send_mail(subject="Verification OTP", receiver=[email], file_name="registration_otp", value_map=value_map)
            logger.info(f"verification code has been sent to {email}")
            db.session.commit()
            return True
        except ConnectionError as e:
            logger.error(f"Email sending failed: {e}")
        except IntegrityError as e:
            db.session.rollback()
            db.session.delete(user_login)
            db.session.commit()
            logger.error(f"Email sending failed: {e}")
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
    else:
        logger.info("User not found for the provided email.")
        return jsonify({"error": "Failed to send verification code."}), 400

def email_otp_verify():
    email = request.json.get("email")
    verification_code = request.json.get('verification_code')

    if not verification_code:
        return jsonify({"error": "Invalid verification code."}), 400

    try:
        user = User.query.filter_by(email=email).first()
        stored_otp = get_otp(email)
        if not stored_otp:
            return jsonify({"error": "No active OTP found for this email address."}), 404

        if is_otp_expired(email):
            return jsonify({"error": "OTP has expired."}), 410

         # Verify OTP
        otp = stored_otp.decode()
        if otp == verification_code:
            user.mark_email_verified()
            delete_otp(email)  # Remove verified OTP
            logger.info(ACTIVE_MESSAGE)
            return jsonify({"message": "User verified successfully."})
        else:
            return jsonify({"error": "Incorrect verification code."}), 403

    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500
    
def signin_with_otp():
    phone_number = request.json.get('phone_number')
    if not phone_number:
        return jsonify({"error": "Phone number is required."}), 400

    user = User.query.filter_by(phone_number=phone_number).first()
    otp = generate_otp()
    store_otp(user.email, otp)

    db.session.commit()
    send_otp_via_sms(phone_number, otp)
    return jsonify({"message": "OTP has been sent to your phone number."}), 200

def mobile_otp_verify():
    phone_number = request.json.get('phone_number')
    otp_entered = request.json.get('otp')
    if not phone_number or not otp_entered:
        return jsonify({"error": "Phone number and OTP are required."}), 400

    user = User.query.filter_by(phone_number=phone_number).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    stored_otp = get_otp(user.email)
    if stored_otp is None:
        return jsonify({"error": "OTP not generated for this phone number."}), 400

    otp = stored_otp.decode()
    if otp_entered == otp:
        delete_otp(user.email)
        db.session.commit()
        access_token = create_access_token(identity=user.id)
        return jsonify({"message": "User authenticated successfully.", 
                        "access_token": access_token,
                        "phone_number": phone_number,"profile_name": f"{user.first_name} {user.last_name}"}), 200
    else:
        return jsonify({"error": "Invalid OTP."}), 401

def set_password():
    email = request.json.get('email')
    passwd = request.json.get('password')
    confirm_passwd = request.json.get('confirm_password')

    try:
        user_id = User.query.filter_by(email=email).first()
        if passwd != confirm_passwd:
            return jsonify({"message": "Passwords do not match or are missing."}), 400
        user_id.password = passwd
        db.session.commit()
        logger.info("Password set for given user")
        return jsonify({"message": "Password set for given user"}), 200
    except Exception as e:
        db.session.rollback()
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def signin_email_password():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            logger.info(f"Email and/or password are missing.")
            return jsonify({"error": "Email and/or password are missing."}), 400

        user = User.query.filter_by(email=email).first()

        if not user:
            logger.info(f"No account found for '{email}'.")
            return jsonify({"error": f"No account found for '{email}'."}), 404

        # Verify the password
        if user.email_verified is True and user.check_password(password):
            access_token = create_access_token(identity=user.id)
            user.access_token = access_token
            user.email = email
            db.session.commit()

            logger.info(f"{user.first_name} has logged in successfully")
            return jsonify({
                "message": "User has logged in successfully.",
                "access_token": access_token,
                "email": email,
                "profile_name": f"{user.first_name} {user.last_name}"
            }), 200
        else:
            logger.error(f"Invalid password for user '{email}'.")
            return jsonify({"error": "Invalid email or password."}), 401

    except Exception as e:
        logger.error(f"An error occurred during login: {str(e)}")
        return jsonify({"error": "An unexpected error occurred."}), 500

@jwt_required()
def update_contact_info():
    try:
        user_id = get_jwt_identity()
        if not user_id:
            return jsonify({"message": "Token is expired. Please log in again."}), 400

        user = User.query.get(user_id)
        if not user:
            return jsonify({"status_code": 404, "error": "User not found."}), 404

        # Extract user data from request body
        user_data = request.json
        if not user_data:
            return jsonify({"error": "No data provided."}), 400

        # Update user information
        user.first_name = user_data.get('first_name', user.first_name)
        user.last_name = user_data.get('last_name', user.last_name)
        user.phone_number = user_data.get('phone_number', user.phone_number)
        
        # If password is provided, hash it and update the password
        new_password = user_data.get('password')
        if new_password:
            user.set_password(new_password)

        db.session.commit()

        logger.info(f"Successfully updated user information for user_id: {user_id}")
        return jsonify({"message": "Contact information updated successfully!"}), 200
    except IntegrityError as e:
        db.session.rollback()
        logger.error(str(e))
        return jsonify({"error": "Integrity error: Duplicate entry or invalid data"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def forgot_password():
    try:
        email = request.json.get('email')

        if not email:
            return jsonify({"error": "Email address is missing."}), 400

        user_login = User.query.filter_by(email=email).first()

        if user_login:
            reset_token = generate_reset_token()
            store_reset_token(email, reset_token)
            try:
                # Construct reset link URL
                reset_link_with_prefix = url_for('auth.render_reset_password_template', token=reset_token, _external=True)
                reset_link = reset_link_with_prefix.replace(f'{request.host_url}', '')
                reset_link_ab = reset_link.replace(f'forgot_password', 'forgot-password')  # Remove the dynamic part
                # reset_link = f'http://127.0.0.1:5000/{reset_link_ab}'
                # email_subject = "Password Reset Link"
                reset_link = f"{Config.APP_URL}:5000/{reset_link_ab}"
                email_subject = "Password Reset Link"
                
                value_map = {
                    "reset_password_link": reset_link,
                    "email": email
                }

                MailProvider.send_mail(subject=email_subject, receiver=[email], file_name="forgot_password", value_map=value_map)

                logger.info(f"Password reset link has been sent to {email}")

                return jsonify({"message": "Password reset link sent successfully.","reset_token":reset_token}), 200

            except ConnectionError as e:
                logger.error(f"Email sending failed: {e}")
                return jsonify({"error": "Failed to send reset link. Please try again."}), 500

            except Exception as e:
                logger.error(f"Error: {e}")
                return jsonify({"error": "Failed to send reset link. Please try again."}), 500

        else:
            return jsonify({"error": "User not found for the provided email."}), 404

    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def reset_password():
    try:
        email = request.json.get('email')
        # email = base64.b64decode(email_id).decode('utf-8')
        new_password = request.json.get('new_password')
        confirm_password = request.json.get('confirm_password')
        user_entered_token = request.json.get('reset_token')


        if not email or not new_password or not confirm_password or not user_entered_token:
            return jsonify({"error": "Email, new password, and confirm password  and user_entered_token are required."}), 400

        # Validate the email format
        if not is_valid_email(email):
            return jsonify({"error": "Invalid email address format."}), 400

        # Check if new password and confirm password match
        if new_password != confirm_password:
            return jsonify({"error": "New password and confirm password do not match."}), 400

        # Check if the user exists
        user_login = User.query.filter_by(email=email).first()
        if not user_login:
            return jsonify({"error": "User not found for the provided email."}), 404


        # Check if the provided reset token is valid
        stored_token = get_reset_token(email)
        stored_token_str = stored_token.decode('utf-8') if stored_token else None

        if not stored_token_str or stored_token_str != user_entered_token or is_reset_token_expired(email):
            return jsonify({"error": "Invalid or expired reset token."}), 400
        
        # Update the user's password
        user_login.set_password(new_password)
        db.session.commit()

        # Delete the reset token from Redis to invalidate it
        delete_reset_token(email)
        
        # Send success email
        # MailProvider.send_mail(subject="Password Reset Confirmation", receiver=[email], file_name="confirmation", value_map={"email": email})
        logger.info(f"Password reset successfully.")

        return jsonify({"message": "Password reset successfully."}), 200

    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def render_reset_password_template(token):
    email = get_email_from_reset_token(token)
    if email:
        return render_template('reset_password.html',email=email,token=token)
    else:
        return render_template('reset_password_expired.html')

def reset_password_template():
    try:
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        user_entered_token = request.form.get('reset_token')

        if not email or not new_password or not confirm_password or not user_entered_token:
            error_message = "Email, new password, confirm password, and reset token are required."
            return render_template("reset_password_expired.html", error=error_message)

        if not is_valid_email(email):
            error_message = "Invalid email address format."
            return render_template("reset_password_expired.html", error=error_message)

        if new_password != confirm_password:
            error_message = "New password and confirm password do not match."
            return render_template("reset_password_expired.html", error=error_message)

        user_login = User.query.filter_by(email=email).first()
        if not user_login:
            error_message = "User not found for the provided email."
            return render_template("reset_password_expired.html", error=error_message)

        stored_token_str = get_reset_token(email)
        stored_token = stored_token_str.decode('utf-8') if stored_token_str else None
        if not stored_token or stored_token != user_entered_token or is_reset_token_expired(email):
            error_message = "Invalid or expired reset token."
            return render_template("reset_password_expired.html", error=error_message)

        user_login.password = generate_password_hash(new_password).decode('utf-8')
        db.session.commit()

        # Send success email
        # MailProvider.send_mail(subject="Password Reset Confirmation", receiver=[email], file_name="confirmation", value_map={"email": email})
        logger.info(f"Password reset successfully.")

        delete_reset_token(email)

        # Render success template
        return render_template("confirmation.html",email=email)

    except Exception as e:
        return render_template("reset_password_expired.html",error=e)
    
# @auth_role('admin')
@jwt_required()
def get_contact_info():
    try:
        user_id = get_jwt_identity()
        if not user_id:
            return jsonify({"message": "Token is expired. Please log in again."}), 400
        
        print("user_id:",user_id)
        existing_user_info = User.query.all()

        if not existing_user_info:
            return jsonify({"status_code": 404, "error": "No users found."}), 404

        users = []
        for user in existing_user_info:
            user_data = {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "phone_number": user.phone_number,
                "email": user.email,
                "email_verified": user.email_verified,
            }
            users.append(user_data)

        return jsonify({"Users": users}), 200

    except Exception as e:
        logger.error(str(e))
        return jsonify({"error": str(e)}), 500

def create_user_role():
    try:
        data = request.json
        if 'user_id' not in data or 'role_id' not in data:
            return jsonify({'error': 'Missing user_id or role_id in request data'}), 400

        # Check if the user role already exists
        existing_user_role = UserRole.query.filter_by(user_id=data['user_id'], role_id=data['role_id']).first()
        if existing_user_role:
            return jsonify({'message': 'User role already exists'}), 409  # Conflict status code

        new_user_role = UserRole(user_id=data['user_id'], role_id=data['role_id'])
        db.session.add(new_user_role)
        db.session.commit()

        return jsonify({'message': 'User role created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500