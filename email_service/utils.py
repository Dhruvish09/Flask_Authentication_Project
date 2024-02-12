TEMPLATE_MAP = {
    'registration_otp': 'registration_otp.html',
    'forgot_password': 'forgot_password.html',
    'reset_password': 'reset_password.html',
    'confirmation': 'confirmation.html',
    'quality_gate_email_notification': 'quality_gate_email_notification.html',
}

SUBJECT_MAP = {
    'registration_otp': 'Verification OTP',
    'forgot_password': 'Forgot Password',
    'reset_password': 'Password Reset Link',
    'confirmation': 'Confirmation Mail',
    'quality_gate_email_notification': 'Quality Gate Notification',
}


def get_subject_by_type(email_type: str):
    if email_type not in SUBJECT_MAP:
        print(f'Invalid email type is found : {email_type}')
    subject = SUBJECT_MAP.get(email_type)
    return subject


def get_template_path(request_type: str):
    if request_type not in TEMPLATE_MAP:
        print(f'No Templated is found for type : {request_type}')
    template_path = TEMPLATE_MAP.get(request_type)
    return template_path
