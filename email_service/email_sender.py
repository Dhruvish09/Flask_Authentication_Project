from flask_mail import Message, Mail
import pathlib
import jinja2
from email_service import utils
from config import EmailConfig
import multiprocessing
from flask import url_for
from common.logger_config import setup_logger

logger = setup_logger()

mail = Mail()
class MailProvider:
    def __init__(self):
        if EmailConfig and EmailConfig.MAIL_PASSWORD and EmailConfig.MAIL_SERVER:
            logger.info('Initialized the Simple Mail Provider')
        else:
            logger.info('Please configure the mandatory environment variables')

    @staticmethod
    def configure_mail(app):
        mail.init_app(app)

    @staticmethod
    def send_mail(
            subject: str,
            receiver: list,
            value_map: dict = None,
            attachment_param: dict = None,
            html_body: str = None,
            file_name=None,
            body: str = "For legacy purposes only. If you see this - something went wrong.",
            cc_addresses: str = None,
            bcc_addresses: str = None):


        absolute_path = pathlib.Path(__file__).parent.absolute()
        template_path = str(absolute_path) + "/templates"

        template_loader = jinja2.FileSystemLoader(searchpath=template_path)
        jinja_env = jinja2.Environment(loader=template_loader, autoescape=True)
        email_type = utils.TEMPLATE_MAP.get(f'{file_name}')
        msg = Message(
            subject,
            sender=EmailConfig.MAIL_USERNAME
        )
        msg.recipients = receiver
        msg.body = body if body else False

        msg.cc = cc_addresses if cc_addresses else False
        msg.bcc = bcc_addresses if bcc_addresses else False
        template = jinja_env.get_template(email_type)
        if value_map:
            email_body = template.render(**value_map)
            msg.html = email_body
        if attachment_param and file_name:
            msg.attach(filename=file_name)

        if html_body is not None:
            msg.attach(content_type=html_body)

        processes = []
        for recipient in receiver:
            p = multiprocessing.Process(target=mail.send(msg),
                                        args=(recipient, subject, body, cc_addresses, bcc_addresses, attachment_param,
                                              html_body))
            processes.append(p)
            p.start()

        # Wait for all processes to finish
        for p in processes:
            p.join()
