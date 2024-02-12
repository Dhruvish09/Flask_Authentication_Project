import logging
from colorlog import ColoredFormatter

def setup_logger():
    logger = logging.getLogger(__name__)

    # Check if the logger already has handlers to prevent duplication
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)

        formatter = ColoredFormatter(
            "%(log_color)s%(levelname)-8s%(reset)s %(blue)s[%(asctime)s]%(reset)s %(yellow)s%(filename)s:%(lineno)d%(reset)s - %(log_color)s%(message)s%(reset)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors={
                'DEBUG': 'cyan',
                'INFO': 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'red,bg_white',
            }
        )

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        # Clear existing handlers to avoid duplication
        logger.handlers.clear()

        logger.addHandler(console_handler)

    return logger
