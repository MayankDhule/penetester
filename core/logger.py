"""
Logging configuration for Pentestrr
"""
import logging
import sys
from colorama import Fore, Style, init

# Ensure stdout/stderr can carry Unicode (emoji, box-drawing) on Windows
# consoles, which default to cp1252 and would otherwise raise
# UnicodeEncodeError on every emoji log line. errors='replace' is a safety
# net so output degrades gracefully instead of crashing the handler.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, ValueError):
        # Stream doesn't support reconfigure (e.g. already wrapped/redirected)
        pass

# Initialize colorama after the streams are reconfigured so its wrapper sits
# on top of the UTF-8 stream.
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""

    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logger(name='Pentestrr', verbose=False):
    """Setup and return logger"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid stacking duplicate handlers if called more than once
    if logger.handlers:
        logger.handlers.clear()
    logger.propagate = False

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Format
    formatter = ColoredFormatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    return logger
