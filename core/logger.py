"""
Logging configuration for PentestAI
"""
import logging
import sys
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
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

def setup_logger(name='PentestAI', verbose=False):
    """Setup and return logger"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
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
