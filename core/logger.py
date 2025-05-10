"""
Logging configuration for the ransomware detection tool.

Performance:
    - Memory Usage: O(1) - Only configures logging, no persistent storage
    - Runtime Complexity: O(1) - Constant-time logging operations
    - I/O Complexity: Low - Only writes to log file when events occur
"""
import logging
from config import LOG_FILE, LOG_LEVEL

class StartupInfoFilter(logging.Filter):
    """
    Custom filter that allows only specific startup INFO logs, plus all WARNING and above.
    """
    def __init__(self):
        super().__init__()
        self.allowed_startup_messages = [
            "RansomwareEventHandler initialized.",
            "Starting live monitor on directory:"
        ]
        self.startup_messages_seen = set()
    
    def filter(self, record):
        # Allow all WARNING and above messages
        if record.levelno >= logging.WARNING:
            return True
            
        # For INFO messages, only allow specific startup messages
        if record.levelno == logging.INFO:
            for startup_msg in self.allowed_startup_messages:
                if startup_msg in record.getMessage() and startup_msg not in self.startup_messages_seen:
                    self.startup_messages_seen.add(startup_msg)
                    return True
        
        # Reject all other INFO messages
        return False

# Create and configure logger
logger = logging.getLogger("RansomwareMonitor")
logger.setLevel(LOG_LEVEL)

# File handler for logging to a file with custom filter
file_handler = logging.FileHandler(LOG_FILE, mode='a')
startup_filter = StartupInfoFilter()
file_handler.addFilter(startup_filter)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Console handler for logging to terminal - will show all levels based on LOG_LEVEL
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)
