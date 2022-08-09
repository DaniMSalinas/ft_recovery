"""Logger class for the project"""
import logging

class RecoveryLogger():
    """Class to handle the logger of the project"""
    def __init__(self):
        self.logger = logging.getLogger("ft_stockholm_logger")
        self.log_console_format = "%(asctime)s [%(levelname)s]: %(message)s"
        self.set_console_handler()

    def set_console_handler(self):
        """function to set console handler"""
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(self.log_console_format))
        self.logger.addHandler(console_handler)

    def set_log_level(self, level):
        """function to set the log level"""
        self.logger.setLevel(level)
