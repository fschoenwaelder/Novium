import datetime
import os
from enum import Enum

class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

class Logger:
    # Set color codes for console output
    COLORS = {
        LogLevel.DEBUG: "\033[94m",    # blue
        LogLevel.INFO: "\033[92m",     # green
        LogLevel.WARNING: "\033[93m",  # yellow
        LogLevel.ERROR: "\033[91m",    # red
        "RESET": "\033[0m"             # clear color
    }

    def __init__(self, log_file_path: str, logger_name: str = "LOGGER"):

        if log_file_path.startswith("~"):
            log_file_path = os.path.expanduser(log_file_path)

        if "$" in log_file_path:
            log_file_path = os.path.expandvars(log_file_path)

        self.log_file_path = log_file_path
        self.logger_name = logger_name
        
        try:
            os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)
        except IOError as e:
            print(f"FATAL: Failed to create log file at {self.log_file_path}: {e}")
            
    def _log(self, level: LogLevel, message: str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{level.value}] [{self.logger_name}]"

        # set output with color
        color = self.COLORS.get(level, self.COLORS["RESET"])

        console_prefix = f"{color}{formatted_message}{self.COLORS['RESET']}"
        message = f"[{timestamp}] {console_prefix} {message}"

        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as log_file:
                print(message)
                log_file.write(message)
        except IOError as e:
            print(f"{self.COLORS[LogLevel.ERROR]}[{timestamp}] [{LogLevel.ERROR}] [{self.logger_name}] Write to log file failed: {e}{self.COLORS['RESET']}")

    def info(self, message: str):
        self._log(LogLevel.INFO, message)

    def warning(self, message: str):
        self._log(LogLevel.WARNING, message)

    def error(self, message: str, exception: Exception = None):
        if exception:
            message += f" | Exception: {str(exception)}"
        self._log(LogLevel.ERROR, message)

    def debug(self, message: str):
        self._log(LogLevel.DEBUG, message)