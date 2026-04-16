"""
Logger - Structured logging utility
"""

import logging
import sys
import json
from typing import Optional, Dict, Any
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_data.update(record.extra)
        
        return json.dumps(log_data)


class WazuhLogger:
    """Structured logger for Wazuh Configurator"""
    
    def __init__(self, name: str = "wazuh_configurator", level: int = logging.INFO, use_json: bool = False):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.use_json = use_json
        
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(level)
            
            if use_json:
                formatter = JSONFormatter()
            else:
                formatter = logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log info message"""
        if extra:
            self.logger.info(message, extra={'extra': extra})
        else:
            self.logger.info(message)
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log warning message"""
        if extra:
            self.logger.warning(message, extra={'extra': extra})
        else:
            self.logger.warning(message)
    
    def error(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log error message"""
        if extra:
            self.logger.error(message, extra={'extra': extra})
        else:
            self.logger.error(message)
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None):
        """Log debug message"""
        if extra:
            self.logger.debug(message, extra={'extra': extra})
        else:
            self.logger.debug(message)
    
    def set_level(self, level: int):
        """Set logging level"""
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)
