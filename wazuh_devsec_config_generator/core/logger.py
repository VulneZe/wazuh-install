"""
Centralized logging system for Wazuh DevSec Generator
Clean, structured logging with multiple output formats
"""

import logging
import sys
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

from .constants import DEFAULT_CONFIG


class LogLevel(str, Enum):
    """Log levels with descriptions"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class WazuhLogger:
    """Centralized logger with structured output"""
    
    def __init__(self, name: str = "wazuh-devsec", level: str = DEFAULT_CONFIG["log_level"]):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup handlers
        self._setup_console_handler()
        self._setup_file_handler()
        
        # Component tracking
        self.component_stack = []
        
    def _setup_console_handler(self) -> None:
        """Setup console handler with clean formatting"""
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)
        
        # Clean formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def _setup_file_handler(self) -> None:
        """Setup file handler for detailed logging"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"wazuh-devsec-{datetime.now().strftime('%Y%m%d')}.log"
        
        handler = logging.FileHandler(log_file, encoding='utf-8')
        handler.setLevel(logging.DEBUG)
        
        # Detailed formatter for file
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        
        self.logger.addHandler(handler)
    
    def debug(self, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Log debug message"""
        self._log(logging.DEBUG, message, component, **kwargs)
    
    def info(self, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Log info message"""
        self._log(logging.INFO, message, component, **kwargs)
    
    def warning(self, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Log warning message"""
        self._log(logging.WARNING, message, component, **kwargs)
    
    def error(self, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Log error message"""
        self._log(logging.ERROR, message, component, **kwargs)
    
    def critical(self, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Log critical message"""
        self._log(logging.CRITICAL, message, component, **kwargs)
    
    def _log(self, level: int, message: str, component: Optional[str] = None, **kwargs) -> None:
        """Internal logging method with component tracking"""
        # Add component to message if provided
        if component:
            message = f"[{component}] {message}"
        
        # Add extra context
        extra = {}
        if kwargs:
            extra.update(kwargs)
        
        self.logger.log(level, message, extra=extra)
    
    def start_component(self, component: str) -> None:
        """Start tracking a component operation"""
        self.component_stack.append(component)
        self.info(f"Starting {component}", component=component)
    
    def end_component(self, component: str, success: bool = True) -> None:
        """End tracking a component operation"""
        if self.component_stack and self.component_stack[-1] == component:
            self.component_stack.pop()
        
        status = "completed" if success else "failed"
        self.info(f"{component} {status}", component=component)
    
    def log_operation(self, operation: str, details: Dict[str, Any]) -> None:
        """Log operation with structured details"""
        detail_str = ", ".join(f"{k}={v}" for k, v in details.items())
        self.info(f"{operation}: {detail_str}")
    
    def log_error_with_context(self, error: Exception, context: str) -> None:
        """Log error with full context"""
        self.error(f"{context}: {type(error).__name__}: {error}", component=context)
    
    def log_validation_result(self, component: str, passed: int, total: int, issues: list) -> None:
        """Log validation results"""
        if passed == total:
            self.info(f"{component} validation passed: {passed}/{total}", component=component)
        else:
            self.warning(f"{component} validation issues: {total-passed}/{total} failed", component=component)
            for issue in issues[:3]:  # Show first 3 issues
                self.warning(f"  - {issue}", component=component)
    
    def log_file_operation(self, operation: str, file_path: Path, success: bool = True) -> None:
        """Log file operation"""
        status = "✅" if success else "❌"
        rel_path = file_path.name  # Show only filename for cleaner output
        self.info(f"{status} {operation}: {rel_path}")
    
    def log_progress(self, current: int, total: int, operation: str) -> None:
        """Log progress information"""
        percentage = (current / total) * 100 if total > 0 else 0
        self.info(f"{operation}: {current}/{total} ({percentage:.1f}%)")
    
    def log_summary(self, title: str, metrics: Dict[str, Any]) -> None:
        """Log summary information"""
        self.info(f"=== {title} ===")
        for key, value in metrics.items():
            self.info(f"  {key}: {value}")
    
    def set_level(self, level: str) -> None:
        """Change logging level"""
        self.logger.setLevel(getattr(logging, level.upper()))
        for handler in self.logger.handlers:
            handler.setLevel(getattr(logging, level.upper()))


# Global logger instance
_logger_instance = None


def get_logger(name: Optional[str] = None) -> WazuhLogger:
    """Get or create logger instance"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = WazuhLogger(name or "wazuh-devsec")
    return _logger_instance


def setup_logging(level: str = DEFAULT_CONFIG["log_level"]) -> WazuhLogger:
    """Setup logging system"""
    global _logger_instance
    _logger_instance = WazuhLogger("wazuh-devsec", level)
    return _logger_instance
