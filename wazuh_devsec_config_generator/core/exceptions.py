"""
Custom exceptions for Wazuh DevSec Generator
Clean, structured exception handling with context
"""

from typing import Optional, Dict, Any, List
from pathlib import Path


class WazuhDevSecError(Exception):
    """Base exception for Wazuh DevSec Generator"""
    
    def __init__(self, message: str, component: Optional[str] = None, 
                 file_path: Optional[Path] = None, context: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.component = component
        self.file_path = file_path
        self.context = context or {}


class ConfigurationError(WazuhDevSecError):
    """Raised when configuration is invalid"""
    pass


class ValidationError(WazuhDevSecError):
    """Raised when validation fails"""
    
    def __init__(self, message: str, validation_results: Optional[List[str]] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.validation_results = validation_results or []


class FileNotFoundError(WazuhDevSecError):
    """Raised when required file is not found"""
    
    def __init__(self, file_path: Path, **kwargs):
        message = f"Required file not found: {file_path}"
        super().__init__(message, file_path=file_path, **kwargs)


class XMLParsingError(WazuhDevSecError):
    """Raised when XML parsing fails"""
    
    def __init__(self, file_path: Path, line_number: Optional[int] = None, **kwargs):
        message = f"XML parsing error in {file_path}"
        if line_number:
            message += f" at line {line_number}"
        super().__init__(message, file_path=file_path, **kwargs)
        self.line_number = line_number


class RuleGenerationError(WazuhDevSecError):
    """Raised when rule generation fails"""
    pass


class IntegrationError(WazuhDevSecError):
    """Raised when integration setup fails"""
    
    def __init__(self, integration_name: str, error_details: Optional[str] = None, **kwargs):
        message = f"Integration error: {integration_name}"
        if error_details:
            message += f" - {error_details}"
        super().__init__(message, component="integration", **kwargs)
        self.integration_name = integration_name
        self.error_details = error_details


class ServiceDetectionError(WazuhDevSecError):
    """Raised when service detection fails"""
    pass


class DashboardGenerationError(WazuhDevSecError):
    """Raised when dashboard generation fails"""
    pass


class TemplateError(WazuhDevSecError):
    """Raised when template rendering fails"""
    
    def __init__(self, template_name: str, error_details: Optional[str] = None, **kwargs):
        message = f"Template error: {template_name}"
        if error_details:
            message += f" - {error_details}"
        super().__init__(message, component="template", **kwargs)
        self.template_name = template_name
        self.error_details = error_details


class PermissionError(WazuhDevSecError):
    """Raised when permission issues occur"""
    
    def __init__(self, operation: str, file_path: Path, **kwargs):
        message = f"Permission denied for {operation} on {file_path}"
        super().__init__(message, file_path=file_path, **kwargs)
        self.operation = operation


class NetworkError(WazuhDevSecError):
    """Raised when network operations fail"""
    
    def __init__(self, url: str, error_details: Optional[str] = None, **kwargs):
        message = f"Network error accessing {url}"
        if error_details:
            message += f" - {error_details}"
        super().__init__(message, component="network", **kwargs)
        self.url = url
        self.error_details = error_details


class DependencyError(WazuhDevSecError):
    """Raised when required dependencies are missing"""
    
    def __init__(self, dependency_name: str, version_required: Optional[str] = None, **kwargs):
        message = f"Missing dependency: {dependency_name}"
        if version_required:
            message += f" (requires {version_required})"
        super().__init__(message, component="dependency", **kwargs)
        self.dependency_name = dependency_name
        self.version_required = version_required


class ProfileError(WazuhDevSecError):
    """Raised when profile operations fail"""
    
    def __init__(self, profile_name: str, operation: str, **kwargs):
        message = f"Profile {operation} failed: {profile_name}"
        super().__init__(message, component="profile", **kwargs)
        self.profile_name = profile_name
        self.operation = operation


class RuleAnalysisError(WazuhDevSecError):
    """Raised when rule analysis fails"""
    pass


class SimulationError(WazuhDevSecError):
    """Raised when simulation operations fail"""
    pass


class DeploymentError(WazuhDevSecError):
    """Raised when deployment operations fail"""
    
    def __init__(self, stage: str, error_details: Optional[str] = None, **kwargs):
        message = f"Deployment failed at stage: {stage}"
        if error_details:
            message += f" - {error_details}"
        super().__init__(message, component="deployment", **kwargs)
        self.stage = stage
        self.error_details = error_details


# Exception handler utility
class ExceptionHandler:
    """Centralized exception handling with logging"""
    
    def __init__(self, logger=None):
        self.logger = logger
    
    def handle_exception(self, exception: Exception, context: Optional[str] = None) -> None:
        """Handle exception with proper logging"""
        if isinstance(exception, WazuhDevSecError):
            # Our custom exceptions
            self._handle_wazuh_exception(exception, context)
        else:
            # Standard Python exceptions
            self._handle_standard_exception(exception, context)
    
    def _handle_wazuh_exception(self, exception: WazuhDevSecError, context: Optional[str]) -> None:
        """Handle our custom exceptions"""
        if self.logger:
            self.logger.error(
                f"{exception.message}",
                component=exception.component or context,
                file_path=exception.file_path,
                **exception.context
            )
        
        # Additional context based on exception type
        if isinstance(exception, ValidationError):
            if self.logger and exception.validation_results:
                for result in exception.validation_results:
                    self.logger.warning(f"Validation issue: {result}")
        
        elif isinstance(exception, IntegrationError):
            if self.logger:
                self.logger.info(f"Check integration setup for {exception.integration_name}")
        
        elif isinstance(exception, FileNotFoundError):
            if self.logger:
                self.logger.info(f"Verify file exists and is accessible: {exception.file_path}")
    
    def _handle_standard_exception(self, exception: Exception, context: Optional[str]) -> None:
        """Handle standard Python exceptions"""
        if self.logger:
            self.logger.error(
                f"Unexpected error: {type(exception).__name__}: {exception}",
                component=context
            )
    
    def create_error_response(self, exception: Exception) -> Dict[str, Any]:
        """Create standardized error response"""
        return {
            "error": True,
            "type": type(exception).__name__,
            "message": str(exception),
            "component": getattr(exception, 'component', None),
            "file_path": getattr(exception, 'file_path', None),
            "context": getattr(exception, 'context', {}),
            "timestamp": datetime.now().isoformat()
        }


# Utility functions for exception handling
def handle_file_operation(operation: str, file_path: Path, logger=None):
    """Context manager for file operations with proper error handling"""
    from contextlib import contextmanager
    
    @contextmanager
    def _handler():
        try:
            yield
        except PermissionError as e:
            error = PermissionError(operation, file_path)
            if logger:
                logger.error(str(error))
            raise error
        except OSError as e:
            error = WazuhDevSecError(f"File operation failed: {operation}", file_path=file_path)
            if logger:
                logger.error(str(error))
            raise error
    
    return _handler()


def validate_file_exists(file_path: Path, component: Optional[str] = None, logger=None) -> None:
    """Validate that file exists"""
    if not file_path.exists():
        error = FileNotFoundError(file_path, component=component)
        if logger:
            logger.error(str(error))
        raise error


def validate_directory_exists(dir_path: Path, create_if_missing: bool = False, 
                          component: Optional[str] = None, logger=None) -> None:
    """Validate that directory exists"""
    if not dir_path.exists():
        if create_if_missing:
            dir_path.mkdir(parents=True, exist_ok=True)
            if logger:
                logger.info(f"Created directory: {dir_path}")
        else:
            error = WazuhDevSecError(f"Directory not found: {dir_path}", component=component)
            if logger:
                logger.error(str(error))
            raise error


# Import datetime for error responses
from datetime import datetime
