"""
Custom Exceptions for Wazuh Configurator
Specific exception classes for better error handling
"""


class WazuhConfiguratorError(Exception):
    """Base exception for Wazuh Configurator"""
    pass


class PathDetectionError(WazuhConfiguratorError):
    """Raised when path detection fails"""
    pass


class ConfigurationError(WazuhConfiguratorError):
    """Raised when configuration operation fails"""
    pass


class SSHConnectionError(WazuhConfiguratorError):
    """Raised when SSH connection fails"""
    pass


class SSHAuthenticationError(WazuhConfiguratorError):
    """Raised when SSH authentication fails"""
    pass


class SSHCommandError(WazuhConfiguratorError):
    """Raised when SSH command execution fails"""
    def __init__(self, message: str, exit_code: int, output: str, error: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.output = output
        self.error = error


class FileOperationError(WazuhConfiguratorError):
    """Raised when file operation fails"""
    pass


class PermissionError(WazuhConfiguratorError):
    """Raised when permission is denied"""
    pass


class ServiceNotAvailableError(WazuhConfiguratorError):
    """Raised when a required service is not available"""
    pass


class InvalidConfigurationError(WazuhConfiguratorError):
    """Raised when configuration is invalid"""
    pass


class CacheError(WazuhConfiguratorError):
    """Raised when cache operation fails"""
    pass
