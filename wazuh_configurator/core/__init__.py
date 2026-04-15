"""
Core module - Base classes and main manager
"""

from .config_manager import ConfigManager
from .wazuh_detector import WazuhDetector, WazuhInstallation
from .base_configurator import BaseConfigurator, ConfigResult

__all__ = [
    'ConfigManager',
    'WazuhDetector',
    'WazuhInstallation',
    'BaseConfigurator',
    'ConfigResult'
]
