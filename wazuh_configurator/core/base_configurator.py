"""
Base Configurator - Abstract base class for configuration strategies
Strategy Pattern Implementation
"""

import shutil
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from dataclasses import dataclass
from ..utils.logger import WazuhLogger


@dataclass
class ConfigResult:
    """Result of a configuration operation"""
    success: bool
    message: str
    details: Dict = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if self.warnings is None:
            self.warnings = []


class BaseConfigurator(ABC):
    """Abstract base class for all configuration strategies"""
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        if not wazuh_path or not isinstance(wazuh_path, str):
            raise ValueError("wazuh_path must be a non-empty string")
        self.wazuh_path = wazuh_path
        self.config_files = {}
        self.backup_files = {}
        self._logger = WazuhLogger(__name__, use_json=False)
    
    @abstractmethod
    def check(self) -> ConfigResult:
        """Check current configuration status"""
        pass
    
    @abstractmethod
    def apply(self) -> ConfigResult:
        """Apply the configuration"""
        pass
    
    @abstractmethod
    def validate(self) -> ConfigResult:
        """Validate the applied configuration"""
        pass
    
    @abstractmethod
    def rollback(self) -> ConfigResult:
        """Rollback to previous configuration"""
        pass
    
    def backup_config(self, file_path: str) -> bool:
        """Backup a configuration file before modification"""
        if not os.path.exists(file_path):
            self._logger.error(f"[-] File does not exist: {file_path}")
            return False
        
        if not os.access(file_path, os.R_OK):
            self._logger.error(f"[-] No read permission: {file_path}")
            return False
        
        try:
            backup_path = f"{file_path}.backup"
            shutil.copy2(file_path, backup_path)
            self.backup_files[file_path] = backup_path
            return True
        except (OSError, IOError) as e:
            self._logger.error(f"[-] Backup failed for {file_path}: {e}")
            return False
    
    def restore_config(self, file_path: str) -> bool:
        """Restore a configuration file from backup"""
        if file_path not in self.backup_files:
            self._logger.error(f"[-] No backup found for {file_path}")
            return False
        
        if not os.access(self.backup_files[file_path], os.R_OK):
            self._logger.error(f"[-] No read permission for backup: {self.backup_files[file_path]}")
            return False
        
        try:
            shutil.copy2(self.backup_files[file_path], file_path)
            return True
        except (OSError, IOError) as e:
            self._logger.error(f"[-] Restore failed for {file_path}: {e}")
            return False
    
    def read_config_file(self, file_path: str) -> Optional[str]:
        """Read a configuration file"""
        if not os.path.exists(file_path):
            self._logger.error(f"[-] File does not exist: {file_path}")
            return None
        
        if not os.access(file_path, os.R_OK):
            self._logger.error(f"[-] No read permission: {file_path}")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except (OSError, IOError) as e:
            self._logger.error(f"[-] Failed to read {file_path}: {e}")
            return None
    
    def write_config_file(self, file_path: str, content: str) -> bool:
        """Write content to a configuration file"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
        except (OSError, IOError) as e:
            self._logger.error(f"[-] Failed to create directory: {e}")
            return False
        
        if not os.access(os.path.dirname(file_path), os.W_OK):
            self._logger.error(f"[-] No write permission: {file_path}")
            return False
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except (OSError, IOError) as e:
            self._logger.error(f"[-] Failed to write {file_path}: {e}")
            return False
