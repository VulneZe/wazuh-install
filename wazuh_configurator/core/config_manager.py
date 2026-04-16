"""
Config Manager - Main configuration manager (Singleton Pattern)
Coordinates all configuration strategies
"""

import threading
from typing import Dict, List, Optional, Dict, Any
from .wazuh_detector import WazuhDetector, WazuhInstallation
from .base_configurator import BaseConfigurator, ConfigResult
from ..utils.ssh_client import SSHClient, SSHCredentials
from ..utils.exceptions import SSHConnectionError, SSHAuthenticationError
from ..utils.logger import WazuhLogger


class ConfigManager:
    """Main configuration manager - Thread-safe Singleton Pattern"""
    
    _instance = None
    _lock = threading.Lock()
    _logger = WazuhLogger(__name__, use_json=False)
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(ConfigManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.detector = WazuhDetector()
        self.installation: Optional[WazuhInstallation] = None
        self.configurators: Dict[str, BaseConfigurator] = {}
        
        # Remote configuration
        self.is_remote = False
        self.ssh_client: Optional[SSHClient] = None
        self.ssh_credentials: Optional[SSHCredentials] = None
        self.custom_ports: Optional[Dict[str, int]] = None
        
        self._initialized = True
    
    def initialize(self) -> ConfigResult:
        """Initialize the configuration manager"""
        self._logger.info("Initialisation du gestionnaire de configuration...")
        
        # Detect Wazuh installation
        self.installation = self.detector.detect_installation()
        
        if not self.installation.installed:
            return ConfigResult(
                success=False,
                message="Wazuh n'est pas installé sur ce système",
                details={"installed": False}
            )
        
        self._logger.info("Gestionnaire de configuration initialisé")
        return ConfigResult(
            success=True,
            message="Gestionnaire de configuration initialisé avec succès",
            details={"installed": True}
        )
    
    def set_remote_config(
        self,
        host: str,
        ssh_user: str,
        ssh_key: Optional[str] = None,
        ssh_password: Optional[str] = None,
        ssh_port: int = 22,
        custom_ports: Optional[str] = None,
        wazuh_path: str = "/var/ossec"
    ):
        """Set remote configuration for SSH connections"""
        self.is_remote = True
        
        # Parse custom ports if provided
        if custom_ports:
            self.custom_ports = {}
            for port_spec in custom_ports.split(','):
                if ':' in port_spec:
                    key, value = port_spec.split(':')
                    self.custom_ports[key.strip()] = int(value.strip())
        
        # Create SSH credentials
        self.ssh_credentials = SSHCredentials(
            host=host,
            username=ssh_user,
            port=ssh_port,
            password=ssh_password,
            key_file=ssh_key
        )
        
        # Create SSH client
        self.ssh_client = SSHClient(self.ssh_credentials)
        
        self._logger.info(f"Configuration distante définie pour {host}:{ssh_port}")
    
    def connect_ssh(self) -> bool:
        """Establish SSH connection if remote mode is enabled"""
        if not self.is_remote or not self.ssh_client:
            return True
        
        try:
            if self.ssh_client.connect():
                self._logger.info("Connexion SSH établie avec succès")
                return True
            else:
                raise SSHConnectionError("Échec de la connexion SSH")
        except SSHAuthenticationError as e:
            self._logger.error(f"Erreur d'authentification SSH: {e}")
            return False
        except SSHConnectionError as e:
            self._logger.error(f"Erreur de connexion SSH: {e}")
            return False
    
    def disconnect_ssh(self):
        """Disconnect SSH connection if established"""
        if self.ssh_client:
            self.ssh_client.disconnect()
    
    def register_configurator(self, name: str, configurator: BaseConfigurator) -> bool:
        """Register a configuration strategy"""
        self.configurators[name] = configurator
        self._logger.info(f"Configurator '{name}' enregistré")
        return True
    
    def get_configurator(self, name: str) -> Optional[BaseConfigurator]:
        """Get a specific configurator"""
        return self.configurators.get(name)
    
    def check_all_configs(self) -> Dict[str, ConfigResult]:
        """Check all registered configurations"""
        self._logger.info("Verification de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            self._logger.info(f"Verification configuration: {name}")
            result = configurator.check()
            results[name] = result
        
        return results
    
    def apply_all_configs(self) -> Dict[str, ConfigResult]:
        """Apply all registered configurations"""
        self._logger.info("Application de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            self._logger.info(f"Application configuration: {name}")
            result = configurator.apply()
            results[name] = result
        
        return results
    
    def apply_config(self, name: str) -> ConfigResult:
        """Apply a specific configuration"""
        configurator = self.get_configurator(name)
        if not configurator:
            return ConfigResult(
                success=False,
                message=f"Configurator '{name}' non trouvé"
            )
        
        self._logger.info(f"Application configuration: {name}")
        return configurator.apply()
    
    def validate_all_configs(self) -> Dict[str, ConfigResult]:
        """Validate all applied configurations"""
        self._logger.info("Validation de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            self._logger.info(f"Validation configuration: {name}")
            results[name] = configurator.validate()
        
        return results
    
    def rollback_all_configs(self) -> Dict[str, ConfigResult]:
        """Rollback all configurations"""
        self._logger.info("Rollback de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            self._logger.info(f"Rollback configuration: {name}")
            results[name] = configurator.rollback()
        
        return results
    
    def rollback_config(self, name: str) -> ConfigResult:
        """Rollback a specific configuration"""
        configurator = self.get_configurator(name)
        if not configurator:
            return ConfigResult(
                success=False,
                message=f"Configurator '{name}' non trouvé"
            )
        
        self._logger.info(f"Rollback configuration: {name}")
        return configurator.rollback()
    
    def get_installation_info(self) -> WazuhInstallation:
        """Get current Wazuh installation information"""
        return self.installation
    
    def get_summary(self) -> Dict:
        """Get summary of current state"""
        return {
            "installed": self.installation.installed if self.installation else False,
            "version": self.installation.version if self.installation else "",
            "components": self.installation.components if self.installation else {},
            "registered_configurators": list(self.configurators.keys()),
            "services_status": self.installation.services_status if self.installation else {}
        }
