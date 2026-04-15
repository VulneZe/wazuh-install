"""
Config Manager - Main configuration manager (Singleton Pattern)
Coordinates all configuration strategies
"""

import threading
from typing import Dict, List, Optional
from .wazuh_detector import WazuhDetector, WazuhInstallation
from .base_configurator import BaseConfigurator, ConfigResult


class ConfigManager:
    """Main configuration manager - Thread-safe Singleton Pattern"""
    
    _instance = None
    _lock = threading.Lock()
    
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
        self._initialized = True
    
    def initialize(self) -> ConfigResult:
        """Initialize the configuration manager"""
        print("[*] Initialisation du gestionnaire de configuration...")
        
        # Detect Wazuh installation
        self.installation = self.detector.detect_installation()
        
        if not self.installation.installed:
            return ConfigResult(
                success=False,
                message="Wazuh n'est pas installé sur ce système",
                details={"installed": False}
            )
        
        print("[+] Gestionnaire de configuration initialisé")
        return ConfigResult(
            success=True,
            message="Gestionnaire initialisé avec succès",
            details={
                "installed": True,
                "version": self.installation.version,
                "components": self.installation.components
            }
        )
    
    def register_configurator(self, name: str, configurator: BaseConfigurator) -> bool:
        """Register a configuration strategy"""
        self.configurators[name] = configurator
        print(f"[+] Configurator '{name}' enregistré")
        return True
    
    def get_configurator(self, name: str) -> Optional[BaseConfigurator]:
        """Get a specific configurator"""
        return self.configurators.get(name)
    
    def check_all_configs(self) -> Dict[str, ConfigResult]:
        """Check all registered configurations"""
        print("[*] Verification de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            print(f"[*] Verification configuration: {name}")
            results[name] = configurator.check_current_config()
        
        return results
    
    def apply_all_configs(self) -> Dict[str, ConfigResult]:
        """Apply all registered configurations"""
        print("[*] Application de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            print(f"[*] Application configuration: {name}")
            results[name] = configurator.apply_config()
        
        return results
    
    def apply_config(self, name: str) -> ConfigResult:
        """Apply a specific configuration"""
        configurator = self.get_configurator(name)
        if not configurator:
            return ConfigResult(
                success=False,
                message=f"Configurator '{name}' non trouvé"
            )
        
        print(f"[*] Application configuration: {name}")
        return configurator.apply_config()
    
    def validate_all_configs(self) -> Dict[str, ConfigResult]:
        """Validate all applied configurations"""
        print("[*] Validation de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            print(f"[*] Validation configuration: {name}")
            results[name] = configurator.validate_config()
        
        return results
    
    def rollback_all_configs(self) -> Dict[str, ConfigResult]:
        """Rollback all configurations"""
        print("[*] Rollback de toutes les configurations...")
        
        results = {}
        for name, configurator in self.configurators.items():
            print(f"[*] Rollback configuration: {name}")
            results[name] = configurator.rollback_config()
        
        return results
    
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
