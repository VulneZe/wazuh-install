"""
Wazuh Detector - Detect existing Wazuh installations
"""

import os
import subprocess
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class WazuhInstallation:
    """Information about a Wazuh installation"""
    installed: bool
    version: str = ""
    components: Dict[str, bool] = None
    config_paths: Dict[str, str] = None
    services_status: Dict[str, str] = None
    
    def __post_init__(self):
        if self.components is None:
            self.components = {}
        if self.config_paths is None:
            self.config_paths = {}
        if self.services_status is None:
            self.services_status = {}


class WazuhDetector:
    """Detect Wazuh installation and components"""
    
    WAZUH_PATHS = [
        "/var/ossec",
        "/etc/wazuh",
        "/usr/share/wazuh"
    ]
    
    WAZUH_SERVICES = [
        "wazuh-indexer",
        "wazuh-manager",
        "wazuh-dashboard"
    ]
    
    CONFIG_FILES = {
        "wazuh-indexer": "/etc/wazuh-indexer/opensearch.yml",
        "wazuh-manager": "/var/ossec/etc/ossec.conf",
        "wazuh-dashboard": "/etc/wazuh-dashboard/opensearch_dashboards.yml"
    }
    
    def __init__(self):
        self.installation = WazuhInstallation(installed=False)
    
    def detect_installation(self) -> WazuhInstallation:
        """Detect if Wazuh is installed and gather information"""
        print("[*] Detection de l'installation Wazuh...")
        
        # Check if Wazuh is installed
        wazuh_path = self._find_wazuh_path()
        if not wazuh_path:
            print("[-] Wazuh non détecté sur ce système")
            return self.installation
        
        self.installation.installed = True
        print(f"[+] Wazuh détecté dans: {wazuh_path}")
        
        # Get version
        self.installation.version = self._get_wazuh_version()
        print(f"[+] Version Wazuh: {self.installation.version}")
        
        # Detect components
        self.installation.components = self._detect_components()
        print(f"[+] Composants détectés: {list(self.installation.components.keys())}")
        
        # Get config paths
        self.installation.config_paths = self._get_config_paths()
        
        # Check services status
        self.installation.services_status = self._check_services_status()
        
        return self.installation
    
    def _find_wazuh_path(self) -> str:
        """Find Wazuh installation path"""
        for path in self.WAZUH_PATHS:
            if os.path.exists(path):
                return path
        return ""
    
    def _get_wazuh_version(self) -> str:
        """Get Wazuh version"""
        try:
            result = subprocess.run(
                ["wazuh-control", "version"],
                capture_output=True, text=True, check=False,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass
        
        # Try alternative method
        try:
            if os.path.exists("/var/ossec/etc/ossec.conf"):
                result = subprocess.run(
                    ["grep", "version", "/var/ossec/etc/ossec.conf"],
                    capture_output=True, text=True, check=False,
                    timeout=10
                )
                if result.returncode == 0:
                    return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass
        
        return "Unknown"
    
    def _detect_components(self) -> Dict[str, bool]:
        """Detect which Wazuh components are installed"""
        components: Dict[str, bool] = {}
        
        # Check indexer
        if os.path.exists("/etc/wazuh-indexer"):
            components["indexer"] = True
        
        # Check manager
        if os.path.exists("/var/ossec"):
            components["manager"] = True
        
        # Check dashboard
        if os.path.exists("/etc/wazuh-dashboard"):
            components["dashboard"] = True
        
        return components
    
    def _get_config_paths(self) -> Dict[str, str]:
        """Get configuration file paths"""
        config_paths: Dict[str, str] = {}
        for component, path in self.CONFIG_FILES.items():
            if os.path.exists(path):
                config_paths[component] = path
        return config_paths
    
    def _check_services_status(self) -> Dict[str, str]:
        """Check status of Wazuh services"""
        services_status: Dict[str, str] = {}
        
        for service in self.WAZUH_SERVICES:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True, check=False,
                    timeout=10
                )
                services_status[service] = result.stdout.strip()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                services_status[service] = "unknown"
            except Exception:
                services_status[service] = "unknown"
        
        return services_status
    
    def is_component_installed(self, component: str) -> bool:
        """Check if a specific component is installed"""
        return self.installation.components.get(component, False)
    
    def get_service_status(self, service: str) -> str:
        """Get status of a specific service"""
        return self.installation.services_status.get(service, "unknown")
