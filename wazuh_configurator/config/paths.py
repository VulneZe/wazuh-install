"""
Wazuh Configuration Paths
Centralized path configuration for Wazuh components
"""

import os
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class WazuhPaths:
    """Centralized Wazuh path configuration"""
    
    # Wazuh Manager paths
    wazuh_path: str = "/var/ossec"
    ossec_conf: str = "/var/ossec/etc/ossec.conf"
    local_options: str = "/var/ossec/etc/local_internal_options.conf"
    passwords_file: str = "/var/ossec/etc/wazuh-passwords.txt"
    api_config: str = "/var/ossec/api/configuration/api.yaml"
    
    # Wazuh Indexer paths
    indexer_config: str = "/etc/wazuh-indexer/opensearch.yml"
    jvm_config: str = "/etc/wazuh-indexer/jvm.options"
    indexer_certs: str = "/etc/wazuh-indexer/certs"
    indexer_security: str = "/etc/wazuh-indexer/opensearch-security"
    internal_users: str = "/etc/wazuh-indexer/opensearch-security/internal_users.yml"
    
    # Wazuh Dashboard paths
    dashboard_config: str = "/etc/wazuh-dashboard/opensearch_dashboards.yml"
    
    # System paths
    logrotate_config: str = "/etc/logrotate.d/wazuh"
    cron_daily: str = "/etc/cron.daily"
    usr_local_bin: str = "/usr/local/bin"
    
    # Logs
    wazuh_logs: str = "/var/ossec/logs"
    alerts_logs: str = "/var/ossec/logs/alerts"
    archives_logs: str = "/var/ossec/logs/archives"
    
    # Default ports
    indexer_port: int = 9200
    manager_events_port: int = 1514
    manager_agents_port: int = 1515
    api_port: int = 55000
    dashboard_port: int = 5601
    ssh_port: int = 22
    
    @classmethod
    def from_dict(cls, config: Dict) -> 'WazuhPaths':
        """Create WazuhPaths from dictionary configuration"""
        return cls(**{k: v for k, v in config.items() if k in cls.__annotations__})
    
    def to_dict(self) -> Dict:
        """Convert WazuhPaths to dictionary"""
        return {
            k: getattr(self, k)
            for k in self.__annotations__
        }


class PathDetector:
    """Automatic path detection for Wazuh installation"""
    
    @staticmethod
    def detect_wazuh_path() -> str:
        """Detect Wazuh installation path"""
        common_paths = [
            "/var/ossec",
            "/opt/wazuh",
            "/usr/local/wazuh"
        ]
        
        for path in common_paths:
            if os.path.exists(path) and os.path.exists(os.path.join(path, "etc", "ossec.conf")):
                return path
        
        return "/var/ossec"  # Default
    
    @staticmethod
    def detect_indexer_path() -> str:
        """Detect Wazuh Indexer configuration path"""
        common_paths = [
            "/etc/wazuh-indexer",
            "/etc/opensearch",
            "/etc/elasticsearch"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return "/etc/wazuh-indexer"  # Default
    
    @staticmethod
    def detect_dashboard_path() -> str:
        """Detect Wazuh Dashboard configuration path"""
        common_paths = [
            "/etc/wazuh-dashboard",
            "/etc/opensearch-dashboards",
            "/etc/kibana"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        return "/etc/wazuh-dashboard"  # Default
    
    @classmethod
    def detect_all_paths(cls) -> WazuhPaths:
        """Detect all Wazuh paths automatically"""
        wazuh_path = cls.detect_wazuh_path()
        indexer_path = cls.detect_indexer_path()
        dashboard_path = cls.detect_dashboard_path()
        
        return WazuhPaths(
            wazuh_path=wazuh_path,
            ossec_conf=os.path.join(wazuh_path, "etc", "ossec.conf"),
            local_options=os.path.join(wazuh_path, "etc", "local_internal_options.conf"),
            passwords_file=os.path.join(wazuh_path, "etc", "wazuh-passwords.txt"),
            api_config=os.path.join(wazuh_path, "api", "configuration", "api.yaml"),
            indexer_config=os.path.join(indexer_path, "opensearch.yml"),
            jvm_config=os.path.join(indexer_path, "jvm.options"),
            indexer_certs=os.path.join(indexer_path, "certs"),
            indexer_security=os.path.join(indexer_path, "opensearch-security"),
            internal_users=os.path.join(indexer_path, "opensearch-security", "internal_users.yml"),
            dashboard_config=os.path.join(dashboard_path, "opensearch_dashboards.yml"),
            wazuh_logs=os.path.join(wazuh_path, "logs"),
            alerts_logs=os.path.join(wazuh_path, "logs", "alerts"),
            archives_logs=os.path.join(wazuh_path, "logs", "archives")
        )


# Default paths instance
default_paths = WazuhPaths()
