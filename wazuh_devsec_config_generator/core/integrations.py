"""
Integration management with plugin system
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional
import subprocess
import json
from enum import Enum

from .config import IntegrationType


class IntegrationStatus(Enum):
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    CONFIGURED = "configured"
    ERROR = "error"


class BaseIntegration(ABC):
    """Base class for all integrations"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.status = IntegrationStatus.NOT_INSTALLED
        self.config = {}
    
    @abstractmethod
    def check_installation(self) -> IntegrationStatus:
        """Check if the integration is installed"""
        pass
    
    @abstractmethod
    def configure(self, config: Dict[str, Any]) -> bool:
        """Configure the integration"""
        pass
    
    @abstractmethod
    def generate_rules(self) -> List[Dict[str, Any]]:
        """Generate specific rules for this integration"""
        pass
    
    @abstractmethod
    def generate_decoders(self) -> List[Dict[str, Any]]:
        """Generate specific decoders for this integration"""
        pass


class VirusTotalIntegration(BaseIntegration):
    """VirusTotal integration for file hash checking"""
    
    def check_installation(self) -> IntegrationStatus:
        """Check if VirusTotal API key is configured"""
        try:
            result = subprocess.run(["which", "vt"], capture_output=True, text=True)
            if result.returncode == 0:
                self.status = IntegrationStatus.INSTALLED
                return self.status
        except:
            pass
        
        # Check for API key in environment
        import os
        if os.getenv("VIRUSTOTAL_API_KEY"):
            self.status = IntegrationStatus.CONFIGURED
            return self.status
        
        self.status = IntegrationStatus.NOT_INSTALLED
        return self.status
    
    def configure(self, config: Dict[str, Any]) -> bool:
        """Configure VirusTotal API"""
        api_key = config.get("api_key")
        if not api_key:
            return False
        
        self.config["api_key"] = api_key
        self.status = IntegrationStatus.CONFIGURED
        return True
    
    def generate_rules(self) -> List[Dict[str, Any]]:
        """Generate VirusTotal-specific rules"""
        return [
            {
                "rule_id": 200001,
                "level": 12,
                "title": "VirusTotal malicious file detected",
                "description": "File detected as malicious by VirusTotal",
                "mitre": "T1560.001",
                "regex": r"virustotal.*malicious",
                "group": "virustotal,devsec"
            },
            {
                "rule_id": 200002,
                "level": 8,
                "title": "VirusTotal suspicious file",
                "description": "File detected as suspicious by VirusTotal",
                "mitre": "T1560.001",
                "regex": r"virustotal.*suspicious",
                "group": "virustotal,devsec"
            }
        ]
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        """Generate VirusTotal decoders"""
        return [
            {
                "name": "virustotal",
                "prematch": r"virustotal",
                "regex": r"virustotal\[(\S+)\]: (.+)"
            }
        ]


class SuricataIntegration(BaseIntegration):
    """Suricata IDS integration"""
    
    def check_installation(self) -> IntegrationStatus:
        """Check if Suricata is installed"""
        try:
            result = subprocess.run(["which", "suricata"], capture_output=True, text=True)
            if result.returncode == 0:
                # Check if running
                result = subprocess.run(["pgrep", "suricata"], capture_output=True)
                if result.returncode == 0:
                    self.status = IntegrationStatus.CONFIGURED
                else:
                    self.status = IntegrationStatus.INSTALLED
                return self.status
        except:
            pass
        
        self.status = IntegrationStatus.NOT_INSTALLED
        return self.status
    
    def configure(self, config: Dict[str, Any]) -> bool:
        """Configure Suricata integration"""
        self.config.update(config)
        return True
    
    def generate_rules(self) -> List[Dict[str, Any]]:
        """Generate Suricata-specific rules"""
        return [
            {
                "rule_id": 201001,
                "level": 13,
                "title": "Suricata high severity alert",
                "description": "High severity alert from Suricata IDS",
                "mitre": "T1190",
                "regex": r"suricata.*\[.*\]\s*\[.*High.*\]",
                "group": "suricata,devsec"
            },
            {
                "rule_id": 201002,
                "level": 10,
                "title": "Suricata medium severity alert",
                "description": "Medium severity alert from Suricata IDS",
                "mitre": "T1059",
                "regex": r"suricata.*\[.*\]\s*\[.*Medium.*\]",
                "group": "suricata,devsec"
            }
        ]
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        """Generate Suricata decoders"""
        return [
            {
                "name": "suricata",
                "prematch": r"suricata",
                "regex": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{4})\[.*\]\s*\[(\d+:\d+:\d+)\]\s*(.+)"
            }
        ]


class ElasticsearchIntegration(BaseIntegration):
    """Elasticsearch integration for log storage"""
    
    def check_installation(self) -> IntegrationStatus:
        """Check if Elasticsearch is available"""
        try:
            import requests
            response = requests.get("http://localhost:9200", timeout=5)
            if response.status_code == 200:
                self.status = IntegrationStatus.CONFIGURED
                return self.status
        except:
            pass
        
        self.status = IntegrationStatus.NOT_INSTALLED
        return self.status
    
    def configure(self, config: Dict[str, Any]) -> bool:
        """Configure Elasticsearch connection"""
        self.config.update(config)
        return True
    
    def generate_rules(self) -> List[Dict[str, Any]]:
        """Generate Elasticsearch-specific rules"""
        return [
            {
                "rule_id": 202001,
                "level": 9,
                "title": "Elasticsearch query anomaly",
                "description": "Unusual query pattern detected in Elasticsearch",
                "mitre": "T1087",
                "regex": r"elasticsearch.*query.*anomaly",
                "group": "elasticsearch,devsec"
            }
        ]
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        """Generate Elasticsearch decoders"""
        return [
            {
                "name": "elasticsearch",
                "prematch": r"elasticsearch",
                "regex": r"elasticsearch\[(\S+)\]: (.+)"
            }
        ]


class IntegrationManager:
    """Manager for all integrations"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.integrations: Dict[IntegrationType, BaseIntegration] = {
            IntegrationType.VIRUSTOTAL: VirusTotalIntegration(output_dir),
            IntegrationType.SURICATA: SuricataIntegration(output_dir),
            IntegrationType.ELASTICSEARCH: ElasticsearchIntegration(output_dir),
        }
    
    def register_integration(self, integration_type: IntegrationType, integration: BaseIntegration) -> None:
        """Register a new integration"""
        self.integrations[integration_type] = integration
    
    def check_all_installations(self) -> Dict[IntegrationType, IntegrationStatus]:
        """Check installation status of all integrations"""
        status_map = {}
        for integration_type, integration in self.integrations.items():
            status_map[integration_type] = integration.check_installation()
        return status_map
    
    def setup_integrations(self, enabled_integrations: List[IntegrationType]) -> Dict[str, Any]:
        """Setup enabled integrations"""
        results = {}
        
        for integration_type in enabled_integrations:
            if integration_type not in self.integrations:
                continue
            
            integration = self.integrations[integration_type]
            status = integration.check_installation()
            
            results[integration_type] = {
                "status": status.value,
                "rules": integration.generate_rules() if status != IntegrationStatus.NOT_INSTALLED else [],
                "decoders": integration.generate_decoders() if status != IntegrationStatus.NOT_INSTALLED else []
            }
        
        return results
    
    def configure_integration(self, integration_type: IntegrationType, config: Dict[str, Any]) -> bool:
        """Configure a specific integration"""
        if integration_type in self.integrations:
            return self.integrations[integration_type].configure(config)
        return False
