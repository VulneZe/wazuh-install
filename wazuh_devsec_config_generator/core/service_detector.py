"""
Service detection and automatic configuration
"""
import subprocess
import socket
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum

from .config import IntegrationType


class ServiceType(str, Enum):
    WEB_SERVER = "web_server"
    DATABASE = "database"
    CI_CD = "ci_cd"
    CONTAINER = "container"
    IDS = "ids"
    SIEM = "siem"
    VERSION_CONTROL = "version_control"


class DetectedService:
    """Represents a detected service"""
    
    def __init__(self, service_type: ServiceType, name: str, version: str = "", port: int = None, config_path: str = ""):
        self.service_type = service_type
        self.name = name
        self.version = version
        self.port = port
        self.config_path = config_path
        self.status = "running"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.service_type.value,
            "name": self.name,
            "version": self.version,
            "port": self.port,
            "config_path": self.config_path,
            "status": self.status
        }


class ServiceDetector:
    """Automatic service detection for Wazuh configuration"""
    
    def __init__(self):
        self.detected_services: List[DetectedService] = []
    
    def scan_all_services(self) -> List[DetectedService]:
        """Scan for all supported services"""
        self.detected_services = []
        
        # Scan different service categories
        self._scan_web_servers()
        self._scan_databases()
        self._scan_ci_cd()
        self._scan_containers()
        self._scan_security_tools()
        self._scan_version_control()
        
        return self.detected_services
    
    def _scan_web_servers(self) -> None:
        """Scan for web servers (Apache, Nginx, IIS)"""
        # Apache
        if self._check_process("apache2") or self._check_process("httpd"):
            version = self._get_version("apache2 -v") or self._get_version("httpd -v")
            config_path = "/etc/apache2/apache2.conf" if Path("/etc/apache2/apache2.conf").exists() else "/etc/httpd/conf/httpd.conf"
            self.detected_services.append(
                DetectedService(ServiceType.WEB_SERVER, "Apache", version, 80, config_path)
            )
        
        # Nginx
        if self._check_process("nginx"):
            version = self._get_version("nginx -v")
            config_path = "/etc/nginx/nginx.conf" if Path("/etc/nginx/nginx.conf").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.WEB_SERVER, "Nginx", version, 80, config_path)
            )
        
        # IIS (Windows)
        if self._check_process("w3wp"):
            self.detected_services.append(
                DetectedService(ServiceType.WEB_SERVER, "IIS", "", 80, "")
            )
    
    def _scan_databases(self) -> None:
        """Scan for databases (MySQL, PostgreSQL, MongoDB, Redis)"""
        # MySQL/MariaDB
        if self._check_process("mysqld") or self._check_process("mariadb"):
            version = self._get_version("mysql --version") or self._get_version("mariadb --version")
            config_path = "/etc/mysql/my.cnf" if Path("/etc/mysql/my.cnf").exists() else "/etc/my.cnf"
            self.detected_services.append(
                DetectedService(ServiceType.DATABASE, "MySQL", version, 3306, config_path)
            )
        
        # PostgreSQL
        if self._check_process("postgres"):
            version = self._get_version("postgres --version")
            config_path = "/etc/postgresql/*/main/postgresql.conf" if Path("/etc/postgresql").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.DATABASE, "PostgreSQL", version, 5432, config_path)
            )
        
        # MongoDB
        if self._check_process("mongod"):
            version = self._get_version("mongod --version")
            config_path = "/etc/mongod.conf" if Path("/etc/mongod.conf").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.DATABASE, "MongoDB", version, 27017, config_path)
            )
        
        # Redis
        if self._check_process("redis-server"):
            version = self._get_version("redis-server --version")
            config_path = "/etc/redis/redis.conf" if Path("/etc/redis/redis.conf").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.DATABASE, "Redis", version, 6379, config_path)
            )
    
    def _scan_ci_cd(self) -> None:
        """Scan for CI/CD tools (Jenkins, GitLab, GitHub Actions)"""
        # Jenkins
        if self._check_process("jenkins") or self._check_port(8080):
            version = self._get_jenkins_version()
            config_path = "/etc/default/jenkins" if Path("/etc/default/jenkins").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.CI_CD, "Jenkins", version, 8080, config_path)
            )
        
        # GitLab
        if self._check_process("gitlab-runsvdir") or self._check_port(80):
            version = self._get_gitlab_version()
            config_path = "/etc/gitlab/gitlab.rb" if Path("/etc/gitlab/gitlab.rb").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.CI_CD, "GitLab", version, 80, config_path)
            )
        
        # GitHub Actions runner
        if self._check_process("actions.runner"):
            self.detected_services.append(
                DetectedService(ServiceType.CI_CD, "GitHub Actions", "", 0, "")
            )
    
    def _scan_containers(self) -> None:
        """Scan for container technologies (Docker, Kubernetes)"""
        # Docker
        if self._check_process("dockerd") or self._check_command("docker --version"):
            version = self._get_version("docker --version")
            self.detected_services.append(
                DetectedService(ServiceType.CONTAINER, "Docker", version, 0, "")
            )
        
        # Kubernetes
        if self._check_process("kubelet") or self._check_command("kubectl version"):
            version = self._get_version("kubectl version --short")
            self.detected_services.append(
                DetectedService(ServiceType.CONTAINER, "Kubernetes", version, 0, "")
            )
        
        # Podman
        if self._check_command("podman --version"):
            version = self._get_version("podman --version")
            self.detected_services.append(
                DetectedService(ServiceType.CONTAINER, "Podman", version, 0, "")
            )
    
    def _scan_security_tools(self) -> None:
        """Scan for security tools (Suricata, OSSEC, Wazuh)"""
        # Suricata
        if self._check_process("suricata"):
            version = self._get_version("suricata --version")
            config_path = "/etc/suricata/suricata.yaml" if Path("/etc/suricata/suricata.yaml").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.IDS, "Suricata", version, 0, config_path)
            )
        
        # Wazuh
        if self._check_process("wazuh-manager") or self._check_process("ossec"):
            version = self._get_wazuh_version()
            config_path = "/var/ossec/etc/ossec.conf" if Path("/var/ossec/etc/ossec.conf").exists() else ""
            self.detected_services.append(
                DetectedService(ServiceType.SIEM, "Wazuh", version, 0, config_path)
            )
        
        # Elastic Stack
        if self._check_process("elasticsearch"):
            version = self._get_elasticsearch_version()
            self.detected_services.append(
                DetectedService(ServiceType.SIEM, "Elasticsearch", version, 9200, "")
            )
        
        if self._check_process("kibana"):
            version = self._get_kibana_version()
            self.detected_services.append(
                DetectedService(ServiceType.SIEM, "Kibana", version, 5601, "")
            )
    
    def _scan_version_control(self) -> None:
        """Scan for version control systems"""
        # Git
        if self._check_command("git --version"):
            version = self._get_version("git --version")
            self.detected_services.append(
                DetectedService(ServiceType.VERSION_CONTROL, "Git", version, 0, "")
            )
        
        # SVN
        if self._check_command("svn --version"):
            version = self._get_version("svn --version")
            self.detected_services.append(
                DetectedService(ServiceType.VERSION_CONTROL, "Subversion", version, 0, "")
            )
    
    def _check_process(self, process_name: str) -> bool:
        """Check if a process is running"""
        try:
            result = subprocess.run(["pgrep", process_name], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_command(self, command: str) -> bool:
        """Check if a command is available"""
        try:
            result = subprocess.run(command.split(), capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def _check_port(self, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_version(self, command: str) -> str:
        """Get version from command output"""
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                # Extract version from output
                output = result.stdout or result.stderr
                for line in output.split('\n'):
                    if 'version' in line.lower() or line.strip().startswith(('v', 'V')):
                        return line.strip()
                return output.split('\n')[0].strip()
        except:
            pass
        return ""
    
    def _get_jenkins_version(self) -> str:
        """Get Jenkins version via API"""
        try:
            response = requests.get("http://localhost:8080/api/json", timeout=5)
            if response.status_code == 200:
                return response.json().get("version", "")
        except:
            pass
        return ""
    
    def _get_gitlab_version(self) -> str:
        """Get GitLab version"""
        try:
            result = subprocess.run(["gitlab-rake", "gitlab:env:info"], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'Version:' in line:
                        return line.split(':')[1].strip()
        except:
            pass
        return ""
    
    def _get_wazuh_version(self) -> str:
        """Get Wazuh version"""
        try:
            result = subprocess.run(["/var/ossec/bin/wazuh-control", "status"], capture_output=True, text=True)
            if result.returncode == 0:
                return "Wazuh Manager"
        except:
            pass
        return ""
    
    def _get_elasticsearch_version(self) -> str:
        """Get Elasticsearch version"""
        try:
            response = requests.get("http://localhost:9200", timeout=5)
            if response.status_code == 200:
                return response.json().get("version", {}).get("number", "")
        except:
            pass
        return ""
    
    def _get_kibana_version(self) -> str:
        """Get Kibana version"""
        try:
            response = requests.get("http://localhost:5601/api/status", timeout=5)
            if response.status_code == 200:
                return response.json().get("version", {}).get("number", "")
        except:
            pass
        return ""
    
    def get_recommended_integrations(self) -> List[IntegrationType]:
        """Get recommended integrations based on detected services"""
        recommendations = set()
        
        for service in self.detected_services:
            if service.service_type == ServiceType.WEB_SERVER:
                recommendations.add(IntegrationType.SURICATA)
                recommendations.add(IntegrationType.ELASTICSEARCH)
            
            elif service.service_type == ServiceType.DATABASE:
                recommendations.add(IntegrationType.ELASTICSEARCH)
                recommendations.add(IntegrationType.VIRUSTOTAL)
            
            elif service.service_type == ServiceType.CI_CD:
                recommendations.add(IntegrationType.VIRUSTOTAL)
                recommendations.add(IntegrationType.ELASTICSEARCH)
            
            elif service.service_type == ServiceType.CONTAINER:
                recommendations.add(IntegrationType.SURICATA)
                recommendations.add(IntegrationType.ELASTICSEARCH)
            
            elif service.service_type == ServiceType.IDS:
                recommendations.add(IntegrationType.ELASTICSEARCH)
                recommendations.add(IntegrationType.THEHIVE)
        
        return list(recommendations)
    
    def get_service_summary(self) -> Dict[str, Any]:
        """Get summary of detected services"""
        summary = {
            "total_services": len(self.detected_services),
            "by_type": {},
            "services": [service.to_dict() for service in self.detected_services],
            "recommended_integrations": [it.value for it in self.get_recommended_integrations()]
        }
        
        for service in self.detected_services:
            service_type = service.service_type.value
            if service_type not in summary["by_type"]:
                summary["by_type"][service_type] = []
            summary["by_type"][service_type].append(service.to_dict())
        
        return summary
