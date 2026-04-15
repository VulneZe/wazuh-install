"""
Constants and configuration for Wazuh DevSec Generator
Clean, centralized configuration management
"""

from enum import Enum
from typing import Dict, List, Any


class RuleCategory(str, Enum):
    """Rule categories with descriptions"""
    GIT = "git"
    DOCKER = "docker"
    IDE = "ide"
    CICD = "cicd"
    RANSOMWARE = "ransomware"
    INSIDER = "insider"
    WEB = "web"
    DATABASE = "database"


class RuleLevel(str, Enum):
    """Wazuh rule levels with descriptions"""
    INFO = "0-3"
    LOW = "4-6"
    MEDIUM = "7-9"
    HIGH = "10-12"
    CRITICAL = "13-15"


class IntegrationStatus(str, Enum):
    """Integration status levels"""
    INSTALLED = "installed"
    CONFIGURED = "configured"
    MISSING = "missing"
    ERROR = "error"


class RuleCategory(str, Enum):
    """Rule categories with descriptions"""
    GIT = "git"
    DOCKER = "docker"
    IDE = "ide"
    CICD = "cicd"
    RANSOMWARE = "ransomware"
    INSIDER = "insider"
    WEB = "web"
    DATABASE = "database"


# Wazuh configuration paths
WAZUH_PATHS = {
    "linux": {
        "root": "/var/ossec",
        "rules": "/var/ossec/etc/rules",
        "decoders": "/var/ossec/etc/decoders",
        "lists": "/var/ossec/etc/lists",
        "config": "/var/ossec/etc/ossec.conf",
        "ar_bin": "/var/ossec/active-response/bin"
    },
    "macos": {
        "root": "/Library/Application Support/Wazuh",
        "rules": "/Library/Application Support/Wazuh/etc/rules",
        "decoders": "/Library/Application Support/Wazuh/etc/decoders",
        "lists": "/Library/Application Support/Wazuh/etc/lists",
        "config": "/Library/Application Support/Wazuh/etc/ossec.conf",
        "ar_bin": "/Library/Application Support/Wazuh/active-response/bin"
    },
    "windows": {
        "root": "C:\\Program Files (x86)\\ossec-agent",
        "rules": "C:\\Program Files (x86)\\ossec-agent\\rules",
        "decoders": "C:\\Program Files (x86)\\ossec-agent\\decoders",
        "lists": "C:\\Program Files (x86)\\ossec-agent\\lists",
        "config": "C:\\Program Files (x86)\\ossec-agent\\ossec.conf",
        "ar_bin": "C:\\Program Files (x86)\\ossec-agent\\active-response\\bin"
    }
}


# Rule ID ranges for different categories
RULE_ID_RANGES = {
    RuleCategory.GIT: (101000, 101999),
    RuleCategory.DOCKER: (104000, 104999),
    RuleCategory.IDE: (102000, 102999),
    RuleCategory.CICD: (103000, 103999),
    RuleCategory.RANSOMWARE: (105000, 105999),
    RuleCategory.INSIDER: (106000, 106999),
    RuleCategory.WEB: (107000, 107999),
    RuleCategory.DATABASE: (108000, 108999)
}


# MITRE ATT&CK technique mappings
MITRE_TECHNIQUES = {
    "git": {
        "clone": "T1213",  # Data from Information Repositories
        "credentials": "T1552.001",  # Credentials from Files or Directories
        "config": "T1565.001",  # Manipulation of Configuration Files
        "force_push": "T1565.001"
    },
    "docker": {
        "privileged": "T1610",  # Deploy Container
        "host_mount": "T1610",
        "socket_mount": "T1610",
        "exec": "T1059"  # Command and Scripting Interpreter
    },
    "ide": {
        "file_access": "T1083",  # File and Directory Discovery
        "extension": "T1102",  # Web Service
        "debug": "T1055.001"  # Process Injection
    },
    "cicd": {
        "package": "T1195.002",  # Supply Chain Compromise
        "pipeline": "T1548.003",  # Abuse Elevation Control Mechanism
        "exfil": "T1041",  # Exfiltration Over C2 Channel
        "secrets": "T1552.001"
    },
    "ransomware": {
        "encryption": "T1486",  # Data Encrypted for Impact
        "extension": "T1486",
        "notes": "T1486",
        "backup": "T1485"  # Data Destruction
    },
    "insider": {
        "exfil": "T1041",
        "access": "T1083",
        "accounts": "T1098",  # Account Manipulation
        "logs": "T1070.001",  # Indicator Removal on Host
        "usb": "T1091"  # Replication Through Removable Media
    },
    "web": {
        "injection": "T1190",  # Exploit Public-Facing Application
        "upload": "T1505.003",  # Web Shell
        "admin": "T1078"  # Valid Accounts
    },
    "database": {
        "dump": "T1007",  # System Service Discovery
        "injection": "T1190",
        "users": "T1078",
        "backup": "T1565.001"
    }
}


# Whitelist patterns for common legitimate activities
WHITELIST_PATTERNS = {
    "git": [
        r"github\.com",
        r"gitlab\.com",
        r"bitbucket\.com",
        r"git@.*\.com",
        r"origin",
        r"upstream",
        r"feature/",
        r"bugfix/",
        r"hotfix/",
        r"\.md$",
        r"\.txt$",
        r"\.json$"
    ],
    "docker": [
        r"ubuntu",
        r"alpine",
        r"debian",
        r"centos",
        r"nginx",
        r"postgres",
        r"redis",
        r"mysql",
        r"python",
        r"node",
        r"java",
        r"test",
        r"debug",
        r"ci",
        r"/tmp",
        r"/workspace"
    ],
    "ide": [
        r"\.env\.example",
        r"\.key\.example",
        r"test\.pem",
        r"@.*\.vscode",
        r"com\.",
        r"ms-",
        r"localhost",
        r"127\.0\.0\.1",
        r":8080",
        r":3000",
        r":8000",
        r":9000",
        r":5000",
        r":4000"
    ],
    "cicd": [
        r"@.*\/.*",
        r"git\+",
        r"\*{3,}",
        r"\.sh",
        r"www-data",
        r"\/bin\/false",
        r"\/backup"
    ]
}


# Dashboard templates configuration
DASHBOARD_TEMPLATES = {
    "security-overview": {
        "name": "Vue d'ensemble Sécurité",
        "description": "Dashboard principal avec métriques de sécurité globales",
        "panels": ["Events timeline", "Rule distribution", "Top alerts", "Severity breakdown"],
        "use_case": "Monitoring quotidien de la sécurité",
        "integrations": ["Toutes"],
        "priority": "high"
    },
    "devsec-monitoring": {
        "name": "Monitoring DevSec",
        "description": "Dashboard spécialisé pour environnement de développement",
        "panels": ["Git activity", "IDE access", "CI/CD pipeline", "Docker security"],
        "use_case": "Surveillance des activités de développement",
        "integrations": ["Git", "IDE", "CI/CD", "Docker"],
        "priority": "high"
    },
    "threat-intelligence": {
        "name": "Threat Intelligence",
        "description": "Dashboard pour analyse des menaces et IOC",
        "panels": ["VirusTotal analysis", "Threat feeds", "IOC tracking", "Attribution"],
        "use_case": "Analyse des menaces et renseignement",
        "integrations": ["VirusTotal", "MISP", "TheHive"],
        "priority": "medium"
    },
    "compliance-reporting": {
        "name": "Rapports de Conformité",
        "description": "Dashboard pour reporting et conformité",
        "panels": ["Compliance score", "Audit trail", "Policy violations", "Risk assessment"],
        "use_case": "Reporting conformité et audit",
        "integrations": ["SCA", "Audit"],
        "priority": "medium"
    },
    "incident-response": {
        "name": "Response à Incident",
        "description": "Dashboard pour gestion des incidents",
        "panels": ["Incident timeline", "Alert correlation", "Response actions", "Post-mortem"],
        "use_case": "Gestion et analyse des incidents",
        "integrations": ["TheHive", "Active Response"],
        "priority": "medium"
    },
    "performance-monitoring": {
        "name": "Monitoring Performance",
        "description": "Dashboard pour performance Wazuh",
        "panels": ["Agent status", "Queue size", "Processing time", "Resource usage"],
        "use_case": "Monitoring infrastructure Wazuh",
        "integrations": ["Wazuh Manager", "Agents"],
        "priority": "low"
    }
}


# Integration configuration
INTEGRATIONS_CONFIG = {
    "virustotal": {
        "name": "VirusTotal",
        "description": "Analyse de fichiers et URLs via VirusTotal API",
        "required_fields": ["api_key"],
        "check_commands": ["vt"],
        "check_files": ["/usr/local/bin/vt"],
        "env_vars": ["VIRUSTOTAL_API_KEY"],
        "priority": "high"
    },
    "suricata": {
        "name": "Suricata",
        "description": "IDS/IPS pour détection d'intrusion réseau",
        "required_fields": ["config_path"],
        "check_commands": ["suricata"],
        "check_files": ["/usr/bin/suricata", "/usr/local/bin/suricata"],
        "check_services": ["suricata"],
        "priority": "high"
    },
    "elasticsearch": {
        "name": "Elasticsearch",
        "description": "Moteur de recherche et d'analyse pour logs",
        "required_fields": ["url", "port"],
        "check_commands": ["elasticsearch"],
        "check_files": ["/usr/share/elasticsearch"],
        "check_ports": [9200],
        "priority": "medium"
    },
    "thehive": {
        "name": "TheHive",
        "description": "Plateforme de réponse à incident",
        "required_fields": ["url", "api_key"],
        "check_commands": ["thehive"],
        "check_ports": [9000],
        "priority": "medium"
    },
    "misp": {
        "name": "MISP",
        "description": "Threat intelligence sharing platform",
        "required_fields": ["url", "api_key"],
        "check_commands": ["misp"],
        "check_ports": [80],
        "priority": "low"
    }
}


# File validation patterns
VALIDATION_PATTERNS = {
    "xml": {
        "required_elements": {
            "rule": ["id", "level", "description"],
            "decoder": ["name"],
            "command": ["name", "executable"]
        },
        "recommended_elements": {
            "rule": ["mitre", "group"],
            "decoder": ["prematch", "regex"]
        }
    },
    "cdb": {
        "format_pattern": r"^[^:]+:.*$",
        "encoding": "utf-8"
    },
    "json": {
        "required_fields": ["id", "title", "panels"],
        "recommended_fields": ["description", "version"]
    }
}


# Quality thresholds
QUALITY_THRESHOLDS = {
    "rule_score": {
        "excellent": 90,
        "good": 80,
        "fair": 70,
        "poor": 60
    },
    "false_positive_risk": {
        "acceptable_threshold": 0.3,  # Max 30% medium/high risk
        "critical_threshold": 0.1   # Max 10% high risk
    },
    "test_coverage": {
        "minimum": 0.8,  # 80% test coverage required
        "target": 0.95  # 95% test coverage target
    }
}


# Error messages and user feedback
ERROR_MESSAGES = {
    "file_not_found": "Fichier non trouvé: {path}",
    "invalid_format": "Format invalide: {error}",
    "permission_denied": "Permission refusée: {path}",
    "network_error": "Erreur réseau: {error}",
    "integration_missing": "Intégration {name} non installée",
    "validation_failed": "Validation échouée: {details}",
    "generation_failed": "Génération échouée: {error}"
}


SUCCESS_MESSAGES = {
    "configuration_generated": "Configuration générée avec succès: {path}",
    "rules_validated": "Règles validées: {count} règles",
    "integration_configured": "Intégration {name} configurée avec succès",
    "dashboard_injected": "Dashboard {name} injecté avec succès",
    "tests_passed": "Tests réussis: {passed}/{total}",
    "deployment_complete": "Déploiement complété avec succès"
}


# Default configuration values
DEFAULT_CONFIG = {
    "output_directory": "output/wazuh-custom-devsec",
    "log_level": "INFO",
    "max_file_size": 1048576,  # 1MB
    "timeout": 30,  # seconds
    "retry_attempts": 3,
    "parallel_processing": True,
    "simulation_mode": False
}
