"""
Dashboard template generator for Wazuh
"""
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from .config import WazuhProfile, IntegrationType


class DashboardGenerator:
    """Generate dashboard templates for Wazuh"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.dashboard_dir = output_dir / "dashboards"
        self.dashboard_dir.mkdir(parents=True, exist_ok=True)
    
    def get_available_templates(self) -> Dict[str, Dict[str, Any]]:
        """Get available dashboard templates"""
        return {
            "security-overview": {
                "name": "Security Overview",
                "description": "Main security dashboard with overview metrics",
                "panels": 8
            },
            "devsec-monitoring": {
                "name": "DevSec Monitoring",
                "description": "Development security monitoring dashboard",
                "panels": 6
            },
            "threat-intelligence": {
                "name": "Threat Intelligence",
                "description": "Threat intelligence and IOC monitoring",
                "panels": 10
            },
            "compliance-reporting": {
                "name": "Compliance Reporting",
                "description": "Compliance and audit reporting dashboard",
                "panels": 12
            },
            "incident-response": {
                "name": "Incident Response",
                "description": "Security incident response workflow",
                "panels": 8
            },
            "performance-monitoring": {
                "name": "Performance Monitoring",
                "description": "Wazuh system performance metrics",
                "panels": 6
            }
        }
    
    def generate_dashboard(self, template_id: str) -> Dict[str, Any]:
        """Generate a specific dashboard template"""
        templates = self.get_available_templates()
        
        if template_id not in templates:
            raise ValueError(f"Unknown template: {template_id}")
        
        template_info = templates[template_id]
        
        # Generate basic dashboard structure
        dashboard = {
            "id": template_id,
            "title": template_info["name"],
            "description": template_info["description"],
            "panels": self._generate_panels_for_template(template_id),
            "created_at": datetime.now().isoformat(),
            "version": "1.0"
        }
        
        return dashboard
    
    def _generate_panels_for_template(self, template_id: str) -> List[Dict[str, Any]]:
        """Generate panels for specific template"""
        panel_configs = {
            "security-overview": [
                {"id": "panel1", "title": "Security Events", "type": "table"},
                {"id": "panel2", "title": "Alert Level Distribution", "type": "pie"},
                {"id": "panel3", "title": "Top Rules", "type": "bar"},
                {"id": "panel4", "title": "Agent Status", "type": "stat"}
            ],
            "devsec-monitoring": [
                {"id": "panel1", "title": "Code Security", "type": "table"},
                {"id": "panel2", "title": "Container Security", "type": "table"},
                {"id": "panel3", "title": "Build Security", "type": "bar"}
            ],
            "threat-intelligence": [
                {"id": "panel1", "title": "IOC Detection", "type": "table"},
                {"id": "panel2", "title": "Threat Sources", "type": "pie"},
                {"id": "panel3", "title": "Malware Analysis", "type": "table"}
            ]
        }
        
        return panel_configs.get(template_id, [
            {"id": "panel1", "title": "Default Panel", "type": "table"}
        ])
    
    def generate_import_script(self, dashboards: Dict[str, Any]) -> None:
        """Generate import script for dashboards"""
        script_content = """#!/bin/bash
# Wazuh Dashboard Import Script
"""

        for dashboard_id, dashboard in dashboards.items():
            script_content += f"""
# Import {dashboard['title']}
echo "Importing {dashboard['title']}..."
# curl -X POST "http://localhost:5601/api/saved_objects/_import" \\
#   -H "kbn-xsrf: true" \\
#   -H "Content-Type: application/json" \\
#   -d @dashboards/{dashboard_id}.json
"""

        script_path = self.output_dir / "import_dashboards.sh"
        script_path.write_text(script_content)
        script_path.chmod(0o755)
    
    def generate_all_dashboards(self, profile: WazuhProfile) -> Dict[str, str]:
        """Generate all dashboard templates for a profile"""
        dashboards = {}
        
        # Main overview dashboard
        dashboards["overview"] = self.generate_overview_dashboard(profile)
        
        # Integration-specific dashboards
        for integration in profile.integrations:
            if integration == IntegrationType.VIRUSTOTAL:
                dashboards["virustotal"] = self.generate_virustotal_dashboard()
            elif integration == IntegrationType.SURICATA:
                dashboards["suricata"] = self.generate_suricata_dashboard()
            elif integration == IntegrationType.ELASTICSEARCH:
                dashboards["elasticsearch"] = self.generate_elasticsearch_dashboard()
        
        # Rule-specific dashboards
        for rule_theme in profile.rules_enabled:
            dashboards[f"rules_{rule_theme}"] = self.generate_rules_dashboard(rule_theme)
        
        return dashboards
    
    def generate_overview_dashboard(self, profile: WazuhProfile) -> str:
        """Generate main overview dashboard"""
        dashboard = {
            "id": f"wazuh-devsec-{profile.name.lower()}-overview",
            "title": f"Wazuh DevSec Overview - {profile.name}",
            "description": f"Overview dashboard for {profile.description}",
            "panels": [
                {
                    "id": "events-overview",
                    "title": "Security Events Overview",
                    "type": "visualization",
                    "grid": {"x": 0, "y": 0, "w": 24, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "timerange": "last 24h"
                    }
                },
                {
                    "id": "rule-distribution",
                    "title": "Rule Distribution",
                    "type": "pie",
                    "grid": {"x": 24, "y": 0, "w": 12, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "aggregation": "terms",
                        "field": "rule.name"
                    }
                },
                {
                    "id": "severity-timeline",
                    "title": "Severity Timeline",
                    "type": "line",
                    "grid": {"x": 36, "y": 0, "w": 12, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "timerange": "last 24h",
                        "aggregation": "date_histogram"
                    }
                },
                {
                    "id": "top-sources",
                    "title": "Top Alert Sources",
                    "type": "table",
                    "grid": {"x": 0, "y": 15, "w": 18, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "aggregation": "terms",
                        "field": "agent.name"
                    }
                },
                {
                    "id": "integration-status",
                    "title": "Integration Status",
                    "type": "metric",
                    "grid": {"x": 18, "y": 15, "w": 12, "h": 12},
                    "metrics": [
                        {"label": "VirusTotal", "query": "virustotal"},
                        {"label": "Suricata", "query": "suricata"},
                        {"label": "Elasticsearch", "query": "elasticsearch"}
                    ]
                },
                {
                    "id": "mitre-coverage",
                    "title": "MITRE ATT&CK Coverage",
                    "type": "heatmap",
                    "grid": {"x": 30, "y": 15, "w": 18, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "aggregation": "terms",
                        "fields": ["rule.mitre_technique", "rule.mitre_tactic"]
                    }
                }
            ],
            "integrations": [it.value if hasattr(it, 'value') else str(it) for it in profile.integrations],
            "rules": profile.rules_enabled,
            "created": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        filename = f"{profile.name}_overview.json"
        filepath = self.dashboard_dir / filename
        with open(filepath, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return str(filepath)
    
    def generate_virustotal_dashboard(self) -> str:
        """Generate VirusTotal-specific dashboard"""
        dashboard = {
            "id": "wazuh-devsec-virustotal",
            "title": "VirusTotal Analysis Dashboard",
            "description": "VirusTotal integration analysis and monitoring",
            "panels": [
                {
                    "id": "vt-scans-overview",
                    "title": "VirusTotal Scans Overview",
                    "type": "visualization",
                    "grid": {"x": 0, "y": 0, "w": 24, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "virustotal"}],
                        "timerange": "last 24h"
                    }
                },
                {
                    "id": "malicious-detections",
                    "title": "Malicious File Detections",
                    "type": "metric",
                    "grid": {"x": 24, "y": 0, "w": 12, "h": 8},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [
                            {"rule.category": "virustotal"},
                            {"virustotal.result": "malicious"}
                        ]
                    }
                },
                {
                    "id": "suspicious-detections",
                    "title": "Suspicious File Detections",
                    "type": "metric",
                    "grid": {"x": 36, "y": 0, "w": 12, "h": 8},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [
                            {"rule.category": "virustotal"},
                            {"virustotal.result": "suspicious"}
                        ]
                    }
                },
                {
                    "id": "file-types-analysis",
                    "title": "File Types Analysis",
                    "type": "pie",
                    "grid": {"x": 24, "y": 8, "w": 12, "h": 7},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "virustotal"}],
                        "aggregation": "terms",
                        "field": "virustotal.file_type"
                    }
                },
                {
                    "id": "top-malicious-files",
                    "title": "Top Malicious Files",
                    "type": "table",
                    "grid": {"x": 36, "y": 8, "w": 12, "h": 7},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [
                            {"rule.category": "virustotal"},
                            {"virustotal.result": "malicious"}
                        ],
                        "aggregation": "terms",
                        "field": "virustotal.file_hash"
                    }
                },
                {
                    "id": "vt-alert-timeline",
                    "title": "VirusTotal Alert Timeline",
                    "type": "line",
                    "grid": {"x": 0, "y": 15, "w": 48, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "virustotal"}],
                        "timerange": "last 7d",
                        "aggregation": "date_histogram"
                    }
                }
            ],
            "created": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        filename = "virustotal_dashboard.json"
        filepath = self.dashboard_dir / filename
        with open(filepath, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return str(filepath)
    
    def generate_suricata_dashboard(self) -> str:
        """Generate Suricata-specific dashboard"""
        dashboard = {
            "id": "wazuh-devsec-suricata",
            "title": "Suricata IDS Dashboard",
            "description": "Suricata intrusion detection system monitoring",
            "panels": [
                {
                    "id": "suricata-alerts-overview",
                    "title": "Suricata Alerts Overview",
                    "type": "visualization",
                    "grid": {"x": 0, "y": 0, "w": 32, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "timerange": "last 24h"
                    }
                },
                {
                    "id": "alert-severity",
                    "title": "Alert Severity Distribution",
                    "type": "pie",
                    "grid": {"x": 32, "y": 0, "w": 16, "h": 8},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "aggregation": "terms",
                        "field": "rule.level"
                    }
                },
                {
                    "id": "top-attack-types",
                    "title": "Top Attack Types",
                    "type": "bar",
                    "grid": {"x": 32, "y": 8, "w": 16, "h": 7},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "aggregation": "terms",
                        "field": "suricata.alert.signature"
                    }
                },
                {
                    "id": "source-ips",
                    "title": "Top Source IPs",
                    "type": "table",
                    "grid": {"x": 0, "y": 15, "w": 24, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "aggregation": "terms",
                        "field": "srcip"
                    }
                },
                {
                    "id": "destinations",
                    "title": "Top Destination Ports",
                    "type": "table",
                    "grid": {"x": 24, "y": 15, "w": 24, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "aggregation": "terms",
                        "field": "dstport"
                    }
                },
                {
                    "id": "suricata-timeline",
                    "title": "Suricata Alert Timeline",
                    "type": "line",
                    "grid": {"x": 0, "y": 27, "w": 48, "h": 10},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.category": "suricata"}],
                        "timerange": "last 7d",
                        "aggregation": "date_histogram"
                    }
                }
            ],
            "created": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        filename = "suricata_dashboard.json"
        filepath = self.dashboard_dir / filename
        with open(filepath, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return str(filepath)
    
    def generate_elasticsearch_dashboard(self) -> str:
        """Generate Elasticsearch-specific dashboard"""
        dashboard = {
            "id": "wazuh-devsec-elasticsearch",
            "title": "Elasticsearch Monitoring Dashboard",
            "description": "Elasticsearch cluster and query monitoring",
            "panels": [
                {
                    "id": "es-cluster-status",
                    "title": "Cluster Status",
                    "type": "metric",
                    "grid": {"x": 0, "y": 0, "w": 12, "h": 8},
                    "query": {
                        "index": ".monitoring-es-*",
                        "metric": "cluster.status"
                    }
                },
                {
                    "id": "es-index-size",
                    "title": "Index Size Overview",
                    "type": "bar",
                    "grid": {"x": 12, "y": 0, "w": 18, "h": 8},
                    "query": {
                        "index": ".monitoring-es-*",
                        "aggregation": "terms",
                        "field": "index.name"
                    }
                },
                {
                    "id": "es-query-performance",
                    "title": "Query Performance",
                    "type": "line",
                    "grid": {"x": 30, "y": 0, "w": 18, "h": 8},
                    "query": {
                        "index": ".monitoring-es-*",
                        "timerange": "last 24h",
                        "aggregation": "avg",
                        "field": "index.search.query_total"
                    }
                },
                {
                    "id": "es-wazuh-alerts",
                    "title": "Wazuh Alerts in Elasticsearch",
                    "type": "visualization",
                    "grid": {"x": 0, "y": 8, "w": 48, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "timerange": "last 24h"
                    }
                },
                {
                    "id": "es-field-mapping",
                    "title": "Field Mapping Analysis",
                    "type": "table",
                    "grid": {"x": 0, "y": 23, "w": 24, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "aggregation": "terms",
                        "field": "_source"
                    }
                },
                {
                    "id": "es-storage-usage",
                    "title": "Storage Usage",
                    "type": "pie",
                    "grid": {"x": 24, "y": 23, "w": 24, "h": 12},
                    "query": {
                        "index": ".monitoring-es-*",
                        "aggregation": "terms",
                        "field": "node.store.size"
                    }
                }
            ],
            "created": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        filename = "elasticsearch_dashboard.json"
        filepath = self.dashboard_dir / filename
        with open(filepath, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return str(filepath)
    
    def generate_rules_dashboard(self, rule_theme: str) -> str:
        """Generate rule-specific dashboard"""
        dashboard = {
            "id": f"wazuh-devsec-rules-{rule_theme}",
            "title": f"{rule_theme.title()} Rules Dashboard",
            "description": f"Monitoring for {rule_theme} security rules",
            "panels": [
                {
                    "id": f"{rule_theme}-alerts-overview",
                    "title": f"{rule_theme.title()} Alerts Overview",
                    "type": "visualization",
                    "grid": {"x": 0, "y": 0, "w": 32, "h": 15},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.group": f"devsec,{rule_theme}"}],
                        "timerange": "last 24h"
                    }
                },
                {
                    "id": f"{rule_theme}-severity-distribution",
                    "title": "Severity Distribution",
                    "type": "pie",
                    "grid": {"x": 32, "y": 0, "w": 16, "h": 8},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.group": f"devsec,{rule_theme}"}],
                        "aggregation": "terms",
                        "field": "rule.level"
                    }
                },
                {
                    "id": f"{rule_theme}-top-agents",
                    "title": "Top Alert Sources",
                    "type": "table",
                    "grid": {"x": 32, "y": 8, "w": 16, "h": 7},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.group": f"devsec,{rule_theme}"}],
                        "aggregation": "terms",
                        "field": "agent.name"
                    }
                },
                {
                    "id": f"{rule_theme}-timeline",
                    "title": f"{rule_theme.title()} Alert Timeline",
                    "type": "line",
                    "grid": {"x": 0, "y": 15, "w": 48, "h": 12},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.group": f"devsec,{rule_theme}"}],
                        "timerange": "last 7d",
                        "aggregation": "date_histogram"
                    }
                },
                {
                    "id": f"{rule_theme}-mitre-techniques",
                    "title": "MITRE Techniques",
                    "type": "heatmap",
                    "grid": {"x": 0, "y": 27, "w": 48, "h": 10},
                    "query": {
                        "index": "wazuh-alerts-*",
                        "filters": [{"rule.group": f"devsec,{rule_theme}"}],
                        "aggregation": "terms",
                        "field": "rule.mitre_technique"
                    }
                }
            ],
            "rule_theme": rule_theme,
            "created": datetime.now().isoformat(),
            "version": "1.0.0"
        }
        
        filename = f"rules_{rule_theme}_dashboard.json"
        filepath = self.dashboard_dir / filename
        with open(filepath, 'w') as f:
            json.dump(dashboard, f, indent=2)
        
        return str(filepath)
    
    def generate_kibana_import_script(self, dashboards: Dict[str, str]) -> str:
        """Generate Kibana import script for dashboards"""
        script_content = f"""#!/bin/bash
# Kibana Dashboard Import Script
# Generated on {datetime.now().isoformat()}

KIBANA_URL="http://localhost:5601"
DASHBOARD_DIR="{self.dashboard_dir}"

echo "Importing Wazuh DevSec dashboards to Kibana..."

"""
        
        for dashboard_name, dashboard_path in dashboards.items():
            script_content += f"""
# Import {dashboard_name} dashboard
echo "Importing {dashboard_name}..."
curl -X POST "$KIBANA_URL/api/saved_objects/_import" \\
    -H "kbn-xsrf: true" \\
    -H "Content-Type: application/json" \\
    --form file=@"{dashboard_path}" \\
    --form overwrite=true

"""
        
        script_content += """
echo "Dashboard import completed!"
echo "Visit $KIBANA_URL/app/dashboards to view your dashboards"
"""
        
        script_path = self.output_dir / "import_dashboards.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Make script executable
        script_path.chmod(0o755)
        
        return str(script_path)
