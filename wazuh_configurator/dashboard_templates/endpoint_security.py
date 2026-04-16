"""
Endpoint Security Dashboard
Dashboard spécialisé pour la sécurité des endpoints et des postes de travail
"""

ENDPOINT_SECURITY_DASHBOARD = {
    "id": "endpoint-security-dashboard",
    "title": "Endpoint Security",
    "description": "Surveillance de la sécurité des endpoints et postes de travail",
    "visualizations": [
        {
            "id": "endpoint-file-integrity",
            "type": "table",
            "title": "Alertes d'Intégrité de Fichiers",
            "description": "Modifications de fichiers sensibles détectées",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: syscheck",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 50
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-process-monitoring",
            "type": "table",
            "title": "Activité des Processus",
            "description": "Exécution de processus surveillée",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: process AND data.program.name: *",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 40
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-rootkit-detection",
            "type": "table",
            "title": "Détection de Rootkits",
            "description": "Alertes de détection de rootkits",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: rootcheck",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 30
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-agent-status",
            "type": "table",
            "title": "État des Agents",
            "description": "Statut de connectivité des agents Wazuh",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: agent",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 50}
                }
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 1, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-malware-detection",
            "type": "table",
            "title": "Détection de Malwares",
            "description": "Alertes liées à des menaces malveillantes",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: malware OR data.virustotal.found: true",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 30
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-sca-findings",
            "type": "table",
            "title": "Résultats SCA par Agent",
            "description": "Vérifications de configuration de sécurité",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: sca",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 30}
                }
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 1, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-network-activity",
            "type": "table",
            "title": "Activité Réseau par Endpoint",
            "description": "Connexions réseau par agent",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: network AND agent.name: *",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 30}
                }
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 1, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-software-inventory",
            "type": "table",
            "title": "Inventaire Logiciel",
            "description": "Logiciels installés sur les endpoints",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: inventory AND data.program.name: *",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 30}
                }
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 1, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-policy-violations",
            "type": "table",
            "title": "Violations de Politique",
            "description": "Alertes de non-conformité aux politiques",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: policy",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 30
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        },
        {
            "id": "endpoint-vulnerability-impact",
            "type": "bar",
            "title": "Impact de Vulnérabilités par Endpoint",
            "description": "Endpoints les plus affectés par les vulnérabilités",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: vulnerability",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 20}
                }
            },
            "attributes": {
                "visState": {
                    "type": "histogram",
                    "params": {
                        "grid": {"categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left"}]},
                        "seriesParams": [{"mode": "normal", "type": "bar"}]
                    }
                }
            }
        },
        {
            "id": "endpoint-remote-access",
            "type": "table",
            "title": "Accès à Distance",
            "description": "Activités d'accès distant (RDP, SSH, etc.)",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: remote OR rule.groups: rdp OR rule.groups: ssh",
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": 30
            },
            "attributes": {
                "visState": {
                    "type": "table",
                    "params": {
                        "sort": {"columnIndex": 0, "direction": "desc"}
                    }
                }
            }
        }
    ],
    "layout": {
        "rows": [
            {
                "title": "Endpoint Monitoring",
                "panels": [
                    {"id": "endpoint-agent-status", "col": 1, "row": 1, "size_x": 6, "size_y": 3},
                    {"id": "endpoint-vulnerability-impact", "col": 7, "row": 1, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Security Events",
                "panels": [
                    {"id": "endpoint-file-integrity", "col": 1, "row": 4, "size_x": 6, "size_y": 3},
                    {"id": "endpoint-process-monitoring", "col": 7, "row": 4, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Threat Detection",
                "panels": [
                    {"id": "endpoint-malware-detection", "col": 1, "row": 7, "size_x": 4, "size_y": 3},
                    {"id": "endpoint-rootkit-detection", "col": 5, "row": 7, "size_y": 3},
                    {"id": "endpoint-remote-access", "col": 9, "row": 7, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Compliance & Inventory",
                "panels": [
                    {"id": "endpoint-sca-findings", "col": 1, "row": 10, "size_x": 4, "size_y": 3},
                    {"id": "endpoint-software-inventory", "col": 5, "row": 10, "size_x": 4, "size_y": 3},
                    {"id": "endpoint-policy-violations", "col": 9, "row": 10, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Network Activity",
                "panels": [
                    {"id": "endpoint-network-activity", "col": 1, "row": 13, "size_x": 12, "size_y": 3}
                ]
            }
        ]
    }
}
