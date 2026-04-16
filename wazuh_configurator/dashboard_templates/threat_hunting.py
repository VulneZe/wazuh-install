"""
Threat Hunting Dashboard
Dashboard avancé pour le threat hunting et l'analyse de menaces
"""

THREAT_HUNTING_DASHBOARD = {
    "id": "threat-hunting-dashboard",
    "title": "Threat Hunting",
    "description": "Dashboard avancé pour la recherche de menaces et l'analyse comportementale",
    "visualizations": [
        {
            "id": "hunting-high-severity",
            "type": "table",
            "title": "Alertes de haute sévérité (Niveau 10+)",
            "description": "Alertes critiques nécessitant une attention immédiate",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.level: >=10",
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
            "id": "hunting-mitre-techniques",
            "type": "bar",
            "title": "Alertes par technique MITRE ATT&CK",
            "description": "Distribution des alertes par technique MITRE",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "rule.mitre.technique", "size": 20}
                }
            },
            "attributes": {
                "visState": {
                    "type": "histogram",
                    "params": {
                        "grid": {"categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}]},
                        "seriesParams": [{"mode": "normal", "type": "bar"}]
                    }
                }
            }
        },
        {
            "id": "hunting-behavioral-anomalies",
            "type": "table",
            "title": "Anomalies comportementales détectées",
            "description": "Comportements suspects ou anormaux",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: anomaly OR rule.groups: behavioral",
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
            "id": "hunting-file-integrity",
            "type": "table",
            "title": "Alertes d'intégrité de fichiers",
            "description": "Modifications de fichiers sensibles détectées",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: syscheck",
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
            "id": "hunting-lateral-movement",
            "type": "table",
            "title": "Signes de mouvement latéral",
            "description": "Activités suggérant un mouvement latéral sur le réseau",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: lateral_movement OR rule.mitre.tactic: lateral-movement",
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
            "id": "hunting-malware-indicators",
            "type": "table",
            "title": "Indicateurs de malwares",
            "description": "Alertes liées à des indicateurs de compromission ou malwares",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: malware OR data.virustotal.found: true OR data.virustotal.positives: >0",
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
            "id": "hunting-unknown-processes",
            "type": "table",
            "title": "Processus inconnus ou suspects",
            "description": "Exécution de processus non reconnus ou suspects",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: process AND data.program.name: *",
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
            "id": "hunting-network-connections",
            "type": "table",
            "title": "Connexions réseau suspectes",
            "description": "Connexions réseau vers des destinations inconnues ou suspectes",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: network AND data.dstport: *",
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
            "id": "hunting-persistence",
            "type": "table",
            "title": "Signes de persistance",
            "description": "Activités suggérant une persistance malveillante",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: persistence OR rule.mitre.tactic: persistence",
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
            "id": "hunting-command-execution",
            "type": "table",
            "title": "Exécution de commandes suspectes",
            "description": "Commandes shell ou PowerShell exécutées récemment",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: command AND data.shell: *",
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
            "id": "hunting-timeline-attacks",
            "type": "line",
            "title": "Timeline des attaques détectées",
            "description": "Évolution des alertes de haute sévérité dans le temps",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.level: >=7",
                "time_field": "@timestamp",
                "interval": "1h"
            },
            "attributes": {
                "visState": {
                    "type": "line",
                    "params": {
                        "grid": {"categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom"}]},
                        "seriesParams": [{"show": "true", "type": "line", "mode": "normal"}]
                    }
                }
            }
        }
    ],
    "layout": {
        "rows": [
            {
                "title": "Critical Alerts",
                "panels": [
                    {"id": "hunting-high-severity", "col": 1, "row": 1, "size_x": 12, "size_y": 4}
                ]
            },
            {
                "title": "MITRE ATT&CK Analysis",
                "panels": [
                    {"id": "hunting-mitre-techniques", "col": 1, "row": 5, "size_x": 6, "size_y": 3},
                    {"id": "hunting-timeline-attacks", "col": 7, "row": 5, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Threat Indicators",
                "panels": [
                    {"id": "hunting-behavioral-anomalies", "col": 1, "row": 8, "size_x": 4, "size_y": 3},
                    {"id": "hunting-file-integrity", "col": 5, "row": 8, "size_x": 4, "size_y": 3},
                    {"id": "hunting-lateral-movement", "col": 9, "row": 8, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Malware & Persistence",
                "panels": [
                    {"id": "hunting-malware-indicators", "col": 1, "row": 11, "size_x": 4, "size_y": 3},
                    {"id": "hunting-unknown-processes", "col": 5, "row": 11, "size_x": 4, "size_y": 3},
                    {"id": "hunting-persistence", "col": 9, "row": 11, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Network & Command Activity",
                "panels": [
                    {"id": "hunting-network-connections", "col": 1, "row": 14, "size_x": 6, "size_y": 3},
                    {"id": "hunting-command-execution", "col": 7, "row": 14, "size_x": 6, "size_y": 3}
                ]
            }
        ]
    }
}
