"""
SSH/Auth Monitoring Dashboard
Dashboard spécialisé pour le monitoring des connexions SSH et des événements d'authentification
"""

SSH_AUTH_MONITORING_DASHBOARD = {
    "id": "ssh-auth-monitoring-dashboard",
    "title": "SSH & Authentication Monitoring",
    "description": "Monitoring des connexions SSH, authentifications et accès système",
    "visualizations": [
        {
            "id": "ssh-connections-timeline",
            "type": "line",
            "title": "Connexions SSH par heure (24h)",
            "description": "Tendance des connexions SSH sur les dernières 24 heures",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: logged_in",
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
        },
        {
            "id": "ssh-users-pie",
            "type": "pie",
            "title": "Connexions SSH par utilisateur",
            "description": "Distribution des utilisateurs de SSH",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: logged_in",
                "aggs": {
                    "terms": {"field": "data.dstuser", "size": 20}
                }
            },
            "attributes": {
                "visState": {
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "isDonut": True,
                        "legendPosition": "right"
                    }
                }
            }
        },
        {
            "id": "ssh-source-ips",
            "type": "table",
            "title": "Top 20 IP sources de connexions SSH",
            "description": "IPs les plus actives pour les connexions SSH",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: logged_in",
                "aggs": {
                    "terms": {"field": "data.srcip", "size": 20}
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
            "id": "ssh-failed-logins",
            "type": "bar",
            "title": "Tentatives de connexion échouées par IP",
            "description": "IPs avec le plus d'échecs de connexion SSH",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: failed_login",
                "aggs": {
                    "terms": {"field": "data.srcip", "size": 20}
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
            "id": "auth-failures-timeline",
            "type": "line",
            "title": "Échecs d'authentification par heure",
            "description": "Tendance des échecs d'authentification système",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: authentication AND data.eventtype: failed_login",
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
        },
        {
            "id": "ssh-geo-map",
            "type": "metric",
            "title": "Connexions SSH par pays",
            "description": "Distribution géographique des connexions SSH",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: logged_in",
                "aggs": {
                    "terms": {"field": "data.srcipgeo.country_name", "size": 20}
                }
            },
            "attributes": {
                "visState": {
                    "type": "metric",
                    "params": {
                        "metric": "count"
                    }
                }
            }
        },
        {
            "id": "ssh-recent-logins",
            "type": "table",
            "title": "Connexions SSH récentes (Dernières 50)",
            "description": "Liste des connexions SSH les plus récentes",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: ssh AND data.eventtype: logged_in",
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
            "id": "sudo-usage",
            "type": "table",
            "title": "Commandes sudo récents",
            "description": "Surveillance des commandes sudo exécutées",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: sudo",
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
            "id": "privilege-escalation",
            "type": "bar",
            "title": "Alertes d'escalation de privilèges",
            "description": "Tentatives d'escalation de privilèges détectées",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: privilege_escalation",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 15}
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
            "id": "root-logins",
            "type": "table",
            "title": "Connexions root récentes",
            "description": "Surveillance des connexions utilisateur root",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "data.dstuser: root AND rule.groups: authentication",
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
                "title": "SSH Connection Overview",
                "panels": [
                    {"id": "ssh-connections-timeline", "col": 1, "row": 1, "size_x": 8, "size_y": 3},
                    {"id": "ssh-users-pie", "col": 9, "row": 1, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "SSH Access Analysis",
                "panels": [
                    {"id": "ssh-source-ips", "col": 1, "row": 4, "size_x": 6, "size_y": 3},
                    {"id": "ssh-failed-logins", "col": 7, "row": 4, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Authentication Monitoring",
                "panels": [
                    {"id": "auth-failures-timeline", "col": 1, "row": 7, "size_x": 6, "size_y": 3},
                    {"id": "sudo-usage", "col": 7, "row": 7, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Security Events",
                "panels": [
                    {"id": "ssh-geo-map", "col": 1, "row": 10, "size_x": 4, "size_y": 3},
                    {"id": "privilege-escalation", "col": 5, "row": 10, "size_x": 4, "size_y": 3},
                    {"id": "root-logins", "col": 9, "row": 10, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Recent SSH Activity",
                "panels": [
                    {"id": "ssh-recent-logins", "col": 1, "row": 13, "size_x": 12, "size_y": 4}
                ]
            }
        ]
    }
}
