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
            "attributes": {
                "title": "Connexions SSH par heure (24h)",
                "visState": {
                    "title": "Connexions SSH par heure (24h)",
                    "type": "line",
                    "params": {
                        "grid": {"categoryLines": False},
                        "categoryAxes": [{
                            "id": "CategoryAxis-1",
                            "type": "category",
                            "position": "bottom",
                            "show": True,
                            "style": {},
                            "scale": {"type": "linear"},
                            "labels": {"show": True, "filter": True, "truncate": 100},
                            "title": {"text": "Heure"}
                        }],
                        "valueAxes": [{
                            "id": "ValueAxis-1",
                            "name": "LeftAxis-1",
                            "type": "value",
                            "position": "left",
                            "show": True,
                            "style": {},
                            "scale": {"type": "linear", "mode": "normal"},
                            "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                            "title": {"text": "Nombre"}
                        }],
                        "seriesParams": [{
                            "show": True,
                            "type": "line",
                            "mode": "normal",
                            "data": {"label": "Count", "id": "1"},
                            "valueAxis": "ValueAxis-1",
                            "drawLinesBetweenPoints": True,
                            "lineWidth": 2,
                            "showCircles": True
                        }],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right"
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"rule.groups:sshd\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-24h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "ssh-users-pie",
            "type": "pie",
            "title": "Connexions SSH par utilisateur",
            "description": "Distribution des utilisateurs de SSH",
            "attributes": {
                "title": "Connexions SSH par utilisateur",
                "visState": {
                    "title": "Connexions SSH par utilisateur",
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": True,
                        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"rule.groups:sshd AND data.eventtype:logged_in\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"data.dstuser\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "ssh-source-ips",
            "type": "table",
            "title": "Top 20 IP sources de connexions SSH",
            "description": "IPs les plus actives pour les connexions SSH",
            "attributes": {
                "title": "Top 20 IP sources de connexions SSH",
                "visState": {
                    "title": "Top 20 IP sources de connexions SSH",
                    "type": "table",
                    "params": {
                        "perPage": 20,
                        "showPartialRows": False,
                        "showMetricsAtAllLevels": False,
                        "sort": {"columnIndex": None, "direction": "desc"},
                        "showTotal": True,
                        "totalFunc": "sum"
                    },
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {
                            "field": "data.srcip",
                            "orderBy": "1",
                            "order": "desc",
                            "size": 20,
                            "otherBucket": False,
                            "missingBucket": False
                        }, "schema": "bucket"}
                    ]
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"rule.groups:sshd AND data.eventtype:logged_in\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"data.srcip\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":20,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"bucket\"}]}"
                }
            }
        },
        {
            "id": "ssh-recent-logins",
            "type": "table",
            "title": "Connexions SSH récentes (Dernières 50)",
            "description": "Liste des connexions SSH les plus récentes",
            "attributes": {
                "title": "Connexions SSH récentes (Dernières 50)",
                "visState": {
                    "title": "Connexions SSH récentes (Dernières 50)",
                    "type": "table",
                    "params": {
                        "perPage": 50,
                        "showPartialRows": False,
                        "showMetricsAtAllLevels": False,
                        "sort": {"columnIndex": None, "direction": "desc"},
                        "showTotal": False,
                        "totalFunc": "sum"
                    },
                    "aggs": []
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"rule.groups:sshd AND data.eventtype:logged_in\",\"language\":\"lucene\"},\"filter\":[],\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"size\":50}"
                }
            }
        }
    ],
    "layout": {
        "panels": [
            {"id": "ssh-connections-timeline", "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"}, "version": "2.19.4", "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_0"},
            {"id": "ssh-users-pie", "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "2"}, "version": "2.19.4", "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_1"},
            {"id": "ssh-source-ips", "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "3"}, "version": "2.19.4", "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_2"},
            {"id": "ssh-recent-logins", "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "4"}, "version": "2.19.4", "panelIndex": "4", "embeddableConfig": {}, "panelRefName": "panel_3"}
        ]
    }
}
