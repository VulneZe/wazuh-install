"""
SOC Overview Dashboard
Dashboard principal pour les analystes SOC avec vue d'ensemble des alertes et de l'état de sécurité
"""

SOC_OVERVIEW_DASHBOARD = {
    "id": "soc-overview-dashboard",
    "title": "SOC Overview",
    "description": "Vue d'ensemble des alertes de sécurité et de l'état du SOC",
    "visualizations": [
        {
            "id": "soc-alerts-timeline",
            "type": "line",
            "title": "Alertes par heure (24h)",
            "description": "Tendance des alertes sur les dernières 24 heures",
            "query": {
                "index": "wazuh-alerts-*",
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
            "id": "soc-alerts-level",
            "type": "pie",
            "title": "Alertes par niveau de sévérité",
            "description": "Distribution des alertes par niveau (0-15)",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "rule.level", "size": 16}
                }
            },
            "attributes": {
                "visState": {
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "isDonut": False,
                        "legendPosition": "right"
                    }
                }
            }
        },
        {
            "id": "soc-top-agents",
            "type": "bar",
            "title": "Top 10 Agents par nombre d'alertes",
            "description": "Agents générant le plus d'alertes",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "agent.name", "size": 10}
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
            "id": "soc-top-rules",
            "type": "table",
            "title": "Top 10 Règles les plus déclenchées",
            "description": "Règles de détection les plus actives",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "rule.description", "size": 10}
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
            "id": "soc-alerts-geo",
            "type": "metric",
            "title": "Alertes par pays (Source IP)",
            "description": "Distribution géographique des IP source",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "data.srcipgeo.country_code2", "size": 20}
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
            "id": "soc-recent-alerts",
            "type": "table",
            "title": "Alertes récentes (Dernières 50)",
            "description": "Liste des alertes les plus récentes",
            "query": {
                "index": "wazuh-alerts-*",
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
            "id": "soc-rule-groups",
            "type": "pie",
            "title": "Alertes par groupe de règles",
            "description": "Distribution des alertes par catégorie de règles",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "rule.groups", "size": 15}
                }
            },
            "attributes": {
                "visState": {
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "isDonut": True,
                        "legendPosition": "bottom"
                    }
                }
            }
        },
        {
            "id": "soc-mitre-tactics",
            "type": "bar",
            "title": "Alertes par tactique MITRE ATT&CK",
            "description": "Distribution des alertes par tactique MITRE",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "terms": {"field": "rule.mitre.tactic", "size": 15}
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
        }
    ],
    "layout": {
        "rows": [
            {
                "title": "Alertes Overview",
                "panels": [
                    {"id": "soc-alerts-timeline", "col": 1, "row": 1, "size_x": 6, "size_y": 3},
                    {"id": "soc-alerts-level", "col": 7, "row": 1, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Top Alert Sources",
                "panels": [
                    {"id": "soc-top-agents", "col": 1, "row": 4, "size_x": 6, "size_y": 3},
                    {"id": "soc-top-rules", "col": 7, "row": 4, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Alert Analysis",
                "panels": [
                    {"id": "soc-rule-groups", "col": 1, "row": 7, "size_x": 4, "size_y": 3},
                    {"id": "soc-mitre-tactics", "col": 5, "row": 7, "size_x": 4, "size_y": 3},
                    {"id": "soc-alerts-geo", "col": 9, "row": 7, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Recent Alerts",
                "panels": [
                    {"id": "soc-recent-alerts", "col": 1, "row": 10, "size_x": 12, "size_y": 4}
                ]
            }
        ]
    }
}
