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
            "attributes": {
                "title": "Alertes par heure (24h)",
                "visState": {
                    "title": "Alertes par heure (24h)",
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
                        "legendPosition": "right",
                        "times": [],
                        "addTimeMarker": False
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"params\":{\"field\":\"@timestamp\",\"timeRange\":{\"from\":\"now-24h\",\"to\":\"now\"},\"useNormalizedOpenSearchInterval\":true,\"scaleMetricValues\":false,\"interval\":\"auto\",\"drop_partials\":false,\"min_doc_count\":1,\"extended_bounds\":{}},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "soc-alerts-level",
            "type": "pie",
            "title": "Alertes par niveau de sévérité",
            "description": "Distribution des alertes par niveau (0-15)",
            "attributes": {
                "title": "Alertes par niveau de sévérité",
                "visState": {
                    "title": "Alertes par niveau de sévérité",
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "isDonut": False,
                        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"rule.level\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":16,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "soc-top-agents",
            "type": "bar",
            "title": "Top 10 Agents par nombre d'alertes",
            "description": "Agents générant le plus d'alertes",
            "attributes": {
                "title": "Top 10 Agents par nombre d'alertes",
                "visState": {
                    "title": "Top 10 Agents par nombre d'alertes",
                    "type": "histogram",
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
                            "title": {}
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
                            "type": "histogram",
                            "mode": "normal",
                            "data": {"label": "Count", "id": "1"},
                            "valueAxis": "ValueAxis-1"
                        }],
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "right",
                        "times": []
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"agent.name\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "soc-top-rules",
            "type": "table",
            "title": "Top 10 Règles les plus déclenchées",
            "description": "Règles de détection les plus actives",
            "attributes": {
                "title": "Top 10 Règles les plus déclenchées",
                "visState": {
                    "title": "Top 10 Règles les plus déclenchées",
                    "type": "table",
                    "params": {
                        "perPage": 10,
                        "showPartialRows": False,
                        "showMetricsAtAllLevels": False,
                        "sort": {"columnIndex": null, "direction": null},
                        "showTotal": True,
                        "totalFunc": "sum",
                        "percentageCol": ""
                    },
                    "aggs": [
                        {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                        {"id": "2", "enabled": True, "type": "terms", "params": {
                            "field": "rule.description",
                            "orderBy": "1",
                            "order": "desc",
                            "size": 10,
                            "otherBucket": False,
                            "missingBucket": False
                        }, "schema": "bucket"}
                    ]
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"rule.description\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":10,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"bucket\"}]}"
                }
            }
        },
        {
            "id": "soc-rule-groups",
            "type": "pie",
            "title": "Alertes par groupe de règles",
            "description": "Distribution des alertes par catégorie de règles",
            "attributes": {
                "title": "Alertes par groupe de règles",
                "visState": {
                    "title": "Alertes par groupe de règles",
                    "type": "pie",
                    "params": {
                        "addTooltip": True,
                        "addLegend": True,
                        "legendPosition": "bottom",
                        "isDonut": True,
                        "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                    }
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"params\":{},\"schema\":\"metric\"},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"params\":{\"field\":\"rule.groups\",\"orderBy\":\"1\",\"order\":\"desc\",\"size\":15,\"otherBucket\":false,\"missingBucket\":false},\"schema\":\"segment\"}]}"
                }
            }
        },
        {
            "id": "soc-recent-alerts",
            "type": "table",
            "title": "Alertes récentes (Dernières 50)",
            "description": "Liste des alertes les plus récentes",
            "attributes": {
                "title": "Alertes récentes (Dernières 50)",
                "visState": {
                    "title": "Alertes récentes (Dernières 50)",
                    "type": "table",
                    "params": {
                        "perPage": 50,
                        "showPartialRows": False,
                        "showMetricsAtAllLevels": False,
                        "sort": {"columnIndex": null, "direction": "desc"},
                        "showTotal": False,
                        "totalFunc": "sum"
                    },
                    "aggs": []
                },
                "uiState": {},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": "{\"index\":\"wazuh-alerts-*\",\"query\":{\"query\":\"\",\"language\":\"lucene\"},\"filter\":[],\"sort\":[{\"@timestamp\":{\"order\":\"desc\"}}],\"size\":50}"
                }
            }
        }
    ],
    "layout": {
        "panels": [
            {"gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"}, "version": "2.19.4", "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_0"},
            {"gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "2"}, "version": "2.19.4", "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_1"},
            {"gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "3"}, "version": "2.19.4", "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_2"},
            {"gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "4"}, "version": "2.19.4", "panelIndex": "4", "embeddableConfig": {}, "panelRefName": "panel_3"},
            {"gridData": {"x": 0, "y": 30, "w": 16, "h": 15, "i": "5"}, "version": "2.19.4", "panelIndex": "5", "embeddableConfig": {}, "panelRefName": "panel_4"},
            {"gridData": {"x": 16, "y": 30, "w": 32, "h": 15, "i": "6"}, "version": "2.19.4", "panelIndex": "6", "embeddableConfig": {}, "panelRefName": "panel_5"}
        ]
    }
}
