"""
Executive & Compliance Dashboard
Dashboard orienté direction et conformité réglementaire
"""

EXECUTIVE_COMPLIANCE_DASHBOARD = {
    "id": "executive-compliance-dashboard",
    "title": "Executive & Compliance",
    "description": "Vue exécutive de la sécurité et de la conformité réglementaire",
    "visualizations": [
        {
            "id": "exec-security-score",
            "type": "metric",
            "title": "Score de Sécurité Global",
            "description": "Indicateur synthétique de la posture de sécurité",
            "query": {
                "index": "wazuh-alerts-*",
                "aggs": {
                    "filter": {
                        "query": {
                            "bool": {
                                "must_not": [
                                    {"range": {"rule.level": {"gte": 10}}}
                                ]
                            }
                        }
                    }
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
            "id": "exec-compliance-status",
            "type": "pie",
            "title": "État de Conformité par Framework",
            "description": "Conformité par norme (CIS, PCI-DSS, HIPAA, GDPR, etc.)",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: sca",
                "aggs": {
                    "terms": {"field": "data.sca.check.compliance.cis_csc_v8", "size": 20}
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
            "id": "exec-alert-trend",
            "type": "line",
            "title": "Tendance des Alertes (30 jours)",
            "description": "Évolution du volume d'alertes sur 30 jours",
            "query": {
                "index": "wazuh-alerts-*",
                "time_field": "@timestamp",
                "interval": "1d"
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
            "id": "exec-critical-incidents",
            "type": "metric",
            "title": "Incidents Critiques (7 jours)",
            "description": "Nombre d'alertes de niveau critique",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.level: >=10 AND @timestamp: >=now-7d",
                "aggs": {
                    "filter": {}
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
            "id": "exec-coverage",
            "type": "gauge",
            "title": "Couverture de Détection",
            "description": "Pourcentage d'agents actifs et connectés",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: agent",
                "aggs": {
                    "cardinality": {
                        "field": "agent.id"
                    }
                }
            },
            "attributes": {
                "visState": {
                    "type": "gauge",
                    "params": {
                        "gauge": {
                            "type": "arc",
                            "orientation": "vertical",
                            "colorSchema": "greenToRed"
                        }
                    }
                }
            }
        },
        {
            "id": "exec-compliance-by-standard",
            "type": "bar",
            "title": "Conformité par Standard",
            "description": "État de conformité par norme réglementaire",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: sca",
                "aggs": {
                    "terms": {"field": "data.sca.policy", "size": 15}
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
            "id": "exec-risk-mitigation",
            "type": "pie",
            "title": "Risques par Niveau de Mitigation",
            "description": "Distribution des risques par état de remédiation",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.groups: vulnerability",
                "aggs": {
                    "terms": {"field": "data.vulnerability.status", "size": 10}
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
            "id": "exec-incident-response-time",
            "type": "line",
            "title": "Temps de Réponse aux Incidents",
            "description": "Temps moyen de détection et réponse",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.level: >=7",
                "time_field": "@timestamp",
                "interval": "1d"
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
            "id": "exec-top-attack-vectors",
            "type": "bar",
            "title": "Vecteurs d'Attaque Principaux",
            "description": "Types d'attaques les plus fréquents",
            "query": {
                "index": "wazuh-alerts-*",
                "query": "rule.level: >=5",
                "aggs": {
                    "terms": {"field": "rule.groups", "size": 15}
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
            "id": "exec-agent-health",
            "type": "table",
            "title": "Santé des Agents",
            "description": "État de connectivité des endpoints",
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
        }
    ],
    "layout": {
        "rows": [
            {
                "title": "Security Overview",
                "panels": [
                    {"id": "exec-security-score", "col": 1, "row": 1, "size_x": 4, "size_y": 3},
                    {"id": "exec-critical-incidents", "col": 5, "row": 1, "size_x": 4, "size_y": 3},
                    {"id": "exec-coverage", "col": 9, "row": 1, "size_x": 4, "size_y": 3}
                ]
            },
            {
                "title": "Compliance Status",
                "panels": [
                    {"id": "exec-compliance-status", "col": 1, "row": 4, "size_x": 6, "size_y": 3},
                    {"id": "exec-compliance-by-standard", "col": 7, "row": 4, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Trends & Response",
                "panels": [
                    {"id": "exec-alert-trend", "col": 1, "row": 7, "size_x": 6, "size_y": 3},
                    {"id": "exec-incident-response-time", "col": 7, "row": 7, "size_x": 6, "size_y": 3}
                ]
            },
            {
                "title": "Risk Analysis",
                "panels": [
                    {"id": "exec-risk-mitigation", "col": 1, "row": 10, "size_x": 4, "size_y": 3},
                    {"id": "exec-top-attack-vectors", "col": 5, "row": 10, "size_x": 8, "size_y": 3}
                ]
            },
            {
                "title": "Infrastructure Health",
                "panels": [
                    {"id": "exec-agent-health", "col": 1, "row": 13, "size_x": 12, "size_y": 4}
                ]
            }
        ]
    }
}
