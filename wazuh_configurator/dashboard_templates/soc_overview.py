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
                "visState": '{"title":"Alertes par heure (24h)","type":"line","params":{"grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"filter":true,"truncate":100},"title":{"text":"Heure"}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Nombre"}}],"seriesParams":[{"show":true,"type":"line","mode":"normal","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1","drawLinesBetweenPoints":true,"lineWidth":2,"showCircles":true}],"addTooltip":true,"addLegend":true,"legendPosition":"right","times":[],"addTimeMarker":false}}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"date_histogram","params":{"field":"@timestamp","timeRange":{"from":"now-24h","to":"now"},"useNormalizedOpenSearchInterval":true,"scaleMetricValues":false,"interval":"auto","drop_partials":false,"min_doc_count":1,"extended_bounds":{}},"schema":"segment"}]}'
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
                "visState": '{"title":"Alertes par niveau de sévérité","type":"pie","params":{"addTooltip":true,"addLegend":true,"legendPosition":"right","isDonut":false,"labels":{"show":true,"values":true,"last_level":true,"truncate":100}}}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"terms","params":{"field":"rule.level","orderBy":"1","order":"desc","size":16,"otherBucket":false,"missingBucket":false},"schema":"segment"}]}'
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
                "visState": '{"title":"Top 10 Agents par nombre d\'alertes","type":"histogram","params":{"grid":{"categoryLines":false},"categoryAxes":[{"id":"CategoryAxis-1","type":"category","position":"bottom","show":true,"style":{},"scale":{"type":"linear"},"labels":{"show":true,"filter":true,"truncate":100},"title":{"text":"Agent"}}],"valueAxes":[{"id":"ValueAxis-1","name":"LeftAxis-1","type":"value","position":"left","show":true,"style":{},"scale":{"type":"linear","mode":"normal"},"labels":{"show":true,"rotate":0,"filter":false,"truncate":100},"title":{"text":"Nombre"}}],"seriesParams":[{"show":true,"type":"histogram","mode":"normal","data":{"label":"Count","id":"1"},"valueAxis":"ValueAxis-1"}],"addTooltip":true,"addLegend":true,"legendPosition":"right"}}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"terms","params":{"field":"agent.name","orderBy":"1","order":"desc","size":10,"otherBucket":false,"missingBucket":false},"schema":"segment"}]}'
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
                "visState": '{"title":"Top 10 Règles les plus déclenchées","type":"table","params":{"perPage":10,"showPartialRows":false,"showMetricsAtAllLevels":false,"sort":{"columnIndex":null,"direction":null},"showTotal":true,"totalFunc":"sum","percentageCol":""},"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"terms","params":{"field":"rule.description","orderBy":"1","order":"desc","size":10,"otherBucket":false,"missingBucket":false},"schema":"bucket"}]}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"terms","params":{"field":"rule.description","orderBy":"1","order":"desc","size":10,"otherBucket":false,"missingBucket":false},"schema":"bucket"}]}'
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
                "visState": '{"title":"Alertes par groupe de règles","type":"pie","params":{"addTooltip":true,"addLegend":true,"legendPosition":"bottom","isDonut":true,"labels":{"show":true,"values":true,"last_level":true,"truncate":100}}}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"aggs":[{"id":"1","enabled":true,"type":"count","params":{},"schema":"metric"},{"id":"2","enabled":true,"type":"terms","params":{"field":"rule.groups","orderBy":"1","order":"desc","size":15,"otherBucket":false,"missingBucket":false},"schema":"segment"}]}'
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
                "visState": '{"title":"Alertes récentes (Dernières 50)","type":"table","params":{"perPage":50,"showPartialRows":false,"showMetricsAtAllLevels":false,"sort":{"columnIndex":null,"direction":"desc"},"showTotal":false,"totalFunc":"sum"},"aggs":[]}',
                "uiState": '{}',
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": '{"index":"wazuh-alerts-*","query":{"query":"","language":"lucene"},"filter":[],"sort":[{"@timestamp":{"order":"desc"}}],"size":50}'
                }
            }
        }
    ],
    "layout": {
        "panels": [
            {"id": "soc-alerts-timeline", "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"}, "version": "2.19.4", "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_0"},
            {"id": "soc-alerts-level", "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "2"}, "version": "2.19.4", "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_1"},
            {"id": "soc-top-agents", "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "3"}, "version": "2.19.4", "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_2"},
            {"id": "soc-top-rules", "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "4"}, "version": "2.19.4", "panelIndex": "4", "embeddableConfig": {}, "panelRefName": "panel_3"},
            {"id": "soc-rule-groups", "gridData": {"x": 0, "y": 30, "w": 16, "h": 15, "i": "5"}, "version": "2.19.4", "panelIndex": "5", "embeddableConfig": {}, "panelRefName": "panel_4"},
            {"id": "soc-recent-alerts", "gridData": {"x": 16, "y": 30, "w": 32, "h": 15, "i": "6"}, "version": "2.19.4", "panelIndex": "6", "embeddableConfig": {}, "panelRefName": "panel_5"}
        ]
    }
}
