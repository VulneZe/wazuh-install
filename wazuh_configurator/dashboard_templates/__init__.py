"""
Wazuh Dashboard Templates
Templates professionnels de dashboards pour SOC et sécurité opérationnelle
"""

from .soc_overview import SOC_OVERVIEW_DASHBOARD
from .ssh_auth_monitoring import SSH_AUTH_MONITORING_DASHBOARD

# Liste de tous les dashboards disponibles (corrigés pour OpenSearch Dashboards)
ALL_DASHBOARDS = [
    SOC_OVERVIEW_DASHBOARD,
    SSH_AUTH_MONITORING_DASHBOARD
]

# Mapping des dashboards par catégorie
DASHBOARDS_BY_CATEGORY = {
    "overview": [SOC_OVERVIEW_DASHBOARD],
    "monitoring": [SSH_AUTH_MONITORING_DASHBOARD]
}
