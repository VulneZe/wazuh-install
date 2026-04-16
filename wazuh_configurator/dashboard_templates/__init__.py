"""
Wazuh Dashboard Templates
Templates professionnels de dashboards pour SOC et sécurité opérationnelle
"""

from .soc_overview import SOC_OVERVIEW_DASHBOARD
from .ssh_auth_monitoring import SSH_AUTH_MONITORING_DASHBOARD
from .threat_hunting import THREAT_HUNTING_DASHBOARD
from .vulnerability_exposure import VULNERABILITY_EXPOSURE_DASHBOARD
from .executive_compliance import EXECUTIVE_COMPLIANCE_DASHBOARD
from .endpoint_security import ENDPOINT_SECURITY_DASHBOARD

# Liste de tous les dashboards disponibles
ALL_DASHBOARDS = [
    SOC_OVERVIEW_DASHBOARD,
    SSH_AUTH_MONITORING_DASHBOARD,
    THREAT_HUNTING_DASHBOARD,
    VULNERABILITY_EXPOSURE_DASHBOARD,
    EXECUTIVE_COMPLIANCE_DASHBOARD,
    ENDPOINT_SECURITY_DASHBOARD
]

# Mapping des dashboards par catégorie
DASHBOARDS_BY_CATEGORY = {
    "overview": [SOC_OVERVIEW_DASHBOARD],
    "monitoring": [SSH_AUTH_MONITORING_DASHBOARD],
    "hunting": [THREAT_HUNTING_DASHBOARD],
    "vulnerability": [VULNERABILITY_EXPOSURE_DASHBOARD],
    "compliance": [EXECUTIVE_COMPLIANCE_DASHBOARD],
    "security": [ENDPOINT_SECURITY_DASHBOARD]
}
