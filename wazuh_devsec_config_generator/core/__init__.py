"""
Core Components - Clean Architecture
Professional Wazuh DevSec Generator Core Modules
"""

# Configuration and Profiles
from .config import ConfigManager, WazuhProfile, ProfileType, IntegrationType
from .factory import ConfigurationFactory
from .settings import WazuhSettings, get_settings

# Detection and Analysis
from .service_detector import ServiceDetector
from .rule_analyzer import RuleAnalyzer
from .validator import WazuhValidator, ValidationReport

# Rules and Templates
from .rules import RuleGenerator
from .decoders import DecoderGenerator
from .improved_rules import ImprovedRuleLibrary, RuleCategory

# Integrations and Dashboards
from .integrations import IntegrationManager, IntegrationStatus
from .dashboard_generator import DashboardGenerator

# Simulation and Testing
from .simulation import WazuhSimulator

# Utilities
from .constants import *
from .logger import get_logger, setup_logging
from .exceptions import *

__all__ = [
    # Configuration
    "ConfigManager",
    "WazuhProfile", 
    "ProfileType",
    "IntegrationType",
    "ConfigurationFactory",
    "WazuhSettings",
    "get_settings",
    
    # Detection and Analysis
    "ServiceDetector",
    "RuleAnalyzer", 
    "WazuhValidator",
    "ValidationReport",
    
    # Rules and Templates
    "RuleGenerator",
    "DecoderGenerator",
    "ImprovedRuleLibrary",
    "RuleCategory",
    
    # Integrations and Dashboards
    "IntegrationManager",
    "IntegrationStatus",
    "DashboardGenerator",
    
    # Simulation and Testing
    "WazuhSimulator",
    
    # Utilities
    "get_logger",
    "setup_logging"
]
