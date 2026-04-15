"""
Wazuh DevSec Generator - Professional Security Configuration Tool
Clean architecture with modular design and comprehensive testing
"""

__version__ = "2.0.0"
__author__ = "Wazuh DevSec Team"
__description__ = "Professional Wazuh configuration generator for DevSec environments"

# Core components
from .core.config import ConfigManager, WazuhProfile, ProfileType, IntegrationType
from .core.factory import ConfigurationFactory
from .core.service_detector import ServiceDetector
from .core.rule_analyzer import RuleAnalyzer
from .core.improved_rules import ImprovedRuleLibrary
from .core.dashboard_generator import DashboardGenerator

# TUI components
from .tui.app import WazuhTUI
from .tui.menu_system import MenuSystem

# Main generators
from .generator import WazuhConfigGenerator
from .generator_v2 import WazuhGeneratorV2

__all__ = [
    # Core
    "ConfigManager",
    "WazuhProfile", 
    "ProfileType",
    "IntegrationType",
    "ConfigurationFactory",
    "ServiceDetector",
    "RuleAnalyzer",
    "ImprovedRuleLibrary",
    "DashboardGenerator",
    
    # TUI
    "WazuhTUI",
    "MenuSystem",
    
    # Generators
    "WazuhConfigGenerator",
    "WazuhGeneratorV2"
]
