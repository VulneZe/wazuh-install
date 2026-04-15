"""
TUI Components - Clean Architecture
Terminal User Interface for Wazuh DevSec Generator
"""

from .main_app import WazuhMainApp
from .app import WazuhTUI  # Legacy compatibility
from .menu_system import MenuSystem

__all__ = ["WazuhMainApp", "WazuhTUI", "MenuSystem"]
