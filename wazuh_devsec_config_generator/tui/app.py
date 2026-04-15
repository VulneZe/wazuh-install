"""
Clean TUI Application - Professional Architecture
Main entry point for Wazuh DevSec Generator Terminal Interface
"""

# Import the clean main application
from .main_app import WazuhMainApp as WazuhTUI

# Maintain backward compatibility
__all__ = ["WazuhTUI"]
