"""
Unit tests for DashboardConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.dashboard_configurator import DashboardConfigurator


class TestDashboardConfiguratorInitialization:
    """Test DashboardConfigurator initialization"""
    
    def test_initialization_default(self):
        """Test initialization with default parameters"""
        configurator = DashboardConfigurator()
        assert configurator.wazuh_path == "/var/ossec"
        assert configurator.dashboard_url == "https://localhost:5601"
        assert configurator.dashboard_username == "admin"


class TestDashboardConfiguratorPublicMethods:
    """Test DashboardConfigurator public methods"""
    
    def test_check_exists(self):
        """Test that check method exists"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_apply_exists(self):
        """Test that apply method exists"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_validate_exists(self):
        """Test that validate method exists"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_rollback_exists(self):
        """Test that rollback method exists"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
