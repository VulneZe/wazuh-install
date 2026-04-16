"""
Unit tests for DashboardConfigurator
"""

import pytest
from wazuh_configurator.strategies.dashboard_configurator import DashboardConfigurator


class TestDashboardConfiguratorPublicMethods:
    """Test DashboardConfigurator public methods"""
    
    def test_can_be_instantiated(self):
        """Test that DashboardConfigurator can be instantiated"""
        configurator = DashboardConfigurator()
        assert configurator is not None
    
    def test_has_check_method(self):
        """Test that check method exists and is callable"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_has_apply_method(self):
        """Test that apply method exists and is callable"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_has_validate_method(self):
        """Test that validate method exists and is callable"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_has_rollback_method(self):
        """Test that rollback method exists and is callable"""
        configurator = DashboardConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
