"""
Unit tests for MonitoringConfigurator
"""

import pytest
from wazuh_configurator.strategies.monitoring_configurator import MonitoringConfigurator


class TestMonitoringConfiguratorPublicMethods:
    """Test MonitoringConfigurator public methods"""
    
    def test_can_be_instantiated(self):
        """Test that MonitoringConfigurator can be instantiated"""
        configurator = MonitoringConfigurator()
        assert configurator is not None
    
    def test_has_check_method(self):
        """Test that check method exists and is callable"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_has_apply_method(self):
        """Test that apply method exists and is callable"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_has_validate_method(self):
        """Test that validate method exists and is callable"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_has_rollback_method(self):
        """Test that rollback method exists and is callable"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
