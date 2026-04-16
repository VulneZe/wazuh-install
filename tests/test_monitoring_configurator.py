"""
Unit tests for MonitoringConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.monitoring_configurator import MonitoringConfigurator


class TestMonitoringConfiguratorInitialization:
    """Test MonitoringConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        configurator = MonitoringConfigurator()
        assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        configurator = MonitoringConfigurator(wazuh_path="/opt/wazuh")
        assert configurator.wazuh_path == "/opt/wazuh"


class TestMonitoringConfiguratorPublicMethods:
    """Test MonitoringConfigurator public methods"""
    
    def test_check_exists(self):
        """Test that check method exists"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_apply_exists(self):
        """Test that apply method exists"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_validate_exists(self):
        """Test that validate method exists"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_rollback_exists(self):
        """Test that rollback method exists"""
        configurator = MonitoringConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
