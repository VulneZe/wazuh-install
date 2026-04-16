"""
Unit tests for PerformanceConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.performance_configurator import PerformanceConfigurator


class TestPerformanceConfiguratorInitialization:
    """Test PerformanceConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        configurator = PerformanceConfigurator()
        assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        configurator = PerformanceConfigurator(wazuh_path="/opt/wazuh")
        assert configurator.wazuh_path == "/opt/wazuh"


class TestPerformanceConfiguratorPublicMethods:
    """Test PerformanceConfigurator public methods"""
    
    def test_check_exists(self):
        """Test that check method exists"""
        configurator = PerformanceConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_apply_exists(self):
        """Test that apply method exists"""
        configurator = PerformanceConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_validate_exists(self):
        """Test that validate method exists"""
        configurator = PerformanceConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_rollback_exists(self):
        """Test that rollback method exists"""
        configurator = PerformanceConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
