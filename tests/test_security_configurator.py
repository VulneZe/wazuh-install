"""
Unit tests for SecurityConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.security_configurator import SecurityConfigurator


class TestSecurityConfiguratorInitialization:
    """Test SecurityConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator()
            assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator(wazuh_path="/opt/wazuh")
            assert configurator.wazuh_path == "/opt/wazuh"


class TestSecurityConfiguratorPublicMethods:
    """Test SecurityConfigurator public methods"""
    
    def test_check_exists(self):
        """Test that check method exists"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator()
            assert hasattr(configurator, 'check')
            assert callable(configurator.check)
    
    def test_apply_exists(self):
        """Test that apply method exists"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator()
            assert hasattr(configurator, 'apply')
            assert callable(configurator.apply)
    
    def test_validate_exists(self):
        """Test that validate method exists"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator()
            assert hasattr(configurator, 'validate')
            assert callable(configurator.validate)
    
    def test_rollback_exists(self):
        """Test that rollback method exists"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            configurator = SecurityConfigurator()
            assert hasattr(configurator, 'rollback')
            assert callable(configurator.rollback)


