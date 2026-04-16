"""
Unit tests for SecurityConfigurator - Real functional tests
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from wazuh_configurator.strategies.security_configurator import SecurityConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


class TestSecurityConfiguratorCheck:
    """Test SecurityConfigurator check method - real behavior"""
    
    def test_check_returns_config_result(self):
        """Test that check returns a ConfigResult object"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                # Mock the internal check methods
                configurator._check_ssl_config = Mock(return_value=True)
                configurator._check_password_strength = Mock(return_value=True)
                configurator._check_api_auth = Mock(return_value=True)
                configurator._check_firewall_rules = Mock(return_value=True)
                
                result = configurator.check()
                
                assert isinstance(result, ConfigResult)
                assert hasattr(result, 'success')
                assert hasattr(result, 'message')
                assert hasattr(result, 'details')
    
    def test_check_success_when_all_checks_pass(self):
        """Test check returns success when all security checks pass"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                configurator._check_ssl_config = Mock(return_value=True)
                configurator._check_password_strength = Mock(return_value=True)
                configurator._check_api_auth = Mock(return_value=True)
                configurator._check_firewall_rules = Mock(return_value=True)
                
                result = configurator.check()
                
                assert result.success is True
                assert "4/4" in result.message.lower()
    
    def test_check_failure_when_some_checks_fail(self):
        """Test check returns failure when some security checks fail"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                configurator._check_ssl_config = Mock(return_value=True)
                configurator._check_password_strength = Mock(return_value=False)
                configurator._check_api_auth = Mock(return_value=True)
                configurator._check_firewall_rules = Mock(return_value=True)
                
                result = configurator.check()
                
                assert result.success is False
                assert "3/4" in result.message.lower()
                assert len(result.warnings) > 0


class TestSecurityConfiguratorApply:
    """Test SecurityConfigurator apply method - real behavior"""
    
    def test_apply_returns_config_result(self):
        """Test that apply returns a ConfigResult object"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                configurator._apply_ssl_config = Mock(return_value=True)
                configurator._apply_strong_passwords = Mock(return_value=True)
                configurator._apply_api_auth = Mock(return_value=True)
                configurator._apply_firewall_rules = Mock(return_value=True)
                
                result = configurator.apply()
                
                assert isinstance(result, ConfigResult)
                assert hasattr(result, 'success')
    
    def test_apply_success_when_all_apply_pass(self):
        """Test apply returns success when all configurations succeed"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                configurator._apply_ssl_config = Mock(return_value=True)
                configurator._apply_strong_passwords = Mock(return_value=True)
                configurator._apply_api_auth = Mock(return_value=True)
                configurator._apply_firewall_rules = Mock(return_value=True)
                
                result = configurator.apply()
                
                assert result.success is True
                assert "4/4" in result.message.lower()


class TestSecurityConfiguratorValidate:
    """Test SecurityConfigurator validate method - real behavior"""
    
    def test_validate_calls_check(self):
        """Test that validate calls check method"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths'):
            with patch('wazuh_configurator.strategies.security_configurator.WazuhLogger'):
                configurator = SecurityConfigurator()
                
                mock_check_result = ConfigResult(
                    success=True,
                    message="Test validation",
                    details={},
                    warnings=[]
                )
                configurator.check = Mock(return_value=mock_check_result)
                
                result = configurator.validate()
                
                configurator.check.assert_called_once()
                assert result is mock_check_result
