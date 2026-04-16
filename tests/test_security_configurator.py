"""
Unit tests for SecurityConfigurator
"""

import pytest
from wazuh_configurator.strategies.security_configurator import SecurityConfigurator


class TestSecurityConfiguratorPublicMethods:
    """Test SecurityConfigurator public methods"""
    
    def test_can_be_instantiated(self):
        """Test that SecurityConfigurator can be instantiated"""
        configurator = SecurityConfigurator()
        assert configurator is not None
    
    def test_has_check_method(self):
        """Test that check method exists and is callable"""
        configurator = SecurityConfigurator()
        assert hasattr(configurator, 'check')
        assert callable(configurator.check)
    
    def test_has_apply_method(self):
        """Test that apply method exists and is callable"""
        configurator = SecurityConfigurator()
        assert hasattr(configurator, 'apply')
        assert callable(configurator.apply)
    
    def test_has_validate_method(self):
        """Test that validate method exists and is callable"""
        configurator = SecurityConfigurator()
        assert hasattr(configurator, 'validate')
        assert callable(configurator.validate)
    
    def test_has_rollback_method(self):
        """Test that rollback method exists and is callable"""
        configurator = SecurityConfigurator()
        assert hasattr(configurator, 'rollback')
        assert callable(configurator.rollback)
