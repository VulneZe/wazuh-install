"""
Unit tests for ConfigManager
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from wazuh_configurator.core.config_manager import ConfigManager


class TestConfigManagerSingleton:
    """Test Singleton pattern implementation"""
    
    def test_singleton_returns_same_instance(self):
        """Test that Singleton returns the same instance"""
        instance1 = ConfigManager()
        instance2 = ConfigManager()
        assert instance1 is instance2
    
    def test_singleton_thread_safety(self):
        """Test that Singleton is thread-safe"""
        import threading
        
        instances = []
        
        def get_instance():
            instances.append(ConfigManager())
        
        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        
        # All instances should be the same
        assert all(inst is instances[0] for inst in instances)


class TestConfigManagerPublicMethods:
    """Test ConfigManager public methods"""
    
    def test_initialize_exists(self):
        """Test that initialize method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'initialize')
        assert callable(manager.initialize)
    
    def test_register_configurator_exists(self):
        """Test that register_configurator method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'register_configurator')
        assert callable(manager.register_configurator)
    
    def test_get_configurator_exists(self):
        """Test that get_configurator method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'get_configurator')
        assert callable(manager.get_configurator)
    
    def test_check_all_configs_exists(self):
        """Test that check_all_configs method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'check_all_configs')
        assert callable(manager.check_all_configs)
    
    def test_apply_all_configs_exists(self):
        """Test that apply_all_configs method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'apply_all_configs')
        assert callable(manager.apply_all_configs)
    
    def test_apply_config_exists(self):
        """Test that apply_config method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'apply_config')
        assert callable(manager.apply_config)
    
    def test_validate_all_configs_exists(self):
        """Test that validate_all_configs method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'validate_all_configs')
        assert callable(manager.validate_all_configs)
    
    def test_rollback_all_configs_exists(self):
        """Test that rollback_all_configs method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'rollback_all_configs')
        assert callable(manager.rollback_all_configs)
    
    def test_rollback_config_exists(self):
        """Test that rollback_config method exists"""
        manager = ConfigManager()
        assert hasattr(manager, 'rollback_config')
        assert callable(manager.rollback_config)
