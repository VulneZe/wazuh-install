"""
Unit tests for ConfigManager
"""

import pytest
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
    
    def test_can_be_instantiated(self):
        """Test that ConfigManager can be instantiated"""
        manager = ConfigManager()
        assert manager is not None
    
    def test_has_rollback_config_method(self):
        """Test that rollback_config method exists (critical bug fix)"""
        manager = ConfigManager()
        assert hasattr(manager, 'rollback_config')
        assert callable(manager.rollback_config)

