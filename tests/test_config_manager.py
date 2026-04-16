"""
Unit tests for ConfigManager - Real functional tests
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.core.config_manager import ConfigManager
from wazuh_configurator.core.base_configurator import ConfigResult


class TestConfigManagerSingleton:
    """Test Singleton pattern implementation - critical for ConfigManager"""
    
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


class TestConfigManagerRollbackConfig:
    """Test rollback_config method - critical bug fix"""
    
    def test_rollback_config_existing_configurator(self):
        """Test rollback_config with existing configurator"""
        manager = ConfigManager()
        manager._logger = Mock()
        
        # Create a mock configurator
        mock_configurator = Mock()
        mock_result = ConfigResult(
            success=True,
            message="Rollback successful",
            details={},
            warnings=[]
        )
        mock_configurator.rollback = Mock(return_value=mock_result)
        
        manager.configurators = {'security': mock_configurator}
        
        result = manager.rollback_config('security')
        
        assert result.success is True
        mock_configurator.rollback.assert_called_once()
    
    def test_rollback_config_nonexistent_configurator(self):
        """Test rollback_config with non-existent configurator"""
        manager = ConfigManager()
        manager._logger = Mock()
        manager.configurators = {}
        
        result = manager.rollback_config('nonexistent')
        
        assert result.success is False
        assert "non trouvé" in result.message.lower()


class TestConfigManagerRegisterAndGet:
    """Test configurator registration and retrieval"""
    
    def test_register_and_get_configurator(self):
        """Test registering and retrieving a configurator"""
        manager = ConfigManager()
        manager._logger = Mock()
        
        mock_configurator = Mock()
        result = manager.register_configurator('test', mock_configurator)
        
        assert result is True
        retrieved = manager.get_configurator('test')
        assert retrieved is mock_configurator

