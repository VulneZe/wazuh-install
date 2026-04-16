"""
Unit tests for ConfigManager
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from wazuh_configurator.core.config_manager import ConfigManager
from wazuh_configurator.core.base_configurator import ConfigResult


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


class TestConfigManagerInitialization:
    """Test ConfigManager initialization"""
    
    def test_initialize_with_wazuh_installed(self, mock_installation, mock_logger):
        """Test initialization when Wazuh is installed"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.detector = Mock()
            manager.detector.detect_installation = Mock(return_value=mock_installation)
            manager.installation = None
            manager._initialized = False
            
            result = manager.initialize()
            
            assert result.success is True
            assert "initialisé avec succès" in result.message.lower()
    
    def test_initialize_without_wazuh(self, mock_logger):
        """Test initialization when Wazuh is not installed"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.detector = Mock()
            mock_installation = Mock()
            mock_installation.installed = False
            manager.detector.detect_installation = Mock(return_value=mock_installation)
            manager.installation = None
            manager._initialized = False
            
            result = manager.initialize()
            
            assert result.success is False
            assert "pas installé" in result.message.lower()


class TestConfigManagerRegistration:
    """Test configurator registration"""
    
    def test_register_configurator(self, mock_configurator):
        """Test registering a configurator"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {}
            manager._logger = Mock()
            
            result = manager.register_configurator('test', mock_configurator)
            
            assert result is True
            assert 'test' in manager.configurators
            assert manager.configurators['test'] is mock_configurator
    
    def test_get_configurator(self, mock_configurator):
        """Test getting a configurator"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            
            result = manager.get_configurator('test')
            
            assert result is mock_configurator
    
    def test_get_nonexistent_configurator(self):
        """Test getting a non-existent configurator"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {}
            
            result = manager.get_configurator('nonexistent')
            
            assert result is None


class TestConfigManagerConfiguration:
    """Test configuration operations"""
    
    def test_check_all_configs(self, mock_configurator, mock_config_result):
        """Test checking all configurations"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.check = Mock(return_value=mock_config_result)
            
            results = manager.check_all_configs()
            
            assert 'test' in results
            assert results['test'] is mock_config_result
            mock_configurator.check.assert_called_once()
    
    def test_apply_all_configs(self, mock_configurator, mock_config_result):
        """Test applying all configurations"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.apply = Mock(return_value=mock_config_result)
            
            results = manager.apply_all_configs()
            
            assert 'test' in results
            assert results['test'] is mock_config_result
            mock_configurator.apply.assert_called_once()
    
    def test_apply_config(self, mock_configurator, mock_config_result):
        """Test applying a specific configuration"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.apply = Mock(return_value=mock_config_result)
            
            result = manager.apply_config('test')
            
            assert result is mock_config_result
            mock_configurator.apply.assert_called_once()
    
    def test_apply_nonexistent_config(self):
        """Test applying a non-existent configuration"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {}
            manager._logger = Mock()
            
            result = manager.apply_config('nonexistent')
            
            assert result.success is False
            assert "non trouvé" in result.message.lower()
    
    def test_validate_all_configs(self, mock_configurator, mock_config_result):
        """Test validating all configurations"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.validate = Mock(return_value=mock_config_result)
            
            results = manager.validate_all_configs()
            
            assert 'test' in results
            assert results['test'] is mock_config_result
            mock_configurator.validate.assert_called_once()
    
    def test_rollback_all_configs(self, mock_configurator, mock_config_result):
        """Test rolling back all configurations"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.rollback = Mock(return_value=mock_config_result)
            
            results = manager.rollback_all_configs()
            
            assert 'test' in results
            assert results['test'] is mock_config_result
            mock_configurator.rollback.assert_called_once()
    
    def test_rollback_config(self, mock_configurator, mock_config_result):
        """Test rolling back a specific configuration"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {'test': mock_configurator}
            manager._logger = Mock()
            mock_configurator.rollback = Mock(return_value=mock_config_result)
            
            result = manager.rollback_config('test')
            
            assert result is mock_config_result
            mock_configurator.rollback.assert_called_once()
    
    def test_rollback_nonexistent_config(self):
        """Test rolling back a non-existent configuration"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.configurators = {}
            manager._logger = Mock()
            
            result = manager.rollback_config('nonexistent')
            
            assert result.success is False
            assert "non trouvé" in result.message.lower()


class TestConfigManagerRemote:
    """Test remote configuration (SSH)"""
    
    def test_set_remote_config(self, mock_ssh_credentials, mock_logger):
        """Test setting remote configuration"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.is_remote = False
            manager.ssh_client = None
            manager.ssh_credentials = None
            manager.custom_ports = None
            
            manager.set_remote_config(
                host="192.168.1.100",
                ssh_user="test_user",
                ssh_key="/tmp/test_key",
                ssh_password="test_password",
                ssh_port=22
            )
            
            assert manager.is_remote is True
            assert manager.ssh_credentials is not None
            assert manager.ssh_client is not None
    
    def test_set_remote_config_with_custom_ports(self, mock_logger):
        """Test setting remote configuration with custom ports"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.is_remote = False
            manager.ssh_client = None
            manager.ssh_credentials = None
            manager.custom_ports = None
            
            manager.set_remote_config(
                host="192.168.1.100",
                ssh_user="test_user",
                custom_ports="events:1514,api:55000"
            )
            
            assert manager.custom_ports is not None
            assert manager.custom_ports.get('events') == 1514
            assert manager.custom_ports.get('api') == 55000
    
    def test_connect_ssh_success(self, mock_ssh_client, mock_logger):
        """Test successful SSH connection"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.is_remote = True
            manager.ssh_client = mock_ssh_client
            
            result = manager.connect_ssh()
            
            assert result is True
            mock_ssh_client.connect.assert_called_once()
    
    def test_connect_ssh_failure(self, mock_ssh_client, mock_logger):
        """Test failed SSH connection"""
        from wazuh_configurator.utils.exceptions import SSHConnectionError
        
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.is_remote = True
            mock_ssh_client.connect = Mock(side_effect=SSHConnectionError("Connection failed"))
            manager.ssh_client = mock_ssh_client
            
            result = manager.connect_ssh()
            
            assert result is False
    
    def test_connect_ssh_not_remote(self, mock_logger):
        """Test SSH connection when not in remote mode"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.is_remote = False
            manager.ssh_client = None
            
            result = manager.connect_ssh()
            
            assert result is True
    
    def test_disconnect_ssh(self, mock_ssh_client, mock_logger):
        """Test disconnecting SSH"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager._logger = mock_logger
            manager.ssh_client = mock_ssh_client
            
            manager.disconnect_ssh()
            
            mock_ssh_client.disconnect.assert_called_once()


class TestConfigManagerInfo:
    """Test information retrieval"""
    
    def test_get_installation_info(self, mock_installation):
        """Test getting installation information"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.installation = mock_installation
            
            result = manager.get_installation_info()
            
            assert result is mock_installation
    
    def test_get_summary(self, mock_installation):
        """Test getting summary"""
        with patch.object(ConfigManager, '__init__', lambda self: None):
            manager = ConfigManager()
            manager.installation = mock_installation
            manager.configurators = {'test': Mock()}
            
            summary = manager.get_summary()
            
            assert summary['installed'] is True
            assert summary['version'] == "4.14.0"
            assert 'test' in summary['registered_configurators']
            assert 'wazuh-indexer' in summary['services_status']
