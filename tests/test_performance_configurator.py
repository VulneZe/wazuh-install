"""
Unit tests for PerformanceConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.performance_configurator import PerformanceConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


class TestPerformanceConfiguratorInitialization:
    """Test PerformanceConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths'):
            configurator = PerformanceConfigurator()
            
            assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths'):
            configurator = PerformanceConfigurator(wazuh_path="/opt/wazuh")
            
            assert configurator.wazuh_path == "/opt/wazuh"


class TestPerformanceConfiguratorCheck:
    """Test PerformanceConfigurator check method"""
    
    @pytest.mark.cached
    def test_check_jvm_memory_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when JVM memory is configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="-Xms2G -Xmx2G"):
                    result = configurator._check_jvm_memory()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_jvm_memory_not_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when JVM memory is not configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="no_heap_config"):
                    result = configurator._check_jvm_memory()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_log_rotation_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when log rotation is configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="rotate 10\nsize 100M"):
                    result = configurator._check_log_rotation()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_log_rotation_not_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when log rotation is not configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="no_rotation"):
                    result = configurator._check_log_rotation()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_disk_cleanup_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when disk cleanup is configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch('os.path.exists', return_value=True):
                    result = configurator._check_disk_cleanup()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_connection_pool_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when connection pool is configured"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="thread_pool: 50"):
                    result = configurator._check_connection_pool()
                    
                    assert result is True
    
    def test_check_all(self, mock_wazuh_paths, mock_logger):
        """Test check method"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, '_check_jvm_memory', return_value=True):
                    with patch.object(configurator, '_check_log_rotation', return_value=True):
                        with patch.object(configurator, '_check_disk_cleanup', return_value=True):
                            with patch.object(configurator, '_check_connection_pool', return_value=True):
                                result = configurator.check()
                                
                                assert result.success is True


class TestPerformanceConfiguratorApply:
    """Test PerformanceConfigurator apply method"""
    
    def test_apply_jvm_memory(self, mock_wazuh_paths, mock_logger):
        """Test applying JVM memory configuration"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_jvm_memory()
                        
                        assert result is True
    
    def test_apply_log_rotation(self, mock_wazuh_paths, mock_logger):
        """Test applying log rotation configuration"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_log_rotation()
                        
                        assert result is True
    
    def test_apply_all(self, mock_wazuh_paths, mock_logger):
        """Test apply method"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, '_apply_jvm_memory', return_value=True):
                    with patch.object(configurator, '_apply_log_rotation', return_value=True):
                        with patch.object(configurator, '_apply_disk_cleanup', return_value=True):
                            result = configurator.apply()
                            
                            assert result.success is True


class TestPerformanceConfiguratorValidate:
    """Test PerformanceConfigurator validate method"""
    
    def test_validate_jvm_memory(self, mock_wazuh_paths, mock_logger):
        """Test validating JVM memory configuration"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="-Xms2G -Xmx2G"):
                    result = configurator._validate_jvm_memory()
                    
                    assert result is True
    
    def test_validate_all(self, mock_wazuh_paths, mock_logger):
        """Test validate method"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, '_validate_jvm_memory', return_value=True):
                    with patch.object(configurator, '_validate_log_rotation', return_value=True):
                        result = configurator.validate()
                        
                        assert result.success is True


class TestPerformanceConfiguratorRollback:
    """Test PerformanceConfigurator rollback method"""
    
    def test_rollback_jvm_memory(self, mock_wazuh_paths, mock_logger):
        """Test rolling back JVM memory configuration"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, 'restore_config', return_value=True):
                    result = configurator._rollback_jvm_memory()
                    
                    assert result is True
    
    def test_rollback_all(self, mock_wazuh_paths, mock_logger):
        """Test rollback method"""
        with patch('wazuh_configurator.strategies.performance_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(PerformanceConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = PerformanceConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.performance_config = {}
                
                with patch.object(configurator, '_rollback_jvm_memory', return_value=True):
                    with patch.object(configurator, '_rollback_log_rotation', return_value=True):
                        result = configurator.rollback()
                        
                        assert result.success is True
