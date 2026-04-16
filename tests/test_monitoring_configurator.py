"""
Unit tests for MonitoringConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.monitoring_configurator import MonitoringConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


class TestMonitoringConfiguratorInitialization:
    """Test MonitoringConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths'):
            configurator = MonitoringConfigurator()
            
            assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths'):
            configurator = MonitoringConfigurator(wazuh_path="/opt/wazuh")
            
            assert configurator.wazuh_path == "/opt/wazuh"


class TestMonitoringConfiguratorCheck:
    """Test MonitoringConfigurator check method"""
    
    @pytest.mark.cached
    def test_check_service_monitoring_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when service monitoring is configured"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch('subprocess.run', return_value=Mock(returncode=0, stdout="active")):
                    result = configurator._check_service_monitoring()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_service_monitoring_not_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when service monitoring is not configured"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch('subprocess.run', return_value=Mock(returncode=1, stderr="Service not found")):
                    result = configurator._check_service_monitoring()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_log_level_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when log level is configured"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="log.level=INFO"):
                    result = configurator._check_log_level()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_log_level_debug(self, mock_wazuh_paths, mock_logger):
        """Test check when log level is DEBUG (not optimal for production)"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="log.level=DEBUG"):
                    result = configurator._check_log_level()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_alerts_enabled(self, mock_wazuh_paths, mock_logger):
        """Test check when alerts are enabled"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="<alerts>enabled</alerts>"):
                    result = configurator._check_alerts_enabled()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_health_checks_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when health checks are configured"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch('os.path.exists', return_value=True):
                    result = configurator._check_health_checks()
                    
                    assert result is True
    
    def test_check_all(self, mock_wazuh_paths, mock_logger):
        """Test check method"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, '_check_service_monitoring', return_value=True):
                    with patch.object(configurator, '_check_log_level', return_value=True):
                        with patch.object(configurator, '_check_alerts_enabled', return_value=True):
                            with patch.object(configurator, '_check_health_checks', return_value=True):
                                result = configurator.check()
                                
                                assert result.success is True


class TestMonitoringConfiguratorApply:
    """Test MonitoringConfigurator apply method"""
    
    def test_apply_monitoring_config(self, mock_wazuh_paths, mock_logger):
        """Test applying monitoring configuration"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_monitoring_config()
                        
                        assert result is True
    
    def test_apply_alerts_config(self, mock_wazuh_paths, mock_logger):
        """Test applying alerts configuration"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_alerts_config()
                        
                        assert result is True
    
    def test_apply_all(self, mock_wazuh_paths, mock_logger):
        """Test apply method"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, '_apply_monitoring_config', return_value=True):
                    with patch.object(configurator, '_apply_alerts_config', return_value=True):
                        result = configurator.apply()
                        
                        assert result.success is True


class TestMonitoringConfiguratorValidate:
    """Test MonitoringConfigurator validate method"""
    
    def test_validate_monitoring_config(self, mock_wazuh_paths, mock_logger):
        """Test validating monitoring configuration"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="log.level=INFO"):
                    result = configurator._validate_monitoring_config()
                    
                    assert result is True
    
    def test_validate_all(self, mock_wazuh_paths, mock_logger):
        """Test validate method"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, '_validate_monitoring_config', return_value=True):
                    with patch.object(configurator, '_validate_alerts_config', return_value=True):
                        result = configurator.validate()
                        
                        assert result.success is True


class TestMonitoringConfiguratorRollback:
    """Test MonitoringConfigurator rollback method"""
    
    def test_rollback_monitoring_config(self, mock_wazuh_paths, mock_logger):
        """Test rolling back monitoring configuration"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, 'restore_config', return_value=True):
                    result = configurator._rollback_monitoring_config()
                    
                    assert result is True
    
    def test_rollback_all(self, mock_wazuh_paths, mock_logger):
        """Test rollback method"""
        with patch('wazuh_configurator.strategies.monitoring_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(MonitoringConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = MonitoringConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.monitoring_config = {}
                
                with patch.object(configurator, '_rollback_monitoring_config', return_value=True):
                    with patch.object(configurator, '_rollback_alerts_config', return_value=True):
                        result = configurator.rollback()
                        
                        assert result.success is True
