"""
Unit tests for SecurityConfigurator
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from wazuh_configurator.strategies.security_configurator import SecurityConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


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


class TestSecurityConfiguratorCheck:
    """Test SecurityConfigurator check method"""
    
    @pytest.mark.cached
    def test_check_ssl_configured(self, mock_wazuh_paths, mock_logger, temp_config_dir):
        """Test check when SSL is configured"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock file content with SSL
                with patch.object(configurator, 'read_config_file', return_value="plugins.security.ssl.enabled=true"):
                    result = configurator._check_ssl_config()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_ssl_not_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when SSL is not configured"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock file content without SSL
                with patch.object(configurator, 'read_config_file', return_value="no_ssl_here"):
                    result = configurator._check_ssl_config()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_password_strength(self, mock_wazuh_paths, mock_logger):
        """Test check when password is strong"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock file content with strong password
                with patch.object(configurator, 'read_config_file', return_value="admin:this_is_a_very_strong_password_12345678"):
                    result = configurator._check_password_strength()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_password_weak(self, mock_wazuh_paths, mock_logger):
        """Test check when password is weak"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock file content with weak password
                with patch.object(configurator, 'read_config_file', return_value="admin:weak"):
                    result = configurator._check_password_strength()
                    
                    assert result is False
    
    @pytest.mark.cached
    def test_check_api_auth_configured(self, mock_wazuh_paths, mock_logger):
        """Test check when API authentication is configured"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock file content with JWT auth
                with patch.object(configurator, 'read_config_file', return_value="jwt_enabled=true"):
                    result = configurator._check_api_auth()
                    
                    assert result is True
    
    @pytest.mark.cached
    def test_check_firewall_configured(self, mock_logger):
        """Test check when firewall is configured"""
        with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityConfigurator()
            configurator._logger = mock_logger
            configurator.security_config = {}
            
            # Mock subprocess for ufw status
            with patch('subprocess.run', return_value=Mock(stdout="Status: active\n1514/tcp\tALLOW\n1515/tcp\tALLOW\n55000/tcp\tALLOW")):
                result = configurator._check_firewall_rules()
                
                assert result is True
    
    def test_check_all(self, mock_wazuh_paths, mock_logger):
        """Test check method"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                # Mock all check methods
                with patch.object(configurator, '_check_ssl_config', return_value=True):
                    with patch.object(configurator, '_check_password_strength', return_value=True):
                        with patch.object(configurator, '_check_api_auth', return_value=True):
                            with patch.object(configurator, '_check_firewall_rules', return_value=True):
                                result = configurator.check()
                                
                                assert result.success is True


class TestSecurityConfiguratorApply:
    """Test SecurityConfigurator apply method"""
    
    def test_apply_ssl_config(self, mock_wazuh_paths, mock_logger):
        """Test applying SSL configuration"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_ssl_config()
                        
                        assert result is True
    
    def test_apply_passwords(self, mock_wazuh_paths, mock_logger):
        """Test applying password configuration"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, 'backup_config', return_value=True):
                    with patch.object(configurator, 'write_config_file', return_value=True):
                        result = configurator._apply_passwords()
                        
                        assert result is True
    
    def test_apply_firewall(self, mock_logger):
        """Test applying firewall configuration"""
        with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityConfigurator()
            configurator._logger = mock_logger
            configurator.security_config = {}
            
            with patch('subprocess.run', return_value=Mock(returncode=0)):
                result = configurator._apply_firewall_rules()
                
                assert result is True
    
    def test_apply_all(self, mock_wazuh_paths, mock_logger):
        """Test apply method"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, '_apply_ssl_config', return_value=True):
                    with patch.object(configurator, '_apply_passwords', return_value=True):
                        with patch.object(configurator, '_apply_firewall_rules', return_value=True):
                            result = configurator.apply()
                            
                            assert result.success is True


class TestSecurityConfiguratorValidate:
    """Test SecurityConfigurator validate method"""
    
    def test_validate_ssl_config(self, mock_wazuh_paths, mock_logger):
        """Test validating SSL configuration"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, 'read_config_file', return_value="plugins.security.ssl.enabled=true"):
                    result = configurator._validate_ssl_config()
                    
                    assert result is True
    
    def test_validate_all(self, mock_wazuh_paths, mock_logger):
        """Test validate method"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, '_validate_ssl_config', return_value=True):
                    with patch.object(configurator, '_validate_passwords', return_value=True):
                        with patch.object(configurator, '_validate_api_auth', return_value=True):
                            result = configurator.validate()
                            
                            assert result.success is True


class TestSecurityConfiguratorRollback:
    """Test SecurityConfigurator rollback method"""
    
    def test_rollback_ssl_config(self, mock_wazuh_paths, mock_logger):
        """Test rolling back SSL configuration"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, 'restore_config', return_value=True):
                    result = configurator._rollback_ssl_config()
                    
                    assert result is True
    
    def test_rollback_all(self, mock_wazuh_paths, mock_logger):
        """Test rollback method"""
        with patch('wazuh_configurator.strategies.security_configurator.WazuhPaths', return_value=mock_wazuh_paths):
            with patch.object(SecurityConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
                configurator = SecurityConfigurator()
                configurator._logger = mock_logger
                configurator.paths = mock_wazuh_paths
                configurator.security_config = {}
                
                with patch.object(configurator, '_rollback_ssl_config', return_value=True):
                    with patch.object(configurator, '_rollback_passwords', return_value=True):
                        with patch.object(configurator, '_rollback_firewall_rules', return_value=True):
                            result = configurator.rollback()
                            
                            assert result.success is True
