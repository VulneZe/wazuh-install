"""
Unit tests for SecurityModulesConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.security_modules_configurator import SecurityModulesConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


class TestSecurityModulesConfiguratorInitialization:
    """Test SecurityModulesConfigurator initialization"""
    
    def test_initialization_default_path(self):
        """Test initialization with default path"""
        configurator = SecurityModulesConfigurator()
        
        assert configurator.wazuh_path == "/var/ossec"
    
    def test_initialization_custom_path(self):
        """Test initialization with custom path"""
        configurator = SecurityModulesConfigurator(wazuh_path="/opt/wazuh")
        
        assert configurator.wazuh_path == "/opt/wazuh"


class TestSecurityModulesConfiguratorVulnDetector:
    """Test Vulnerability Detector module"""
    
    @pytest.mark.cached
    def test_check_vulnerability_detector_enabled(self, mock_logger):
        """Test check when Vulnerability Detector is enabled"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<vulnerability_detector><enabled>yes</enabled></vulnerability_detector>"):
                result = configurator._check_vulnerability_detector()
                
                assert result.success is True
    
    @pytest.mark.cached
    def test_check_vulnerability_detector_disabled(self, mock_logger):
        """Test check when Vulnerability Detector is disabled"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<vulnerability_detector><enabled>no</enabled></vulnerability_detector>"):
                result = configurator._check_vulnerability_detector()
                
                assert result.success is False
    
    def test_apply_vulnerability_detector(self, mock_logger):
        """Test applying Vulnerability Detector configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'backup_config', return_value=True):
                with patch.object(configurator, 'write_config_file', return_value=True):
                    result = configurator._apply_vulnerability_detector()
                    
                    assert result.success is True
    
    def test_validate_vulnerability_detector(self, mock_logger):
        """Test validating Vulnerability Detector configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<vulnerability_detector><enabled>yes</enabled></vulnerability_detector>"):
                result = configurator._validate_vulnerability_detector()
                
                assert result.success is True
    
    def test_rollback_vulnerability_detector(self, mock_logger):
        """Test rolling back Vulnerability Detector configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'restore_config', return_value=True):
                result = configurator._rollback_vulnerability_detector()
                    
                assert result.success is True


class TestSecurityModulesConfiguratorCISBenchmarks:
    """Test CIS Benchmarks module"""
    
    @pytest.mark.cached
    def test_check_cis_benchmarks_enabled(self, mock_logger):
        """Test check when CIS Benchmarks is enabled"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<cis_benchmark><enabled>yes</enabled></cis_benchmark>"):
                result = configurator._check_cis_benchmarks()
                
                assert result.success is True
    
    def test_apply_cis_benchmarks(self, mock_logger):
        """Test applying CIS Benchmarks configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'backup_config', return_value=True):
                with patch.object(configurator, 'write_config_file', return_value=True):
                    result = configurator._apply_cis_benchmarks()
                    
                    assert result.success is True


class TestSecurityModulesConfiguratorFIM:
    """Test File Integrity Monitoring module"""
    
    @pytest.mark.cached
    def test_check_fim_enabled(self, mock_logger):
        """Test check when FIM is enabled"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<syscheck><directories>/etc</directories></syscheck>"):
                result = configurator._check_fim()
                
                assert result.success is True
    
    def test_apply_fim(self, mock_logger):
        """Test applying FIM configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'backup_config', return_value=True):
                with patch.object(configurator, 'write_config_file', return_value=True):
                    result = configurator._apply_fim()
                    
                    assert result.success is True


class TestSecurityModulesConfiguratorMITREAttack:
    """Test MITRE ATT&CK module"""
    
    @pytest.mark.cached
    def test_check_mitre_attack_enabled(self, mock_logger):
        """Test check when MITRE ATT&CK is enabled"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'read_config_file', return_value="<rule><mitre><enabled>yes</enabled></mitre></rule>"):
                result = configurator._check_mitre_attack()
                
                assert result.success is True
    
    def test_apply_mitre_attack(self, mock_logger):
        """Test applying MITRE ATT&CK configuration"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, 'backup_config', return_value=True):
                with patch.object(configurator, 'write_config_file', return_value=True):
                    result = configurator._apply_mitre_attack()
                    
                    assert result.success is True


class TestSecurityModulesConfiguratorIntegration:
    """Test integration of all modules"""
    
    def test_check_all(self, mock_logger):
        """Test check method for all modules"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, '_check_vulnerability_detector', return_value=ConfigResult(success=True)):
                with patch.object(configurator, '_check_cis_benchmarks', return_value=ConfigResult(success=True)):
                    with patch.object(configurator, '_check_fim', return_value=ConfigResult(success=True)):
                        with patch.object(configurator, '_check_mitre_attack', return_value=ConfigResult(success=True)):
                            result = configurator.check()
                            
                            assert result.success is True
    
    def test_apply_all(self, mock_logger):
        """Test apply method for all modules"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, '_apply_vulnerability_detector', return_value=ConfigResult(success=True)):
                with patch.object(configurator, '_apply_cis_benchmarks', return_value=ConfigResult(success=True)):
                    with patch.object(configurator, '_apply_fim', return_value=ConfigResult(success=True)):
                        with patch.object(configurator, '_apply_mitre_attack', return_value=ConfigResult(success=True)):
                            result = configurator.apply()
                            
                            assert result.success is True
    
    def test_validate_all(self, mock_logger):
        """Test validate method for all modules"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, '_validate_vulnerability_detector', return_value=ConfigResult(success=True)):
                with patch.object(configurator, '_validate_cis_benchmarks', return_value=ConfigResult(success=True)):
                    with patch.object(configurator, '_validate_fim', return_value=ConfigResult(success=True)):
                        with patch.object(configurator, '_validate_mitre_attack', return_value=ConfigResult(success=True)):
                            result = configurator.validate()
                            
                            assert result.success is True
    
    def test_rollback_all(self, mock_logger):
        """Test rollback method for all modules"""
        with patch.object(SecurityModulesConfigurator, '__init__', lambda self, wazuh_path="/var/ossec": None):
            configurator = SecurityModulesConfigurator()
            configurator._logger = mock_logger
            configurator.ossec_conf_path = "/tmp/test_ossec.conf"
            
            with patch.object(configurator, '_rollback_vulnerability_detector', return_value=ConfigResult(success=True)):
                with patch.object(configurator, '_rollback_cis_benchmarks', return_value=ConfigResult(success=True)):
                    with patch.object(configurator, '_rollback_fim', return_value=ConfigResult(success=True)):
                        with patch.object(configurator, '_rollback_mitre_attack', return_value=ConfigResult(success=True)):
                            result = configurator.rollback()
                            
                            assert result.success is True
