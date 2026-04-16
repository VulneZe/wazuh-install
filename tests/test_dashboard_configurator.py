"""
Unit tests for DashboardConfigurator
"""

import pytest
from unittest.mock import Mock, patch
from wazuh_configurator.strategies.dashboard_configurator import DashboardConfigurator
from wazuh_configurator.core.base_configurator import ConfigResult


class TestDashboardConfiguratorInitialization:
    """Test DashboardConfigurator initialization"""
    
    def test_initialization_default(self):
        """Test initialization with default parameters"""
        configurator = DashboardConfigurator()
        
        assert configurator.wazuh_path == "/var/ossec"
        assert configurator.dashboard_url == "https://localhost:5601"
        assert configurator.dashboard_username == "admin"
    
    def test_initialization_custom(self):
        """Test initialization with custom parameters"""
        configurator = DashboardConfigurator(
            wazuh_path="/opt/wazuh",
            dashboard_url="https://192.168.1.100:5601",
            dashboard_username="custom_user",
            dashboard_password="custom_password"
        )
        
        assert configurator.wazuh_path == "/opt/wazuh"
        assert configurator.dashboard_url == "https://192.168.1.100:5601"
        assert configurator.dashboard_username == "custom_user"
        assert configurator.dashboard_password == "custom_password"


class TestDashboardConfiguratorCheck:
    """Test DashboardConfigurator check method"""
    
    @pytest.mark.cached
    def test_check_dashboard_connection_success(self, mock_logger):
        """Test check when dashboard connection succeeds"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200)):
                result = configurator._check_dashboard_connection()
                
                assert result is True
    
    @pytest.mark.cached
    def test_check_dashboard_connection_failure(self, mock_logger):
        """Test check when dashboard connection fails"""
        from wazuh_configurator.utils.exceptions import ServiceNotAvailableError
        
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', side_effect=Exception("Connection refused")):
                result = configurator._check_dashboard_connection()
                
                assert result is False
    
    @pytest.mark.cached
    def test_check_visualizations(self, mock_logger):
        """Test check for existing visualizations"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200, json=lambda: {"saved_objects": []})):
                result = configurator._check_existing_visualizations()
                
                assert result is True
    
    @pytest.mark.cached
    def test_check_dashboards(self, mock_logger):
        """Test check for existing dashboards"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200, json=lambda: {"saved_objects": []})):
                result = configurator._check_existing_dashboards()
                
                assert result is True
    
    def test_check_all(self, mock_logger):
        """Test check method"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch.object(configurator, '_check_dashboard_connection', return_value=True):
                with patch.object(configurator, '_check_existing_visualizations', return_value=True):
                    with patch.object(configurator, '_check_existing_dashboards', return_value=True):
                        result = configurator.check()
                        
                        assert result.success is True


class TestDashboardConfiguratorApply:
    """Test DashboardConfigurator apply method"""
    
    def test_create_index_pattern(self, mock_logger):
        """Test creating index pattern"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.post', return_value=Mock(status_code=200)):
                result = configurator._create_index_pattern()
                
                assert result is True
    
    def test_create_visualizations(self, mock_logger):
        """Test creating visualizations"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.post', return_value=Mock(status_code=200)):
                result = configurator._create_visualizations()
                
                assert result is True
    
    def test_create_dashboard(self, mock_logger):
        """Test creating dashboard"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.post', return_value=Mock(status_code=200)):
                result = configurator._create_dashboard()
                
                assert result is True
    
    def test_apply_all(self, mock_logger):
        """Test apply method"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch.object(configurator, '_create_index_pattern', return_value=True):
                with patch.object(configurator, '_create_visualizations', return_value=True):
                    with patch.object(configurator, '_create_dashboard', return_value=True):
                        result = configurator.apply()
                        
                        assert result.success is True


class TestDashboardConfiguratorValidate:
    """Test DashboardConfigurator validate method"""
    
    @pytest.mark.cached
    def test_validate_index_pattern(self, mock_logger):
        """Test validating index pattern"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200)):
                result = configurator._validate_index_pattern()
                
                assert result is True
    
    @pytest.mark.cached
    def test_validate_visualizations(self, mock_logger):
        """Test validating visualizations"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200)):
                result = configurator._validate_visualizations()
                
                assert result is True
    
    @pytest.mark.cached
    def test_validate_dashboard(self, mock_logger):
        """Test validating dashboard"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', return_value=Mock(status_code=200)):
                result = configurator._validate_dashboard()
                
                assert result is True
    
    def test_validate_all(self, mock_logger):
        """Test validate method"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch.object(configurator, '_validate_index_pattern', return_value=True):
                with patch.object(configurator, '_validate_visualizations', return_value=True):
                    with patch.object(configurator, '_validate_dashboard', return_value=True):
                        result = configurator.validate()
                        
                        assert result.success is True


class TestDashboardConfiguratorRollback:
    """Test DashboardConfigurator rollback method"""
    
    def test_delete_index_pattern(self, mock_logger):
        """Test deleting index pattern"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.delete', return_value=Mock(status_code=200)):
                result = configurator._delete_index_pattern()
                
                assert result is True
    
    def test_delete_visualizations(self, mock_logger):
        """Test deleting visualizations"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.delete', return_value=Mock(status_code=200)):
                result = configurator._delete_visualizations()
                
                assert result is True
    
    def test_delete_dashboard(self, mock_logger):
        """Test deleting dashboard"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.delete', return_value=Mock(status_code=200)):
                result = configurator._delete_dashboard()
                
                assert result is True
    
    def test_rollback_all(self, mock_logger):
        """Test rollback method"""
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch.object(configurator, '_delete_index_pattern', return_value=True):
                with patch.object(configurator, '_delete_visualizations', return_value=True):
                    with patch.object(configurator, '_delete_dashboard', return_value=True):
                        result = configurator.rollback()
                        
                        assert result.success is True


class TestDashboardConfiguratorErrorHandling:
    """Test DashboardConfigurator error handling"""
    
    def test_service_not_available_error(self, mock_logger):
        """Test ServiceNotAvailableError handling"""
        from wazuh_configurator.utils.exceptions import ServiceNotAvailableError
        from requests.exceptions import ConnectionError
        
        with patch.object(DashboardConfigurator, '__init__', lambda self, wazuh_path="/var/ossec", dashboard_url="https://localhost:5601", dashboard_username="admin", dashboard_password=None: None):
            configurator = DashboardConfigurator()
            configurator._logger = mock_logger
            configurator.dashboard_url = "https://localhost:5601"
            configurator.dashboard_username = "admin"
            configurator.dashboard_password = "admin"
            
            with patch('requests.get', side_effect=ConnectionError("Connection refused")):
                result = configurator._check_dashboard_connection()
                
                assert result is False
