"""
Pytest configuration and fixtures for Wazuh Configurator tests
"""

import pytest
import os
import sys
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def mock_wazuh_paths():
    """Mock WazuhPaths for testing"""
    from wazuh_configurator.config.paths import WazuhPaths
    
    paths = Mock(spec=WazuhPaths)
    paths.ossec_conf = "/tmp/test_ossec.conf"
    paths.local_options = "/tmp/test_local_options"
    paths.api_config = "/tmp/test_api_config"
    paths.passwords_file = "/tmp/test_passwords.txt"
    paths.jvm_config = "/tmp/test_jvm_config"
    paths.logrotate_config = "/tmp/test_logrotate_config"
    paths.indexer_config = "/tmp/test_indexer_config"
    paths.cron_daily = "/tmp/test_cron_daily"
    
    return paths


@pytest.fixture
def mock_config_result():
    """Mock ConfigResult for testing"""
    from wazuh_configurator.core.base_configurator import ConfigResult
    
    return ConfigResult(
        success=True,
        message="Test message",
        details={"test": "value"},
        warnings=["Test warning"]
    )


@pytest.fixture
def mock_installation():
    """Mock WazuhInstallation for testing"""
    from wazuh_configurator.core.wazuh_detector import WazuhInstallation
    
    installation = Mock(spec=WazuhInstallation)
    installation.installed = True
    installation.version = "4.14.0"
    installation.path = "/var/ossec"
    installation.components = {
        "indexer": True,
        "server": True,
        "dashboard": True
    }
    installation.services_status = {
        "wazuh-indexer": "active",
        "wazuh-server": "active",
        "wazuh-dashboard": "active"
    }
    
    return installation


@pytest.fixture
def mock_logger():
    """Mock WazuhLogger for testing"""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    
    return logger


@pytest.fixture
def mock_ssh_credentials():
    """Mock SSHCredentials for testing"""
    from wazuh_configurator.utils.ssh_client import SSHCredentials
    
    credentials = SSHCredentials(
        host="192.168.1.100",
        username="test_user",
        port=22,
        password="test_password",
        key_file="/tmp/test_key"
    )
    
    return credentials


@pytest.fixture
def mock_ssh_client():
    """Mock SSHClient for testing"""
    client = Mock()
    client.connect = Mock(return_value=True)
    client.disconnect = Mock(return_value=True)
    client.execute_command = Mock(return_value=("stdout", "stderr", 0))
    client.upload_file = Mock(return_value=True)
    client.download_file = Mock(return_value=True)
    
    return client


@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary directory for test configurations"""
    config_dir = tmp_path / "test_config"
    config_dir.mkdir()
    
    # Create test config files
    (config_dir / "ossec.conf").write_text("<ossec_config><test>value</test></ossec_config>")
    (config_dir / "local_options").write_text("log.level=INFO")
    (config_dir / "api_config").write_text("jwt_enabled=true")
    (config_dir / "passwords.txt").write_text("admin:test_password123456789012345")
    
    return config_dir


@pytest.fixture
def mock_file_handler():
    """Mock FileHandler for testing"""
    from wazuh_configurator.utils.file_handler import FileHandler
    
    with patch.object(FileHandler, 'read_file', return_value="test content"):
        with patch.object(FileHandler, 'write_file', return_value=True):
            with patch.object(FileHandler, 'backup_file', return_value=True):
                with patch.object(FileHandler, 'restore_file', return_value=True):
                    yield FileHandler


@pytest.fixture
def mock_cache():
    """Mock cache decorator for testing"""
    from wazuh_configurator.utils.cache import Cache
    
    cache = Mock(spec=Cache)
    cache._get = Mock(return_value=None)
    cache._set = Mock()
    cache._clear = Mock()
    
    return cache
