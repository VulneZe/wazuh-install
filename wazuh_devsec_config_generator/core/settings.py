"""
Centralized settings management for Wazuh DevSec Generator
Clean configuration with validation and defaults
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from enum import Enum

from .constants import DEFAULT_CONFIG, RuleCategory
from .config import IntegrationType
from .exceptions import ConfigurationError, ValidationError


class Environment(str, Enum):
    """Environment types"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
    SIMULATION = "simulation"


class LogLevel(str, Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: LogLevel = LogLevel.INFO
    file_enabled: bool = True
    console_enabled: bool = True
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    log_dir: Path = Path("logs")


@dataclass
class PathConfig:
    """Path configuration"""
    output_dir: Path = Path("output/wazuh-custom-devsec")
    template_dir: Path = Path("wazuh_devsec_config_generator/templates")
    data_dir: Path = Path("data")
    log_dir: Path = Path("logs")
    temp_dir: Path = Path("temp")
    
    def __post_init__(self):
        """Ensure paths are absolute"""
        if not self.output_dir.is_absolute():
            self.output_dir = Path.cwd() / self.output_dir
        if not self.template_dir.is_absolute():
            self.template_dir = Path.cwd() / self.template_dir
        if not self.data_dir.is_absolute():
            self.data_dir = Path.cwd() / self.data_dir
        if not self.log_dir.is_absolute():
            self.log_dir = Path.cwd() / self.log_dir
        if not self.temp_dir.is_absolute():
            self.temp_dir = Path.cwd() / self.temp_dir


@dataclass
class ValidationConfig:
    """Validation configuration"""
    strict_mode: bool = False
    fail_on_warnings: bool = False
    max_file_size: int = 1048576  # 1MB
    timeout: int = 30
    retry_attempts: int = 3
    parallel_processing: bool = True
    max_workers: int = 4


@dataclass
class IntegrationConfig:
    """Integration configuration"""
    virustotal_api_key: Optional[str] = None
    virustotal_timeout: int = 30
    suricata_config_path: Optional[Path] = None
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_timeout: int = 30
    thehive_url: str = "http://localhost:9000"
    thehive_api_key: Optional[str] = None
    misp_url: str = "http://localhost"
    misp_api_key: Optional[str] = None
    
    def __post_init__(self):
        """Convert string paths to Path objects"""
        if self.suricata_config_path and isinstance(self.suricata_config_path, str):
            self.suricata_config_path = Path(self.suricata_config_path)


@dataclass
class DashboardConfig:
    """Dashboard configuration"""
    auto_generate: bool = True
    template_dir: Path = Path("templates/dashboards")
    output_dir: Path = Path("dashboards")
    kibana_url: str = "http://localhost:5601"
    import_script_name: str = "import_dashboards.sh"
    
    def __post_init__(self):
        """Ensure paths are absolute"""
        if not self.template_dir.is_absolute():
            self.template_dir = Path.cwd() / self.template_dir
        if not self.output_dir.is_absolute():
            self.output_dir = Path.cwd() / self.output_dir


@dataclass
class SimulationConfig:
    """Simulation configuration"""
    enabled: bool = False
    mock_services: bool = True
    generate_sample_data: bool = True
    validate_deployment: bool = True
    create_reports: bool = True
    report_format: str = "json"  # json, yaml, html


@dataclass
class WazuhSettings:
    """Main settings class"""
    environment: Environment = Environment.DEVELOPMENT
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    paths: PathConfig = field(default_factory=PathConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    integrations: IntegrationConfig = field(default_factory=IntegrationConfig)
    dashboards: DashboardConfig = field(default_factory=DashboardConfig)
    simulation: SimulationConfig = field(default_factory=SimulationConfig)
    
    # Runtime settings
    debug: bool = False
    verbose: bool = False
    quiet: bool = False
    dry_run: bool = False
    
    def __post_init__(self):
        """Post-initialization validation"""
        self._validate_settings()
        self._ensure_directories()
    
    def _validate_settings(self) -> None:
        """Validate settings consistency"""
        # Validate log level
        if self.logging.level not in LogLevel:
            raise ConfigurationError(f"Invalid log level: {self.logging.level}")
        
        # Validate environment
        if self.environment not in Environment:
            raise ConfigurationError(f"Invalid environment: {self.environment}")
        
        # Validate paths
        if not self.paths.output_dir:
            raise ConfigurationError("Output directory cannot be empty")
        
        # Validate validation settings
        if self.validation.max_workers < 1:
            raise ConfigurationError("Max workers must be at least 1")
        
        # Validate simulation settings
        if self.simulation.report_format not in ["json", "yaml", "html"]:
            raise ConfigurationError(f"Invalid report format: {self.simulation.report_format}")
    
    def _ensure_directories(self) -> None:
        """Ensure required directories exist"""
        directories = [
            self.paths.output_dir,
            self.paths.log_dir,
            self.paths.temp_dir,
            self.dashboards.output_dir
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_file(cls, config_file: Path) -> "WazuhSettings":
        """Load settings from configuration file"""
        if not config_file.exists():
            raise ConfigurationError(f"Configuration file not found: {config_file}")
        
        try:
            import json
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            return cls.from_dict(config_data)
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading config file: {e}")
    
    @classmethod
    def from_dict(cls, config_data: Dict[str, Any]) -> "WazuhSettings":
        """Create settings from dictionary"""
        # Extract nested configurations
        logging_data = config_data.get("logging", {})
        paths_data = config_data.get("paths", {})
        validation_data = config_data.get("validation", {})
        integrations_data = config_data.get("integrations", {})
        dashboards_data = config_data.get("dashboards", {})
        simulation_data = config_data.get("simulation", {})
        
        # Create configuration objects
        logging_config = LoggingConfig(**logging_data)
        paths_config = PathConfig(**paths_data)
        validation_config = ValidationConfig(**validation_data)
        integration_config = IntegrationConfig(**integrations_data)
        dashboard_config = DashboardConfig(**dashboards_data)
        simulation_config = SimulationConfig(**simulation_data)
        
        # Create main settings
        settings = cls(
            environment=Environment(config_data.get("environment", "development")),
            logging=logging_config,
            paths=paths_config,
            validation=validation_config,
            integrations=integration_config,
            dashboards=dashboard_config,
            simulation=simulation_config,
            debug=config_data.get("debug", False),
            verbose=config_data.get("verbose", False),
            quiet=config_data.get("quiet", False),
            dry_run=config_data.get("dry_run", False)
        )
        
        return settings
    
    @classmethod
    def from_env(cls) -> "WazuhSettings":
        """Load settings from environment variables"""
        config_data = {}
        
        # Environment mapping
        env_mapping = {
            "WAZUH_ENVIRONMENT": "environment",
            "WAZUH_LOG_LEVEL": "logging.level",
            "WAZUH_OUTPUT_DIR": "paths.output_dir",
            "WAZUH_DEBUG": "debug",
            "WAZUH_VERBOSE": "verbose",
            "WAZUH_QUIET": "quiet",
            "WAZUH_SIMULATION": "simulation.enabled",
            "WAZUH_VIRUSTOTAL_API_KEY": "integrations.virustotal_api_key",
            "WAZUH_ELASTICSEARCH_URL": "integrations.elasticsearch_url",
            "WAZUH_THEHIVE_API_KEY": "integrations.thehive_api_key"
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string to appropriate type
                if value.lower() in ["true", "false"]:
                    value = value.lower() == "true"
                elif value.isdigit():
                    value = int(value)
                
                # Handle nested keys
                keys = config_key.split(".")
                current = config_data
                for key in keys[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]
                current[keys[-1]] = value
        
        return cls.from_dict(config_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary"""
        return {
            "environment": self.environment.value,
            "logging": {
                "level": self.logging.level.value,
                "file_enabled": self.logging.file_enabled,
                "console_enabled": self.logging.console_enabled,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count,
                "log_dir": str(self.logging.log_dir)
            },
            "paths": {
                "output_dir": str(self.paths.output_dir),
                "template_dir": str(self.paths.template_dir),
                "data_dir": str(self.paths.data_dir),
                "log_dir": str(self.paths.log_dir),
                "temp_dir": str(self.paths.temp_dir)
            },
            "validation": {
                "strict_mode": self.validation.strict_mode,
                "fail_on_warnings": self.validation.fail_on_warnings,
                "max_file_size": self.validation.max_file_size,
                "timeout": self.validation.timeout,
                "retry_attempts": self.validation.retry_attempts,
                "parallel_processing": self.validation.parallel_processing,
                "max_workers": self.validation.max_workers
            },
            "integrations": {
                "virustotal_api_key": self.integrations.virustotal_api_key,
                "virustotal_timeout": self.integrations.virustotal_timeout,
                "suricata_config_path": str(self.integrations.suricata_config_path) if self.integrations.suricata_config_path else None,
                "elasticsearch_url": self.integrations.elasticsearch_url,
                "elasticsearch_timeout": self.integrations.elasticsearch_timeout,
                "thehive_url": self.integrations.thehive_url,
                "thehive_api_key": self.integrations.thehive_api_key,
                "misp_url": self.integrations.misp_url,
                "misp_api_key": self.integrations.misp_api_key
            },
            "dashboards": {
                "auto_generate": self.dashboards.auto_generate,
                "template_dir": str(self.dashboards.template_dir),
                "output_dir": str(self.dashboards.output_dir),
                "kibana_url": self.dashboards.kibana_url,
                "import_script_name": self.dashboards.import_script_name
            },
            "simulation": {
                "enabled": self.simulation.enabled,
                "mock_services": self.simulation.mock_services,
                "generate_sample_data": self.simulation.generate_sample_data,
                "validate_deployment": self.simulation.validate_deployment,
                "create_reports": self.simulation.create_reports,
                "report_format": self.simulation.report_format
            },
            "debug": self.debug,
            "verbose": self.verbose,
            "quiet": self.quiet,
            "dry_run": self.dry_run
        }
    
    def save_to_file(self, config_file: Path) -> None:
        """Save settings to configuration file"""
        try:
            import json
            
            config_data = self.to_dict()
            
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2, default=str)
                
        except Exception as e:
            raise ConfigurationError(f"Error saving config file: {e}")
    
    def get_rule_categories(self) -> list:
        """Get enabled rule categories"""
        return [category.value for category in RuleCategory]
    
    def get_enabled_integrations(self) -> list:
        """Get list of enabled integrations"""
        enabled = []
        
        if self.integrations.virustotal_api_key:
            enabled.append(IntegrationType.VIRUSTOTAL)
        
        if self.integrations.suricata_config_path:
            enabled.append(IntegrationType.SURICATA)
        
        if self.integrations.elasticsearch_url:
            enabled.append(IntegrationType.ELASTICSEARCH)
        
        if self.integrations.thehive_api_key:
            enabled.append(IntegrationType.THEHIVE)
        
        if self.integrations.misp_api_key:
            enabled.append(IntegrationType.MISP)
        
        return enabled
    
    def is_simulation_mode(self) -> bool:
        """Check if simulation mode is enabled"""
        return self.simulation.enabled or self.environment == Environment.SIMULATION
    
    def should_validate_strictly(self) -> bool:
        """Check if strict validation should be used"""
        return self.validation.strict_mode or self.environment == Environment.PRODUCTION


# Global settings instance
_settings_instance = None


def get_settings() -> WazuhSettings:
    """Get global settings instance"""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = WazuhSettings.from_env()
    return _settings_instance


def load_settings_from_file(config_file: Path) -> WazuhSettings:
    """Load settings from file and set as global"""
    global _settings_instance
    _settings_instance = WazuhSettings.from_file(config_file)
    return _settings_instance


def create_default_config(config_file: Path) -> None:
    """Create default configuration file"""
    settings = WazuhSettings()
    settings.save_to_file(config_file)
