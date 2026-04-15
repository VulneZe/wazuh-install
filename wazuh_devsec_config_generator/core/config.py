"""
Configuration management with profiles and settings
"""
from pathlib import Path
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class ProfileType(str, Enum):
    DEV = "dev"
    PRODUCTION = "production"
    TESTING = "testing"
    CUSTOM = "custom"


class IntegrationType(str, Enum):
    VIRUSTOTAL = "virustotal"
    SURICATA = "suricata"
    ELASTICSEARCH = "elasticsearch"
    THEHIVE = "thehive"
    MISP = "misp"


class WazuhProfile(BaseModel):
    """Profile configuration for different deployment scenarios"""
    name: str
    type: ProfileType
    description: str
    rules_enabled: List[str] = Field(default_factory=list)
    integrations: List[IntegrationType] = Field(default_factory=list)
    custom_settings: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class ConfigManager:
    """Centralized configuration management"""
    
    def __init__(self, config_dir: Path = Path("config")):
        self.config_dir = config_dir
        self.config_dir.mkdir(exist_ok=True)
        self.profiles_file = self.config_dir / "profiles.json"
        self.settings_file = self.config_dir / "settings.json"
        self._profiles: Dict[str, WazuhProfile] = {}
        self._current_profile: Optional[str] = None
        self._load_default_profiles()
        self._load_profiles()
    
    def _load_default_profiles(self):
        """Load default built-in profiles"""
        default_profiles = {
            "dev": WazuhProfile(
                name="Development",
                type=ProfileType.DEV,
                description="Development environment with comprehensive monitoring",
                rules_enabled=["git", "ide", "cicd", "docker"],
                integrations=[IntegrationType.VIRUSTOTAL]
            ),
            "production": WazuhProfile(
                name="Production",
                type=ProfileType.PRODUCTION,
                description="Production environment with security-focused rules",
                rules_enabled=["ransomware", "insider", "web", "database", "docker"],
                integrations=[IntegrationType.SURICATA, IntegrationType.ELASTICSEARCH]
            ),
            "testing": WazuhProfile(
                name="Testing",
                type=ProfileType.TESTING,
                description="Testing environment with all features enabled",
                rules_enabled=["git", "ide", "cicd", "docker", "ransomware", "insider", "web", "database"],
                integrations=list(IntegrationType)
            )
        }
        
        if not self.profiles_file.exists():
            self._save_profiles(default_profiles)
        else:
            self._profiles = default_profiles
    
    def _load_profiles(self):
        """Load profiles from JSON file"""
        if self.profiles_file.exists():
            import json
            with open(self.profiles_file, 'r') as f:
                data = json.load(f)
                for name, profile_data in data.items():
                    self._profiles[name] = WazuhProfile(**profile_data)
    
    def _save_profiles(self, profiles: Optional[Dict[str, WazuhProfile]] = None):
        """Save profiles to JSON file"""
        import json
        profiles_to_save = profiles or self._profiles
        with open(self.profiles_file, 'w') as f:
            json.dump(
                {name: profile.dict() for name, profile in profiles_to_save.items()},
                f, 
                indent=2,
                default=str
            )
    
    def get_profile(self, name: str) -> Optional[WazuhProfile]:
        """Get a specific profile by name"""
        return self._profiles.get(name)
    
    def list_profiles(self) -> List[str]:
        """List all available profiles"""
        return list(self._profiles.keys())
    
    def set_current_profile(self, name: str) -> bool:
        """Set the current active profile"""
        if name in self._profiles:
            self._current_profile = name
            return True
        return False
    
    def get_current_profile(self) -> Optional[WazuhProfile]:
        """Get the current active profile"""
        if self._current_profile:
            return self._profiles.get(self._current_profile)
        return None
    
    def add_profile(self, profile: WazuhProfile) -> None:
        """Add a new profile"""
        self._profiles[profile.name] = profile
        self._save_profiles()
    
    def remove_profile(self, name: str) -> bool:
        """Remove a profile"""
        if name in self._profiles and name not in ["dev", "production", "testing"]:
            del self._profiles[name]
            self._save_profiles()
            return True
        return False
