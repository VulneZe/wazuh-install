"""
Factory pattern for creating different types of configurations and integrations
"""
from abc import ABC, abstractmethod
from typing import Dict, Type, Any
from pathlib import Path

from .rules import RuleGenerator
from .decoders import DecoderGenerator
from .integrations import IntegrationManager


class GeneratorFactory:
    """Factory for creating different types of generators"""
    
    _generators: Dict[str, Type] = {}
    
    @classmethod
    def register(cls, name: str, generator_class: Type) -> None:
        """Register a new generator type"""
        cls._generators[name] = generator_class
    
    @classmethod
    def create(cls, name: str, **kwargs) -> Any:
        """Create an instance of a registered generator"""
        if name not in cls._generators:
            raise ValueError(f"Unknown generator type: {name}")
        return cls._generators[name](**kwargs)
    
    @classmethod
    def list_generators(cls) -> list:
        """List all registered generator types"""
        return list(cls._generators.keys())


class ConfigurationFactory:
    """Factory for creating complete configurations"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.rule_generator = RuleGenerator(output_dir)
        self.decoder_generator = DecoderGenerator(output_dir)
        self.integration_manager = IntegrationManager(output_dir)
    
    def create_configuration(self, profile_name: str, **kwargs) -> Dict[str, Any]:
        """Create a complete configuration based on profile"""
        from .config import ConfigManager
        config_manager = ConfigManager()
        profile = config_manager.get_profile(profile_name)
        
        if not profile:
            raise ValueError(f"Profile '{profile_name}' not found")
        
        # Generate rules based on profile
        rules_result = self.rule_generator.generate_rules(profile.rules_enabled)
        
        # Generate decoders
        decoders_result = self.decoder_generator.generate_decoders(profile.rules_enabled)
        
        # Setup integrations
        integrations_result = self.integration_manager.setup_integrations([it for it in profile.integrations])
        
        return {
            "profile": profile,
            "rules": rules_result,
            "decoders": decoders_result,
            "integrations": integrations_result,
            "output_dir": str(self.output_dir)
        }


# Register default generators
GeneratorFactory.register("rules", RuleGenerator)
GeneratorFactory.register("decoders", DecoderGenerator)
GeneratorFactory.register("integrations", IntegrationManager)
