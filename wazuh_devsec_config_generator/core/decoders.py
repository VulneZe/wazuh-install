"""
Decoder generation with strategy pattern
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader


class DecoderStrategy(ABC):
    """Abstract strategy for decoder generation"""
    
    @abstractmethod
    def generate_decoders(self) -> List[Dict[str, Any]]:
        """Generate decoders for a specific theme"""
        pass


class GitDecoderStrategy(DecoderStrategy):
    """Strategy for Git-related decoders"""
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "git",
                "prematch": r"git\[\d+\]:",
                "regex": r"git\[(\d+)\]: (.+)"
            },
            {
                "name": "git-auth",
                "prematch": r"git.*authentication",
                "regex": r"git.*authentication.*failed.*for.*(\S+)"
            }
        ]


class IDEDecoderStrategy(DecoderStrategy):
    """Strategy for IDE-related decoders"""
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "dev-ide",
                "prematch": r"code|idea|VSCode",
                "regex": r"(\S+) (\S+)"
            },
            {
                "name": "vscode-extension",
                "prematch": r"VSCode.*extension",
                "regex": r"extension.*(\S+).*installed"
            }
        ]


class DockerDecoderStrategy(DecoderStrategy):
    """Strategy for Docker-related decoders"""
    
    def generate_decoders(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "docker",
                "prematch": r"docker",
                "regex": r"(\S+)\s+(\S+)\s+(.+)"
            },
            {
                "name": "docker-daemon",
                "prematch": r"dockerd",
                "regex": r"dockerd\[(\d+)\]: (.+)"
            }
        ]


class DecoderGenerator:
    """Main decoder generator using strategy pattern"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.templates_dir = Path("wazuh_devsec_config_generator/templates")
        self.env = Environment(loader=FileSystemLoader(self.templates_dir))
        self.strategies: Dict[str, DecoderStrategy] = {
            "git": GitDecoderStrategy(),
            "ide": IDEDecoderStrategy(),
            "docker": DockerDecoderStrategy(),
        }
    
    def register_strategy(self, theme: str, strategy: DecoderStrategy) -> None:
        """Register a new decoder strategy"""
        self.strategies[theme] = strategy
    
    def generate_decoders(self, enabled_themes: List[str]) -> Dict[str, Any]:
        """Generate decoders for enabled themes"""
        decoders_dir = self.output_dir / "etc/decoders"
        decoders_dir.mkdir(parents=True, exist_ok=True)
        
        decoder_template = self.env.get_template("decoder.jinja")
        generated_decoders = {}
        
        for theme in enabled_themes:
            if theme not in self.strategies:
                continue
                
            strategy = self.strategies[theme]
            decoders = strategy.generate_decoders()
            
            # Generate XML file
            content = ""
            for decoder in decoders:
                content += decoder_template.render(**decoder) + "\n"
            
            # Remove trailing newline
            content = content.strip()
            
            filename = f"{theme}-decoder.xml"
            (decoders_dir / filename).write_text(content, encoding="utf-8")
            
            generated_decoders[theme] = {
                "count": len(decoders),
                "file": filename,
                "decoders": decoders
            }
        
        return generated_decoders
