"""
Rule generation with strategy pattern
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel

from ..generator import RuleDefinition


class RuleStrategy(ABC):
    """Abstract strategy for rule generation"""
    
    @abstractmethod
    def generate_rules(self, theme: str) -> List[RuleDefinition]:
        """Generate rules for a specific theme"""
        pass


class GitRuleStrategy(RuleStrategy):
    """Strategy for Git-related rules"""
    
    def generate_rules(self, theme: str) -> List[RuleDefinition]:
        return [
            RuleDefinition(
                rule_id=101001, level=10, title="Git clone depuis IP externe",
                description="Détection de clone git depuis adresse IP externe non whitelistée",
                mitre="T1213", regex=r"git clone.*(http|ssh)://",
                group="git,devsec", anti_fp_list="whitelist_internal_ips"
            ),
            RuleDefinition(
                rule_id=101002, level=12, title="Git credential extraction",
                description="Tentative d'extraction des credentials git",
                mitre="T1552.001", regex=r"git.*(credential|token|password)",
                group="git,devsec"
            ),
            RuleDefinition(
                rule_id=101003, level=8, title="Git push vers repo externe",
                description="Push git vers repository externe non autorisé",
                mitre="T1567.001", regex=r"git push.*origin",
                group="git,devsec", anti_fp_list="whitelist_internal_ips"
            ),
            RuleDefinition(
                rule_id=101004, level=11, title="Git config modification",
                description="Modification de configuration git suspecte",
                mitre="T1565.001", regex=r"git config.*user\.(email|name)",
                group="git,devsec"
            ),
            RuleDefinition(
                rule_id=101005, level=9, title="Git stash pop sur code sensible",
                description="Restauration de git stash contenant du code sensible",
                mitre="T1560.001", regex=r"git stash pop|git stash apply",
                group="git,devsec"
            ),
            RuleDefinition(
                rule_id=101006, level=13, title="Git force push destructif",
                description="Force push écrasant l'historique git",
                mitre="T1565.001", regex=r"git push.*--force",
                group="git,devsec"
            ),
        ]


class IDERuleStrategy(RuleStrategy):
    """Strategy for IDE-related rules"""
    
    def generate_rules(self, theme: str) -> List[RuleDefinition]:
        return [
            RuleDefinition(
                rule_id=102001, level=9, title="VSCode/IntelliJ lance process suspect",
                description="IDE lance des commandes system suspectes",
                mitre="T1059", regex=r"(code|idea).*?(powershell|curl|wget)",
                group="ide,devsec"
            ),
            RuleDefinition(
                rule_id=102002, level=10, title="Extension IDE installation non autorisée",
                description="Installation d'extensions IDE depuis source externe",
                mitre="T1195.002", regex=r"(code|idea).*install.*extension",
                group="ide,devsec"
            ),
            RuleDefinition(
                rule_id=102003, level=8, title="IDE debug sur process système",
                description="Session de debug IDE sur processus système",
                mitre="T1055.001", regex=r"(code|idea).*debug.*attach",
                group="ide,devsec"
            ),
            RuleDefinition(
                rule_id=102004, level=11, title="IDE terminal execution non whitelistée",
                description="Exécution de commandes via terminal IDE",
                mitre="T1059", regex=r"(code|idea).*terminal.*exec",
                group="ide,devsec"
            ),
            RuleDefinition(
                rule_id=102005, level=7, title="IDE file access patterns",
                description="Accès fichiers patterns suspects depuis IDE",
                mitre="T1083", regex=r"(code|idea).*open.*(\.env|\.key|\.pem)",
                group="ide,devsec"
            ),
        ]


class DockerRuleStrategy(RuleStrategy):
    """Strategy for Docker-related rules"""
    
    def generate_rules(self, theme: str) -> List[RuleDefinition]:
        return [
            RuleDefinition(
                rule_id=104001, level=13, title="Docker --privileged ou host mount",
                description="Docker lancé avec privilèges ou mount host",
                mitre="T1610", regex=r"docker run.*(--privileged|--mount.*host)",
                group="docker"
            ),
            RuleDefinition(
                rule_id=104002, level=11, title="Docker socket mount",
                description="Mount du socket docker dans container",
                mitre="T1610", regex=r"docker run.*-v.*docker.sock",
                group="docker"
            ),
            RuleDefinition(
                rule_id=104003, level=10, title="Docker image from private registry",
                description="Pull d'image depuis registry privée non autorisée",
                mitre="T1195.002", regex=r"docker pull.*(internal|private)",
                group="docker"
            ),
            RuleDefinition(
                rule_id=104004, level=12, title="Docker exec shell access",
                description="Accès shell dans container docker",
                mitre="T1059", regex=r"docker exec.*(/bin/bash|/bin/sh)",
                group="docker"
            ),
            RuleDefinition(
                rule_id=104005, level=9, title="Docker volume mount sensitive",
                description="Mount de volumes sensibles dans container",
                mitre="T1083", regex=r"docker run.*-v.*(etc|root|home)",
                group="docker"
            ),
        ]


class RuleGenerator:
    """Main rule generator using strategy pattern"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.templates_dir = Path("wazuh_devsec_config_generator/templates")
        self.env = Environment(loader=FileSystemLoader(self.templates_dir))
        self.strategies: Dict[str, RuleStrategy] = {
            "git": GitRuleStrategy(),
            "ide": IDERuleStrategy(),
            "docker": DockerRuleStrategy(),
        }
    
    def register_strategy(self, theme: str, strategy: RuleStrategy) -> None:
        """Register a new rule strategy"""
        self.strategies[theme] = strategy
    
    def generate_rules(self, enabled_themes: List[str]) -> Dict[str, Any]:
        """Generate rules for enabled themes"""
        rules_dir = self.output_dir / "etc/rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        rule_template = self.env.get_template("rule.jinja")
        generated_rules = {}
        
        for theme in enabled_themes:
            if theme not in self.strategies:
                continue
                
            strategy = self.strategies[theme]
            rules = strategy.generate_rules(theme)
            
            # Generate XML file
            content = f'<group name="devsec,{theme}">\n'
            for rule in rules:
                content += rule_template.render(rule=rule.dict()) + "\n"
            content += "</group>"
            
            filename = f"10{theme}_rules.xml"
            (rules_dir / filename).write_text(content, encoding="utf-8")
            
            generated_rules[theme] = {
                "count": len(rules),
                "file": filename,
                "rules": rules
            }
        
        return generated_rules
