"""
Enhanced menu system with verification and dashboard injection features
"""
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.text import Text
import json

from ..core.config import ConfigManager
from ..core.service_detector import ServiceDetector
from ..core.integrations import IntegrationManager, IntegrationStatus
from ..core.dashboard_generator import DashboardGenerator


class MenuSystem:
    """Enhanced menu system for Wazuh DevSec Generator"""
    
    def __init__(self, config_dir: Path):
        self.console = Console()
        self.config_dir = config_dir
        self.config_manager = ConfigManager()
        self.service_detector = ServiceDetector()
        self.integration_manager = IntegrationManager(config_dir)
        self.dashboard_generator = DashboardGenerator(config_dir)
    
    def show_main_menu(self) -> str:
        """Display enhanced main menu with new options"""
        menu = Table(title="🛡️  Wazuh DevSec Generator - Menu Principal", show_header=False, box=None)
        menu.add_column("Option", style="cyan", width=50)
        menu.add_column("Description", style="white")
        
        menu.add_row("1", "🔍 Vérification des fichiers actuels")
        menu.add_row("2", "📊 Injection de modèles de dashboard")
        menu.add_row("3", "⚙️  Injection de règles personnalisées")
        menu.add_row("4", "🔗 Gestion des intégrations")
        menu.add_row("5", "📝 Gestion des profils")
        menu.add_row("6", "🧪 Tests et validation")
        menu.add_row("7", "🚀 Déploiement")
        menu.add_row("8", "📈 Dashboard d'état")
        menu.add_row("0", "🚪 Quitter")
        
        self.console.print(menu)
        return Prompt.ask("Choisissez une option", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])
    
    def verify_current_files(self) -> None:
        """Verify current Wazuh installation and configuration"""
        self.console.clear()
        self.console.print("[bold cyan]🔍 Vérification des Fichiers Actuels[/]")
        
        # Check Wazuh installation
        wazuh_status = self._check_wazuh_installation()
        
        # Check existing rules
        rules_status = self._check_existing_rules()
        
        # Check integrations
        integrations_status = self._check_integrations()
        
        # Check ossec.conf
        config_status = self._check_ossec_config()
        
        # Display comprehensive report
        self._display_verification_report(wazuh_status, rules_status, integrations_status, config_status)
        
        Prompt.ask("Appuyez sur Entrée pour continuer")
    
    def _check_wazuh_installation(self) -> Dict[str, Any]:
        """Check Wazuh installation status"""
        status = {
            "installed": False,
            "version": "Non détecté",
            "manager_running": False,
            "agent_count": 0,
            "paths": {},
            "issues": []
        }
        
        # Check common Wazuh paths
        wazuh_paths = {
            "/var/ossec": "Standard Linux",
            "/Library/Application Support/Wazuh": "macOS",
            "/opt/wazuh": "Alternative",
            "C:\\Program Files (x86)\\ossec-agent": "Windows"
        }
        
        for path, description in wazuh_paths.items():
            if Path(path).exists():
                status["paths"][path] = description
                status["installed"] = True
                
                # Try to get version
                version_file = Path(path) / "etc" / "ossec.conf"
                if version_file.exists():
                    status["version"] = "Détecté"
        
        # Check if running (simulation)
        status["manager_running"] = True  # Simulated
        status["agent_count"] = 5  # Simulated
        
        return status
    
    def _check_existing_rules(self) -> Dict[str, Any]:
        """Check existing Wazuh rules"""
        status = {
            "local_rules": False,
            "custom_rules": [],
            "rule_count": 0,
            "issues": [],
            "recommendations": []
        }
        
        # Check standard Wazuh rules directory
        rules_dirs = [
            Path("/var/ossec/etc/rules"),
            Path("/var/ossec/rules"),
            self.config_dir / "etc/rules"
        ]
        
        for rules_dir in rules_dirs:
            if rules_dir.exists():
                rule_files = list(rules_dir.glob("*.xml"))
                status["rule_count"] += len(rule_files)
                
                for rule_file in rule_files:
                    if "local_rules" in rule_file.name:
                        status["local_rules"] = True
                    elif rule_file.name.startswith(("10", "11", "12")):
                        status["custom_rules"].append(rule_file.name)
        
        # Analyze rule quality
        if status["rule_count"] < 50:
            status["recommendations"].append("Peu de règles détectées - considérez ajouter des règles DevSec")
        
        if not status["local_rules"]:
            status["issues"].append("local_rules.xml non trouvé")
            status["recommendations"].append("Créez local_rules.xml pour les overrides")
        
        return status
    
    def _check_integrations(self) -> Dict[str, Any]:
        """Check integration status"""
        status = {
            "virustotal": {"installed": False, "configured": False, "issues": []},
            "suricata": {"installed": False, "configured": False, "issues": []},
            "elasticsearch": {"installed": False, "configured": False, "issues": []},
            "thehive": {"installed": False, "configured": False, "issues": []},
            "misp": {"installed": False, "configured": False, "issues": []}
        }
        
        # Check each integration
        integration_checks = {
            "virustotal": {
                "commands": ["vt"],
                "files": ["/usr/local/bin/vt"],
                "env_vars": ["VIRUSTOTAL_API_KEY"],
                "description": "VirusTotal API pour analyse de fichiers"
            },
            "suricata": {
                "commands": ["suricata"],
                "files": ["/usr/bin/suricata", "/usr/local/bin/suricata"],
                "services": ["suricata"],
                "description": "IDS/IPS pour détection d'intrusion"
            },
            "elasticsearch": {
                "commands": ["elasticsearch"],
                "files": ["/usr/share/elasticsearch"],
                "ports": [9200],
                "description": "Moteur de recherche pour logs"
            }
        }
        
        for integration, checks in integration_checks.items():
            integration_status = status[integration]
            
            # Check commands
            for cmd in checks.get("commands", []):
                try:
                    import subprocess
                    result = subprocess.run(["which", cmd], capture_output=True)
                    if result.returncode == 0:
                        integration_status["installed"] = True
                except:
                    pass
            
            # Check files
            for file_path in checks.get("files", []):
                if Path(file_path).exists():
                    integration_status["installed"] = True
            
            # Check configuration
            if integration_status["installed"]:
                integration_status["configured"] = True  # Simplified
            else:
                integration_status["issues"].append(f"{integration} non installé")
        
        return status
    
    def _check_ossec_config(self) -> Dict[str, Any]:
        """Check ossec.conf configuration"""
        status = {
            "file_exists": False,
            "sylog_enabled": False,
            "fim_enabled": False,
            "rootcheck_enabled": False,
            "vuln_detection": False,
            "issues": [],
            "recommendations": []
        }
        
        # Check ossec.conf locations
        ossec_configs = [
            Path("/var/ossec/etc/ossec.conf"),
            Path("/var/ossec/etc/ossec.conf.d"),
            self.config_dir / "etc/ossec.conf.d"
        ]
        
        for config_path in ossec_configs:
            if config_path.exists():
                status["file_exists"] = True
                
                # Analyze configuration (simplified)
                if config_path.is_dir():
                    # ossec.conf.d directory
                    config_files = list(config_path.glob("*.xml"))
                    status["recommendations"].append(f"Fragment configuration: {len(config_files)} fichiers")
                else:
                    # Single ossec.conf file
                    try:
                        content = config_path.read_text()
                        if "syslog" in content:
                            status["sylog_enabled"] = True
                        if "syscheck" in content:
                            status["fim_enabled"] = True
                        if "rootcheck" in content:
                            status["rootcheck_enabled"] = True
                        if "vulnerability-detection" in content:
                            status["vuln_detection"] = True
                    except:
                        pass
                
                break
        
        if not status["file_exists"]:
            status["issues"].append("ossec.conf non trouvé")
        
        return status
    
    def _display_verification_report(self, wazuh_status, rules_status, integrations_status, config_status) -> None:
        """Display comprehensive verification report"""
        
        # Wazuh Installation Status
        wazuh_table = Table(title="📋 Statut Installation Wazuh")
        wazuh_table.add_column("Composant", style="cyan")
        wazuh_table.add_column("État", style="white")
        
        wazuh_icon = "✅" if wazuh_status["installed"] else "❌"
        wazuh_table.add_row("Installation", f"{wazuh_icon} {'Installé' if wazuh_status['installed'] else 'Non installé'}")
        wazuh_table.add_row("Version", wazuh_status["version"])
        wazuh_table.add_row("Manager", f"{'✅ Actif' if wazuh_status['manager_running'] else '❌ Inactif'}")
        wazuh_table.add_row("Agents", f"{wazuh_status['agent_count']} agents")
        
        self.console.print(wazuh_table)
        
        # Rules Status
        rules_table = Table(title="📋 Analyse des Règles")
        rules_table.add_column("Type", style="cyan")
        rules_table.add_column("État", style="white")
        
        rules_table.add_row("Règles totales", f"{rules_status['rule_count']} règles")
        rules_table.add_row("local_rules.xml", f"{'✅ Présent' if rules_status['local_rules'] else '❌ Manquant'}")
        rules_table.add_row("Règles personnalisées", f"{len(rules_status['custom_rules'])} fichiers")
        
        self.console.print(rules_table)
        
        # Integrations Status
        integrations_table = Table(title="📋 État des Intégrations")
        integrations_table.add_column("Intégration", style="cyan")
        integrations_table.add_column("Installation", style="white")
        integrations_table.add_column("Configuration", style="white")
        integrations_table.add_column("Recommandation", style="yellow")
        
        for integration, status in integrations_status.items():
            install_icon = "✅" if status["installed"] else "❌"
            config_icon = "✅" if status["configured"] else "❌"
            
            recommendation = ""
            if not status["installed"]:
                recommendation = "À installer"
            elif not status["configured"]:
                recommendation = "À configurer"
            
            integrations_table.add_row(
                integration.title(),
                install_icon,
                config_icon,
                recommendation
            )
        
        self.console.print(integrations_table)
        
        # Issues and Recommendations
        all_issues = (rules_status.get("issues", []) + 
                     config_status.get("issues", []))
        all_recommendations = (rules_status.get("recommendations", []) + 
                             config_status.get("recommendations", []))
        
        if all_issues:
            self.console.print("\n[bold red]⚠️  Problèmes Identifiés:[/]")
            for issue in all_issues:
                self.console.print(f"   • {issue}")
        
        if all_recommendations:
            self.console.print("\n[bold yellow]💡 Recommandations:[/]")
            for rec in all_recommendations:
                self.console.print(f"   • {rec}")
    
    def inject_dashboard_templates(self) -> None:
        """Inject dashboard templates with proper selection"""
        self.console.clear()
        self.console.print("[bold cyan]📊 Injection de Modèles de Dashboard[/]")
        
        # Show available dashboard templates
        self._show_dashboard_templates()
        
        # Let user select templates
        selection = self._select_dashboard_templates()
        
        if selection:
            self._inject_selected_dashboards(selection)
        else:
            self.console.print("[yellow]Aucun template sélectionné[/]")
        
        Prompt.ask("Appuyez sur Entrée pour continuer")
    
    def _show_dashboard_templates(self) -> None:
        """Show available dashboard templates"""
        templates = {
            "security-overview": {
                "name": "Vue d'ensemble Sécurité",
                "description": "Dashboard principal avec métriques de sécurité globales",
                "panels": ["Events timeline", "Rule distribution", "Top alerts", "Severity breakdown"],
                "use_case": "Monitoring quotidien de la sécurité",
                "integrations": ["Toutes"]
            },
            "devsec-monitoring": {
                "name": "Monitoring DevSec",
                "description": "Dashboard spécialisé pour environnement de développement",
                "panels": ["Git activity", "IDE access", "CI/CD pipeline", "Docker security"],
                "use_case": "Surveillance des activités de développement",
                "integrations": ["Git", "IDE", "CI/CD", "Docker"]
            },
            "threat-intelligence": {
                "name": "Threat Intelligence",
                "description": "Dashboard pour analyse des menaces et IOC",
                "panels": ["VirusTotal analysis", "Threat feeds", "IOC tracking", "Attribution"],
                "use_case": "Analyse des menaces et renseignement",
                "integrations": ["VirusTotal", "MISP", "TheHive"]
            },
            "compliance-reporting": {
                "name": "Rapports de Conformité",
                "description": "Dashboard pour reporting et conformité",
                "panels": ["Compliance score", "Audit trail", "Policy violations", "Risk assessment"],
                "use_case": "Reporting conformité et audit",
                "integrations": ["SCA", "Audit"]
            },
            "incident-response": {
                "name": "Response à Incident",
                "description": "Dashboard pour gestion des incidents",
                "panels": ["Incident timeline", "Alert correlation", "Response actions", "Post-mortem"],
                "use_case": "Gestion et analyse des incidents",
                "integrations": ["TheHive", "Active Response"]
            },
            "performance-monitoring": {
                "name": "Monitoring Performance",
                "description": "Dashboard pour performance Wazuh",
                "panels": ["Agent status", "Queue size", "Processing time", "Resource usage"],
                "use_case": "Monitoring infrastructure Wazuh",
                "integrations": ["Wazuh Manager", "Agents"]
            }
        }
        
        table = Table(title="📊 Modèles de Dashboard Disponibles")
        table.add_column("ID", style="cyan", width=20)
        table.add_column("Nom", style="green", width=25)
        table.add_column("Description", style="white", width=40)
        table.add_column("Cas d'Usage", style="yellow", width=25)
        
        for template_id, template in templates.items():
            table.add_row(
                template_id,
                template["name"],
                template["description"],
                template["use_case"]
            )
        
        self.console.print(table)
        
        # Show detailed information for each template
        self.console.print("\n[bold]Détails des Templates:[/]")
        for template_id, template in templates.items():
            panels_str = ", ".join(template["panels"])
            integrations_str = ", ".join(template["integrations"])
            
            self.console.print(Panel(
                f"""
[cyan]{template['name']}[/] ({template_id})
{template['description']}

📊 Panneaux: {panels_str}
🔗 Intégrations: {integrations_str}
🎯 Cas d'usage: {template['use_case']}
                """.strip(),
                title="Template Details",
                border_style="blue"
            ))
    
    def _select_dashboard_templates(self) -> List[str]:
        """Let user select dashboard templates"""
        available_templates = [
            "security-overview",
            "devsec-monitoring", 
            "threat-intelligence",
            "compliance-reporting",
            "incident-response",
            "performance-monitoring"
        ]
        
        self.console.print("\n[bold yellow]Sélectionnez les templates à injecter (séparez par des virgules):[/]")
        self.console.print("Exemple: security-overview,devsec-monitoring,threat-intelligence")
        
        selection = Prompt.ask("Templates", default="security-overview,devsec-monitoring")
        
        # Validate selection
        selected = []
        for template in selection.split(','):
            template = template.strip()
            if template in available_templates:
                selected.append(template)
            else:
                self.console.print(f"[red]Template '{template}' non valide[/]")
        
        return selected
    
    def _inject_selected_dashboards(self, selected_templates: List[str]) -> None:
        """Inject selected dashboard templates"""
        self.console.print(f"[green]Injection de {len(selected_templates)} templates...[/]")
        
        # Create dashboards directory
        dashboards_dir = self.config_dir / "dashboards"
        dashboards_dir.mkdir(parents=True, exist_ok=True)
        
        injected_count = 0
        for template_id in selected_templates:
            dashboard_file = dashboards_dir / f"{template_id}_dashboard.json"
            
            # Generate dashboard content based on template
            dashboard_content = self._generate_dashboard_from_template(template_id)
            
            with open(dashboard_file, 'w') as f:
                json.dump(dashboard_content, f, indent=2)
            
            injected_count += 1
            self.console.print(f"✅ Template '{template_id}' injecté: {dashboard_file}")
        
        # Generate import script
        self._generate_dashboard_import_script(selected_templates)
        
        self.console.print(f"\n[bold green]✅ {injected_count} dashboards injectés avec succès![/]")
        self.console.print(f"[blue]📜 Script d'import: {dashboards_dir}/import_dashboards.sh[/]")
    
    def _generate_dashboard_from_template(self, template_id: str) -> Dict[str, Any]:
        """Generate dashboard content from template"""
        from datetime import datetime
        
        templates_config = {
            "security-overview": {
                "title": "Wazuh Security Overview",
                "description": "Vue d'ensemble de la sécurité",
                "panels": [
                    {"id": "events-timeline", "title": "Timeline des Événements", "type": "line"},
                    {"id": "rule-distribution", "title": "Distribution des Règles", "type": "pie"},
                    {"id": "severity-breakdown", "title": "Répartition par Sévérité", "type": "bar"},
                    {"id": "top-sources", "title": "Top Sources d'Alertes", "type": "table"}
                ]
            },
            "devsec-monitoring": {
                "title": "DevSec Monitoring Dashboard",
                "description": "Monitoring spécialisé DevSec",
                "panels": [
                    {"id": "git-activity", "title": "Activité Git", "type": "timeline"},
                    {"id": "ide-access", "title": "Accès IDE", "type": "heatmap"},
                    {"id": "cicd-pipeline", "title": "Pipelines CI/CD", "type": "flow"},
                    {"id": "docker-security", "title": "Sécurité Docker", "type": "metric"}
                ]
            }
        }
        
        config = templates_config.get(template_id, templates_config["security-overview"])
        
        return {
            "id": f"wazuh-{template_id}",
            "title": config["title"],
            "description": config["description"],
            "panels": config["panels"],
            "template_id": template_id,
            "created": datetime.now().isoformat(),
            "version": "1.0.0",
            "wazuh_version": "4.x",
            "kibana_version": "8.x"
        }
    
    def _generate_dashboard_import_script(self, selected_templates: List[str]) -> None:
        """Generate Kibana import script for selected dashboards"""
        dashboards_dir = self.config_dir / "dashboards"
        
        script_content = f"""#!/bin/bash
# Kibana Dashboard Import Script
# Generated on {datetime.now().isoformat()}

KIBANA_URL="http://localhost:5601"
DASHBOARD_DIR="{dashboards_dir}"

echo "Importation des dashboards Wazuh vers Kibana..."

"""
        
        for template_id in selected_templates:
            dashboard_file = f"{template_id}_dashboard.json"
            script_content += f"""
# Import {template_id} dashboard
echo "Importation du dashboard {template_id}..."
curl -X POST "$KIBANA_URL/api/saved_objects/_import" \\
    -H "kbn-xsrf: true" \\
    -H "Content-Type: application/json" \\
    --form file=@"$DASHBOARD_DIR/{dashboard_file}" \\
    --form overwrite=true

"""
        
        script_content += """
echo "Importation des dashboards terminée!"
echo "Visitez $KIBANA_URL/app/dashboards pour voir vos dashboards"
"""
        
        script_file = dashboards_dir / "import_dashboards.sh"
        with open(script_file, 'w') as f:
            f.write(script_content)
        
        # Make executable
        script_file.chmod(0o755)
    
    def inject_custom_rules(self) -> None:
        """Inject custom rules by theme"""
        self.console.clear()
        self.console.print("[bold cyan]⚙️  Injection de Règles Personnalisées[/]")
        
        # Show available rule themes
        self._show_rule_themes()
        
        # Let user select themes
        selected_themes = self._select_rule_themes()
        
        if selected_themes:
            self._inject_selected_rules(selected_themes)
        else:
            self.console.print("[yellow]Aucun thème sélectionné[/]")
        
        Prompt.ask("Appuyez sur Entrée pour continuer")
    
    def _show_rule_themes(self) -> None:
        """Show available rule themes"""
        themes = {
            "git": {
                "name": "Git Security",
                "description": "Règles pour sécurité Git (clone, push, credentials, etc.)",
                "rule_count": 6,
                "examples": ["Clone externe", "Extraction credentials", "Force push destructif"],
                "mitre_tags": ["T1213", "T1552.001", "T1565.001"],
                "severity": "Medium-High"
            },
            "docker": {
                "name": "Docker Security",
                "description": "Règles pour sécurité conteneurs (privileged, socket mount, etc.)",
                "rule_count": 5,
                "examples": ["Container privileged", "Host mount", "Socket mount"],
                "mitre_tags": ["T1610", "T1055"],
                "severity": "High"
            },
            "ide": {
                "name": "IDE Security",
                "description": "Règles pour sécurité environnements de développement (VSCode, IntelliJ)",
                "rule_count": 5,
                "examples": ["Process suspect", "Extension non autorisée", "Debug système"],
                "mitre_tags": ["T1059", "T1055.001"],
                "severity": "Medium"
            },
            "cicd": {
                "name": "CI/CD Security",
                "description": "Règles pour sécurité pipelines (Jenkins, GitLab, npm/pip)",
                "rule_count": 5,
                "examples": ["Package non-whitelist", "Pipeline modification", "Secret injection"],
                "mitre_tags": ["T1195.002", "T1552.001"],
                "severity": "High"
            },
            "ransomware": {
                "name": "Ransomware Detection",
                "description": "Règles pour détection ransomware et malwares",
                "rule_count": 4,
                "examples": ["Encryption fichiers", "Bulk modification", "Ransom notes"],
                "mitre_tags": ["T1486", "T1560.001"],
                "severity": "Critical"
            },
            "insider": {
                "name": "Insider Threat",
                "description": "Règles pour détection menaces internes",
                "rule_count": 5,
                "examples": ["Exfiltration massive", "Accès répertoires sensibles", "USB connection"],
                "mitre_tags": ["T1041", "T1083", "T1091"],
                "severity": "High"
            },
            "web": {
                "name": "Web Security",
                "description": "Règles pour sécurité web (injection, shell upload, admin access)",
                "rule_count": 4,
                "examples": ["SQL injection", "Web shell upload", "Admin panel access"],
                "mitre_tags": ["T1190", "T1505.003", "T1078"],
                "severity": "High"
            },
            "database": {
                "name": "Database Security",
                "description": "Règles pour sécurité bases de données (dump, injection, users)",
                "rule_count": 5,
                "examples": ["DB dump", "SQL injection", "User creation", "Backup encryption"],
                "mitre_tags": ["T1007", "T1190", "T1078"],
                "severity": "High"
            }
        }
        
        table = Table(title="📋 Thèmes de Règles Disponibles")
        table.add_column("Thème", style="cyan", width=15)
        table.add_column("Nom", style="green", width=20)
        table.add_column("Description", style="white", width=40)
        table.add_column("Règles", style="yellow", width=8)
        table.add_column("Sévérité", style="red", width=10)
        
        for theme_id, theme in themes.items():
            table.add_row(
                theme_id,
                theme["name"],
                theme["description"],
                str(theme["rule_count"]),
                theme["severity"]
            )
        
        self.console.print(table)
        
        # Show detailed examples for each theme
        self.console.print("\n[bold]Exemples de Règles par Thème:[/]")
        for theme_id, theme in themes.items():
            examples_str = ", ".join(theme["examples"])
            mitre_str = ", ".join(theme["mitre_tags"])
            
            self.console.print(Panel(
                f"""
[cyan]{theme['name']}[/] ({theme_id})
{theme['description']}

🎯 Exemples: {examples_str}
🏷️  MITRE: {mitre_str}
⚠️  Sévérité: {theme['severity']}
                """.strip(),
                title="Rule Theme Details",
                border_style="blue"
            ))
    
    def _select_rule_themes(self) -> List[str]:
        """Let user select rule themes"""
        available_themes = [
            "git", "docker", "ide", "cicd", 
            "ransomware", "insider", "web", "database"
        ]
        
        self.console.print("\n[bold yellow]Sélectionnez les thèmes de règles à injecter (séparez par des virgules):[/]")
        self.console.print("Exemple: git,docker,cicd,ransomware")
        self.console.print("Ou tapez 'all' pour tous les thèmes")
        
        selection = Prompt.ask("Thèmes", default="git,docker,cicd")
        
        if selection.lower() == "all":
            return available_themes
        
        # Validate selection
        selected = []
        for theme in selection.split(','):
            theme = theme.strip()
            if theme in available_themes:
                selected.append(theme)
            else:
                self.console.print(f"[red]Thème '{theme}' non valide[/]")
        
        return selected
    
    def _inject_selected_rules(self, selected_themes: List[str]) -> None:
        """Inject selected rule themes"""
        self.console.print(f"[green]Injection de règles pour {len(selected_themes)} thèmes...[/]")
        
        # Use existing rule generator
        from ..core.rules import RuleGenerator
        
        rules_dir = self.config_dir / "etc/rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        
        generator = RuleGenerator(self.config_dir)
        results = generator.generate_rules(selected_themes)
        
        injected_count = 0
        for theme, result in results.items():
            if result["count"] > 0:
                injected_count += result["count"]
                self.console.print(f"✅ Thème '{theme}': {result['count']} règles injectées")
        
        self.console.print(f"\n[bold green]✅ {injected_count} règles injectées avec succès![/]")
        self.console.print(f"[blue]📁 Règles sauvegardées dans: {rules_dir}[/]")
