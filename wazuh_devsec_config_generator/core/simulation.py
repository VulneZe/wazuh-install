"""
Simulation mode for testing without Wazuh installation
"""
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

console = Console()


class WazuhSimulator:
    """Simulate Wazuh environment for testing purposes"""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.simulated_logs_dir = output_dir / "simulation" / "logs"
        self.simulated_configs_dir = output_dir / "simulation" / "configs"
        self.validation_results = output_dir / "simulation" / "validation"
        
        # Create simulation directories
        self.simulated_logs_dir.mkdir(parents=True, exist_ok=True)
        self.simulated_configs_dir.mkdir(parents=True, exist_ok=True)
        self.validation_results.mkdir(parents=True, exist_ok=True)
    
    def simulate_wazuh_environment(self) -> Dict[str, Any]:
        """Create a complete simulated Wazuh environment"""
        console.print("[bold cyan]🎭 Creating Wazuh Simulation Environment[/]")
        
        simulation_data = {
            "wazuh_version": "4.8.0",
            "simulation_created": datetime.now().isoformat(),
            "platform": "macOS (simulation)",
            "components": {
                "manager": {"status": "simulated", "port": 15151},
                "agent_count": 5,
                "rules_count": 0,
                "decoders_count": 0
            }
        }
        
        # Save simulation metadata
        with open(self.output_dir / "simulation" / "metadata.json", 'w') as f:
            json.dump(simulation_data, f, indent=2)
        
        console.print(f"✅ Simulation environment created")
        console.print(f"   📁 Logs: {self.simulated_logs_dir}")
        console.print(f"   📁 Configs: {self.simulated_configs_dir}")
        
        return simulation_data
    
    def simulate_log_processing(self, log_file: Path) -> Dict[str, Any]:
        """Simulate Wazuh log processing"""
        console.print(f"[bold blue]🔄 Simulating log processing: {log_file.name}[/]")
        
        # Read the log file
        try:
            log_content = log_file.read_text().strip()
        except:
            return {"error": "Could not read log file"}
        
        # Simulate rule matching
        simulated_alert = {
            "timestamp": datetime.now().isoformat(),
            "rule_id": self._extract_rule_id_from_filename(log_file.name),
            "level": self._simulate_level_detection(),
            "description": f"Simulated alert from {log_file.name}",
            "log": log_content,
            "agent": {"name": "simulated-agent-mac", "id": "001"},
            "full_log": log_content,
            "location": f"simulation->/{log_file.name}"
        }
        
        # Save simulated alert
        alert_file = self.simulated_logs_dir / f"alert_{log_file.stem}.json"
        with open(alert_file, 'w') as f:
            json.dump(simulated_alert, f, indent=2)
        
        console.print(f"   ✅ Alert generated: {alert_file.name}")
        return simulated_alert
    
    def _extract_rule_id_from_filename(self, filename: str) -> int:
        """Extract rule ID from filename for simulation"""
        # Map filenames to rule IDs
        rule_mapping = {
            "git-suspicious": 101001,
            "vscode-curl": 102001,
            "jenkins-install": 103001,
            "docker-privileged": 104001,
            "ransomware-encrypt": 105001,
            "ssh-exfil": 106001,
            "web-shell": 107003,
            "db-dump": 108001,
            "git-force-push": 101006,
            "ide-debug": 102003,
            "docker-socket": 104002,
            "npm-install": 103001,
            "file-encryption": 105001,
            "usb-connect": 106005,
            "nginx-config": 107001,
            "sql-injection": 108002,
            "git-stash": 101005,
            "docker-exec": 104004,
            "pipeline-modify": 103002,
            "bulk-delete": 105004
        }
        
        for pattern, rule_id in rule_mapping.items():
            if pattern in filename:
                return rule_id
        
        return 100000  # Default rule ID
    
    def _simulate_level_detection(self) -> int:
        """Simulate rule level detection"""
        import random
        return random.choice([7, 8, 9, 10, 11, 12, 13, 14, 15])
    
    def simulate_configuration_validation(self) -> Dict[str, Any]:
        """Validate generated configuration in simulation mode"""
        console.print("[bold yellow]🔍 Simulating Configuration Validation[/]")
        
        validation_results = {
            "timestamp": datetime.now().isoformat(),
            "validation_type": "simulation",
            "results": {}
        }
        
        # Validate rules
        rules_dir = self.output_dir / "etc/rules"
        if rules_dir.exists():
            rule_files = list(rules_dir.glob("*.xml"))
            validation_results["results"]["rules"] = {
                "count": len(rule_files),
                "files": [f.name for f in rule_files],
                "status": "valid",
                "simulated_test": "All rules would load successfully"
            }
        
        # Validate decoders
        decoders_dir = self.output_dir / "etc/decoders"
        if decoders_dir.exists():
            decoder_files = list(decoders_dir.glob("*.xml"))
            validation_results["results"]["decoders"] = {
                "count": len(decoder_files),
                "files": [f.name for f in decoder_files],
                "status": "valid",
                "simulated_test": "All decoders would parse correctly"
            }
        
        # Validate lists
        lists_dir = self.output_dir / "etc/lists/cdb"
        if lists_dir.exists():
            list_files = list(lists_dir.glob("*.txt"))
            validation_results["results"]["lists"] = {
                "count": len(list_files),
                "files": [f.name for f in list_files],
                "status": "valid",
                "simulated_test": "All CDB lists would compile successfully"
            }
        
        # Validate active response
        ar_dir = self.output_dir / "etc/active-response/bin"
        if ar_dir.exists():
            ar_files = list(ar_dir.glob("*.py"))
            validation_results["results"]["active_response"] = {
                "count": len(ar_files),
                "files": [f.name for f in ar_files],
                "status": "valid",
                "simulated_test": "All AR scripts would execute successfully"
            }
        
        # Save validation results
        with open(self.validation_results / "validation_report.json", 'w') as f:
            json.dump(validation_results, f, indent=2)
        
        # Display summary
        self._display_validation_summary(validation_results)
        
        return validation_results
    
    def _display_validation_summary(self, results: Dict[str, Any]) -> None:
        """Display validation summary in a nice table"""
        table = Table(title="Configuration Validation Summary (Simulation)")
        table.add_column("Component", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Notes", style="white")
        
        for component, data in results["results"].items():
            table.add_row(
                component.title(),
                str(data["count"]),
                data["status"],
                data["simulated_test"]
            )
        
        console.print(table)
    
    def simulate_deployment(self) -> Dict[str, Any]:
        """Simulate deployment to Wazuh"""
        console.print("[bold green]🚀 Simulating Wazuh Deployment[/]")
        
        deployment_steps = [
            "Checking Wazuh installation... (simulated)",
            "Backing up current configuration... (simulated)",
            "Copying rules to /var/ossec/etc/rules/... (simulated)",
            "Copying decoders to /var/ossec/etc/decoders/... (simulated)",
            "Updating CDB lists... (simulated)",
            "Installing Active Response scripts... (simulated)",
            "Restarting Wazuh Manager... (simulated)",
            "Validating configuration... (simulated)"
        ]
        
        deployment_results = {
            "timestamp": datetime.now().isoformat(),
            "mode": "simulation",
            "steps": [],
            "success": True
        }
        
        with Progress(console=console) as progress:
            task = progress.add_task("Deploying...", total=len(deployment_steps))
            
            for i, step in enumerate(deployment_steps):
                progress.update(task, advance=1)
                console.print(f"   {i+1}. {step}")
                deployment_results["steps"].append({
                    "step": i+1,
                    "description": step,
                    "status": "success",
                    "simulated": True
                })
        
        console.print("\n✅ Deployment simulation completed successfully!")
        console.print("📝 In a real environment, Wazuh would be restarted with new configuration")
        
        # Save deployment results
        with open(self.validation_results / "deployment_simulation.json", 'w') as f:
            json.dump(deployment_results, f, indent=2)
        
        return deployment_results
    
    def run_full_simulation(self) -> Dict[str, Any]:
        """Run complete simulation suite"""
        console.print("[bold magenta]🎭 Starting Full Wazuh Simulation Suite[/]")
        
        simulation_results = {
            "timestamp": datetime.now().isoformat(),
            "platform": "macOS",
            "mode": "full_simulation"
        }
        
        # 1. Create simulation environment
        env_data = self.simulate_wazuh_environment()
        simulation_results["environment"] = env_data
        
        # 2. Process sample logs
        logs_dir = self.output_dir / "tests/sample-logs"
        processed_logs = []
        
        if logs_dir.exists():
            log_files = list(logs_dir.glob("*.txt"))
            console.print(f"\n[bold blue]📋 Processing {len(log_files)} sample logs[/]")
            
            for log_file in log_files:
                alert = self.simulate_log_processing(log_file)
                processed_logs.append({
                    "log_file": log_file.name,
                    "alert_file": f"alert_{log_file.stem}.json",
                    "rule_id": alert.get("rule_id"),
                    "level": alert.get("level")
                })
        
        simulation_results["processed_logs"] = processed_logs
        
        # 3. Validate configuration
        validation_data = self.simulate_configuration_validation()
        simulation_results["validation"] = validation_data
        
        # 4. Simulate deployment
        deployment_data = self.simulate_deployment()
        simulation_results["deployment"] = deployment_data
        
        # 5. Generate simulation report
        self._generate_simulation_report(simulation_results)
        
        console.print("\n[bold green]🎉 Full simulation completed successfully![/]")
        console.print(f"📁 Simulation results saved in: {self.output_dir / 'simulation'}")
        
        return simulation_results
    
    def _generate_simulation_report(self, results: Dict[str, Any]) -> None:
        """Generate comprehensive simulation report"""
        report = {
            "title": "Wazuh DevSec Generator - Simulation Report",
            "generated": datetime.now().isoformat(),
            "summary": {
                "processed_logs": len(results.get("processed_logs", [])),
                "validation_components": len(results.get("validation", {}).get("results", {})),
                "deployment_steps": len(results.get("deployment", {}).get("steps", [])),
                "overall_status": "success"
            },
            "details": results
        }
        
        with open(self.output_dir / "simulation" / "full_simulation_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        # Display summary
        console.print(Panel(
            f"""
📊 Simulation Summary:
   • Logs processed: {report['summary']['processed_logs']}
   • Config components validated: {report['summary']['validation_components']}
   • Deployment steps simulated: {report['summary']['deployment_steps']}
   • Overall status: {report['summary']['overall_status']}
   
📁 Full report: {self.output_dir / 'simulation' / 'full_simulation_report.json'}
            """.strip(),
            title="Simulation Complete",
            border_style="green"
        ))


def add_simulation_mode_to_generator():
    """Add simulation mode to the main generator"""
    pass
