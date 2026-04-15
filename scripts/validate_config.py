#!/usr/bin/env python3
"""
Wazuh Configuration Validation Script
Validates generated configuration files without requiring Wazuh installation
"""

import sys
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from datetime import datetime

console = Console()


class ConfigValidator:
    """Validate Wazuh configuration files"""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.validation_results = {
            "timestamp": datetime.now().isoformat(),
            "config_dir": str(config_dir),
            "validations": {},
            "summary": {"total": 0, "passed": 0, "failed": 0, "warnings": 0}
        }
    
    def validate_all(self) -> Dict[str, Any]:
        """Run all validation checks"""
        console.print("[bold cyan]🔍 Starting Configuration Validation[/]")
        
        with Progress(console=console) as progress:
            task = progress.add_task("Validating configuration...", total=6)
            
            # Validate rules
            progress.update(task, description="Validating rules...")
            self.validate_rules()
            progress.advance(task)
            
            # Validate decoders
            progress.update(task, description="Validating decoders...")
            self.validate_decoders()
            progress.advance(task)
            
            # Validate CDB lists
            progress.update(task, description="Validating CDB lists...")
            self.validate_cdb_lists()
            progress.advance(task)
            
            # Validate active response
            progress.update(task, description="Validating active response...")
            self.validate_active_response()
            progress.advance(task)
            
            # Validate ossec.conf fragments
            progress.update(task, description="Validating ossec.conf...")
            self.validate_ossec_conf()
            progress.advance(task)
            
            # Validate dashboards
            progress.update(task, description="Validating dashboards...")
            self.validate_dashboards()
            progress.advance(task)
        
        self._generate_report()
        return self.validation_results
    
    def validate_rules(self) -> None:
        """Validate rule XML files"""
        rules_dir = self.config_dir / "etc/rules"
        if not rules_dir.exists():
            self._add_validation_result("rules", "failed", "Rules directory not found")
            return
        
        rule_files = list(rules_dir.glob("*.xml"))
        validation_data = {
            "files_found": len(rule_files),
            "files_valid": 0,
            "rules_count": 0,
            "issues": []
        }
        
        for rule_file in rule_files:
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                # Check XML structure
                if root.tag in ["group", "rule"]:
                    validation_data["files_valid"] += 1
                    
                    # Count rules
                    rules = root.findall(".//rule")
                    validation_data["rules_count"] += len(rules)
                    
                    # Validate rule structure
                    for rule in rules:
                        rule_id = rule.get("id")
                        level = rule.get("level")
                        
                        if not rule_id:
                            validation_data["issues"].append(f"{rule_file.name}: Rule missing ID")
                        if not level:
                            validation_data["issues"].append(f"{rule_file.name}: Rule missing level")
                        if rule_id and not rule_id.isdigit():
                            validation_data["issues"].append(f"{rule_file.name}: Invalid rule ID format")
                
            except ET.ParseError as e:
                validation_data["issues"].append(f"{rule_file.name}: XML parsing error - {e}")
            except Exception as e:
                validation_data["issues"].append(f"{rule_file.name}: Unexpected error - {e}")
        
        status = "passed" if validation_data["files_valid"] == len(rule_files) and not validation_data["issues"] else "failed"
        self._add_validation_result("rules", status, validation_data)
    
    def validate_decoders(self) -> None:
        """Validate decoder XML files"""
        decoders_dir = self.config_dir / "etc/decoders"
        if not decoders_dir.exists():
            self._add_validation_result("decoders", "failed", "Decoders directory not found")
            return
        
        decoder_files = list(decoders_dir.glob("*.xml"))
        validation_data = {
            "files_found": len(decoder_files),
            "files_valid": 0,
            "decoders_count": 0,
            "issues": []
        }
        
        for decoder_file in decoder_files:
            try:
                tree = ET.parse(decoder_file)
                root = tree.getroot()
                
                # Check XML structure
                if root.tag == "decoder":
                    validation_data["files_valid"] += 1
                    validation_data["decoders_count"] += 1
                    
                    # Validate decoder structure
                    name = root.get("name")
                    if not name:
                        validation_data["issues"].append(f"{decoder_file.name}: Decoder missing name")
                
            except ET.ParseError as e:
                validation_data["issues"].append(f"{decoder_file.name}: XML parsing error - {e}")
            except Exception as e:
                validation_data["issues"].append(f"{decoder_file.name}: Unexpected error - {e}")
        
        status = "passed" if validation_data["files_valid"] == len(decoder_files) and not validation_data["issues"] else "failed"
        self._add_validation_result("decoders", status, validation_data)
    
    def validate_cdb_lists(self) -> None:
        """Validate CDB list files"""
        lists_dir = self.config_dir / "etc/lists/cdb"
        if not lists_dir.exists():
            self._add_validation_result("cdb_lists", "failed", "CDB lists directory not found")
            return
        
        list_files = list(lists_dir.glob("*.txt"))
        validation_data = {
            "files_found": len(list_files),
            "files_valid": 0,
            "total_entries": 0,
            "issues": []
        }
        
        for list_file in list_files:
            try:
                content = list_file.read_text(encoding='utf-8')
                lines = [line.strip() for line in content.split('\n') if line.strip()]
                
                validation_data["files_valid"] += 1
                validation_data["total_entries"] += len(lines)
                
                # Check for common CDB format issues
                for i, line in enumerate(lines, 1):
                    if ':' in line and len(line.split(':')) < 2:
                        validation_data["issues"].append(f"{list_file.name}:{i} - Invalid CDB key:value format")
                
            except Exception as e:
                validation_data["issues"].append(f"{list_file.name}: Read error - {e}")
        
        status = "passed" if validation_data["files_valid"] == len(list_files) and not validation_data["issues"] else "failed"
        self._add_validation_result("cdb_lists", status, validation_data)
    
    def validate_active_response(self) -> None:
        """Validate active response scripts and commands"""
        ar_dir = self.config_dir / "etc/active-response"
        if not ar_dir.exists():
            self._add_validation_result("active_response", "failed", "Active response directory not found")
            return
        
        validation_data = {
            "scripts_found": 0,
            "scripts_valid": 0,
            "commands_found": 0,
            "commands_valid": 0,
            "issues": []
        }
        
        # Validate scripts
        scripts_dir = ar_dir / "bin"
        if scripts_dir.exists():
            script_files = list(scripts_dir.glob("*.py"))
            validation_data["scripts_found"] = len(script_files)
            
            for script_file in script_files:
                try:
                    content = script_file.read_text()
                    
                    # Basic Python script validation
                    if script_file.suffix == ".py":
                        if "def main(" in content or "if __name__" in content or len(content) > 100:
                            validation_data["scripts_valid"] += 1
                        else:
                            validation_data["issues"].append(f"{script_file.name}: Script appears incomplete")
                
                except Exception as e:
                    validation_data["issues"].append(f"{script_file.name}: Read error - {e}")
        
        # Validate command XML
        commands_dir = ar_dir / "commands"
        if commands_dir.exists():
            command_files = list(commands_dir.glob("*.xml"))
            validation_data["commands_found"] = len(command_files)
            
            for command_file in command_files:
                try:
                    tree = ET.parse(command_file)
                    root = tree.getroot()
                    
                    if root.tag == "command":
                        validation_data["commands_valid"] += 1
                        
                        # Validate required elements
                        name = root.find("name")
                        executable = root.find("executable")
                        
                        if not name or not name.text:
                            validation_data["issues"].append(f"{command_file.name}: Missing command name")
                        if not executable or not executable.text:
                            validation_data["issues"].append(f"{command_file.name}: Missing executable")
                
                except ET.ParseError as e:
                    validation_data["issues"].append(f"{command_file.name}: XML parsing error - {e}")
                except Exception as e:
                    validation_data["issues"].append(f"{command_file.name}: Unexpected error - {e}")
        
        total_valid = validation_data["scripts_valid"] + validation_data["commands_valid"]
        total_found = validation_data["scripts_found"] + validation_data["commands_found"]
        
        status = "passed" if total_valid == total_found and not validation_data["issues"] else "failed"
        self._add_validation_result("active_response", status, validation_data)
    
    def validate_ossec_conf(self) -> None:
        """Validate ossec.conf fragments"""
        conf_dir = self.config_dir / "etc/ossec.conf.d"
        if not conf_dir.exists():
            self._add_validation_result("ossec_conf", "failed", "ossec.conf.d directory not found")
            return
        
        conf_files = list(conf_dir.glob("*.xml"))
        validation_data = {
            "files_found": len(conf_files),
            "files_valid": 0,
            "issues": []
        }
        
        for conf_file in conf_files:
            try:
                tree = ET.parse(conf_file)
                root = tree.getroot()
                
                # Check for valid Wazuh configuration elements
                valid_elements = ["syscheck", "rootcheck", "localfile", "remote", "vulnerability-detection", 
                                "sca", "active-response", "command", "ruleset", "global"]
                
                if root.tag in valid_elements or any(child.tag in valid_elements for child in root):
                    validation_data["files_valid"] += 1
                else:
                    validation_data["issues"].append(f"{conf_file.name}: Unknown configuration element '{root.tag}'")
                
            except ET.ParseError as e:
                validation_data["issues"].append(f"{conf_file.name}: XML parsing error - {e}")
            except Exception as e:
                validation_data["issues"].append(f"{conf_file.name}: Unexpected error - {e}")
        
        status = "passed" if validation_data["files_valid"] == len(conf_files) and not validation_data["issues"] else "failed"
        self._add_validation_result("ossec_conf", status, validation_data)
    
    def validate_dashboards(self) -> None:
        """Validate dashboard JSON files"""
        dashboards_dir = self.config_dir / "dashboards"
        if not dashboards_dir.exists():
            self._add_validation_result("dashboards", "warning", "No dashboards directory found (optional)")
            return
        
        dashboard_files = list(dashboards_dir.glob("*.json"))
        validation_data = {
            "files_found": len(dashboard_files),
            "files_valid": 0,
            "panels_total": 0,
            "issues": []
        }
        
        for dashboard_file in dashboard_files:
            try:
                with open(dashboard_file, 'r') as f:
                    dashboard = json.load(f)
                
                # Validate dashboard structure
                required_fields = ["id", "title", "panels"]
                missing_fields = [field for field in required_fields if field not in dashboard]
                
                if missing_fields:
                    validation_data["issues"].append(f"{dashboard_file.name}: Missing fields {missing_fields}")
                else:
                    validation_data["files_valid"] += 1
                    
                    # Count panels
                    panels = dashboard.get("panels", [])
                    if isinstance(panels, list):
                        validation_data["panels_total"] += len(panels)
                    elif isinstance(panels, dict):
                        validation_data["panels_total"] += 1
                
            except json.JSONDecodeError as e:
                validation_data["issues"].append(f"{dashboard_file.name}: JSON parsing error - {e}")
            except Exception as e:
                validation_data["issues"].append(f"{dashboard_file.name}: Unexpected error - {e}")
        
        status = "passed" if validation_data["files_valid"] == len(dashboard_files) and not validation_data["issues"] else "failed"
        self._add_validation_result("dashboards", status, validation_data)
    
    def _add_validation_result(self, component: str, status: str, data: Dict[str, Any]) -> None:
        """Add validation result"""
        self.validation_results["validations"][component] = {
            "status": status,
            "data": data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Update summary
        self.validation_results["summary"]["total"] += 1
        if status == "passed":
            self.validation_results["summary"]["passed"] += 1
        elif status == "failed":
            self.validation_results["summary"]["failed"] += 1
        elif status == "warning":
            self.validation_results["summary"]["warnings"] += 1
    
    def _generate_report(self) -> None:
        """Generate validation report"""
        # Display summary table
        table = Table(title="Configuration Validation Summary")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Details", style="white")
        
        for component, result in self.validation_results["validations"].items():
            status = result["status"]
            status_icon = {"passed": "✅", "failed": "❌", "warning": "⚠️"}.get(status, "❓")
            
            details = []
            data = result["data"]
            
            if component == "rules":
                details.append(f"{data.get('files_valid', 0)}/{data.get('files_found', 0)} files")
                details.append(f"{data.get('rules_count', 0)} rules")
            elif component == "decoders":
                details.append(f"{data.get('files_valid', 0)}/{data.get('files_found', 0)} files")
                details.append(f"{data.get('decoders_count', 0)} decoders")
            elif component == "cdb_lists":
                details.append(f"{data.get('files_valid', 0)}/{data.get('files_found', 0)} files")
                details.append(f"{data.get('total_entries', 0)} entries")
            elif component == "active_response":
                details.append(f"{data.get('scripts_valid', 0)}/{data.get('scripts_found', 0)} scripts")
                details.append(f"{data.get('commands_valid', 0)}/{data.get('commands_found', 0)} commands")
            elif component == "ossec_conf":
                details.append(f"{data.get('files_valid', 0)}/{data.get('files_found', 0)} files")
            elif component == "dashboards":
                details.append(f"{data.get('files_valid', 0)}/{data.get('files_found', 0)} files")
                details.append(f"{data.get('panels_total', 0)} panels")
            
            if data.get("issues"):
                details.append(f"{len(data['issues'])} issues")
            
            table.add_row(component.title(), f"{status_icon} {status}", ", ".join(details))
        
        console.print(table)
        
        # Display issues if any
        total_issues = sum(len(result["data"].get("issues", [])) for result in self.validation_results["validations"].values())
        
        if total_issues > 0:
            console.print(f"\n[bold red]⚠️  Found {total_issues} issues:[/]")
            for component, result in self.validation_results["validations"].items():
                issues = result["data"].get("issues", [])
                if issues:
                    console.print(f"\n[cyan]{component.title()} Issues:[/]")
                    for issue in issues:
                        console.print(f"   • {issue}")
        
        # Summary panel
        summary = self.validation_results["summary"]
        console.print(Panel(
            f"""
📊 Validation Summary:
   • Total components: {summary['total']}
   • ✅ Passed: {summary['passed']}
   • ❌ Failed: {summary['failed']}
   • ⚠️  Warnings: {summary['warnings']}
   
📁 Full report saved to: {self.config_dir}/validation_report.json
            """.strip(),
            title="Validation Complete",
            border_style="green" if summary["failed"] == 0 else "red"
        ))
        
        # Save detailed report
        report_file = self.config_dir / "validation_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.validation_results, f, indent=2)


def main():
    """Main validation script"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate Wazuh configuration files")
    parser.add_argument("config_dir", help="Path to configuration directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    config_dir = Path(args.config_dir)
    if not config_dir.exists():
        console.print(f"[red]❌ Configuration directory not found: {config_dir}[/]")
        sys.exit(1)
    
    validator = ConfigValidator(config_dir)
    results = validator.validate_all()
    
    # Exit with error code if validation failed
    if results["summary"]["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
