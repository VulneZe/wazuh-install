#!/usr/bin/env python3
"""
Test Wazuh Rules with Sample Logs
Simulates log processing without requiring Wazuh installation
"""

import sys
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from datetime import datetime
import xml.etree.ElementTree as ET

console = Console()


class LogTester:
    """Test Wazuh rules with sample logs"""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.rules = {}
        self.decoders = {}
        self.test_results = {
            "timestamp": datetime.now().isoformat(),
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "results": []
        }
    
    def load_configuration(self) -> bool:
        """Load rules and decoders from configuration"""
        console.print("[bold cyan]📋 Loading Wazuh Configuration[/]")
        
        # Load rules
        rules_dir = self.config_dir / "etc/rules"
        if rules_dir.exists():
            for rule_file in rules_dir.glob("*.xml"):
                try:
                    tree = ET.parse(rule_file)
                    root = tree.getroot()
                    
                    for rule_elem in root.findall(".//rule"):
                        rule_id = rule_elem.get("id")
                        if rule_id:
                            self.rules[rule_id] = {
                                "element": rule_elem,
                                "file": rule_file.name,
                                "level": rule_elem.get("level"),
                                "description": rule_elem.findtext("description", ""),
                                "regex": rule_elem.findtext("regex", ""),
                                "group": rule_elem.get("group", "")
                            }
                except Exception as e:
                    console.print(f"[red]Error loading rules from {rule_file}: {e}[/]")
        
        # Load decoders
        decoders_dir = self.config_dir / "etc/decoders"
        if decoders_dir.exists():
            for decoder_file in decoders_dir.glob("*.xml"):
                try:
                    tree = ET.parse(decoder_file)
                    root = tree.getroot()
                    
                    for decoder_elem in root.findall(".//decoder"):
                        name = decoder_elem.get("name")
                        if name:
                            self.decoders[name] = {
                                "element": decoder_elem,
                                "file": decoder_file.name,
                                "prematch": decoder_elem.findtext("prematch", ""),
                                "regex": decoder_elem.findtext("regex", "")
                            }
                except Exception as e:
                    console.print(f"[red]Error loading decoders from {decoder_file}: {e}[/]")
        
        console.print(f"✅ Loaded {len(self.rules)} rules and {len(self.decoders)} decoders")
        return len(self.rules) > 0
    
    def test_sample_logs(self, logs_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Test sample logs against loaded rules"""
        if logs_dir is None:
            logs_dir = self.config_dir / "tests/sample-logs"
        
        if not logs_dir.exists():
            console.print(f"[red]❌ Sample logs directory not found: {logs_dir}[/]")
            return self.test_results
        
        log_files = list(logs_dir.glob("*.txt"))
        if not log_files:
            console.print(f"[yellow]⚠️  No log files found in {logs_dir}[/]")
            return self.test_results
        
        console.print(f"[bold blue]🧪 Testing {len(log_files)} sample logs[/]")
        
        # Load expected results if available
        expected_results = self._load_expected_results(logs_dir)
        
        with Progress(console=console) as progress:
            task = progress.add_task("Testing logs...", total=len(log_files))
            
            for log_file in log_files:
                progress.update(task, description=f"Testing {log_file.name}...")
                
                test_result = self._test_single_log(log_file, expected_results)
                self.test_results["results"].append(test_result)
                
                if test_result["matched"]:
                    self.test_results["tests_passed"] += 1
                else:
                    self.test_results["tests_failed"] += 1
                
                self.test_results["tests_run"] += 1
                progress.advance(task)
        
        self._display_test_summary()
        self._save_test_report()
        
        return self.test_results
    
    def _load_expected_results(self, logs_dir: Path) -> Dict[str, int]:
        """Load expected test results from file"""
        expected_file = logs_dir / "expected_results.txt"
        expected_results = {}
        
        if expected_file.exists():
            try:
                content = expected_file.read_text()
                for line in content.split('\n'):
                    if '->' in line:
                        parts = line.split('->')
                        if len(parts) == 2:
                            log_name = parts[0].strip()
                            rule_id = parts[1].strip()
                            expected_results[log_name] = int(rule_id)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not load expected results: {e}[/]")
        
        return expected_results
    
    def _test_single_log(self, log_file: Path, expected_results: Dict[str, int]) -> Dict[str, Any]:
        """Test a single log file against rules"""
        test_result = {
            "log_file": log_file.name,
            "log_content": "",
            "matched": False,
            "matched_rule": None,
            "expected_rule": expected_results.get(log_file.name),
            "match_details": {},
            "test_passed": False
        }
        
        try:
            log_content = log_file.read_text().strip()
            test_result["log_content"] = log_content
            
            # Test against decoders first
            decoded_log = self._apply_decoders(log_content)
            
            # Test against rules
            matched_rule = self._find_matching_rule(decoded_log)
            
            if matched_rule:
                test_result["matched"] = True
                test_result["matched_rule"] = matched_rule["id"]
                test_result["match_details"] = {
                    "rule_id": matched_rule["id"],
                    "level": matched_rule["level"],
                    "description": matched_rule["description"],
                    "regex": matched_rule["regex"]
                }
            
            # Check if test passed (matched expected rule)
            if test_result["expected_rule"]:
                if test_result["matched_rule"] == str(test_result["expected_rule"]):
                    test_result["test_passed"] = True
                else:
                    test_result["test_passed"] = False
            else:
                # No expected result, consider passed if any rule matched
                test_result["test_passed"] = test_result["matched"]
        
        except Exception as e:
            test_result["error"] = str(e)
        
        return test_result
    
    def _apply_decoders(self, log_content: str) -> str:
        """Apply decoders to log content"""
        decoded_log = log_content
        
        for decoder_name, decoder in self.decoders.items():
            prematch = decoder.get("prematch", "")
            if prematch and re.search(prematch, log_content, re.IGNORECASE):
                # Apply decoder regex if available
                regex = decoder.get("regex", "")
                if regex:
                    try:
                        match = re.search(regex, log_content, re.IGNORECASE)
                        if match:
                            # In a real decoder, this would extract fields
                            # For simulation, we just note that decoder matched
                            decoded_log = log_content
                    except re.error:
                        pass
        
        return decoded_log
    
    def _find_matching_rule(self, log_content: str) -> Optional[Dict[str, Any]]:
        """Find rule that matches the log content"""
        for rule_id, rule in self.rules.items():
            regex = rule.get("regex", "")
            if regex:
                try:
                    if re.search(regex, log_content, re.IGNORECASE):
                        return {
                            "id": rule_id,
                            "level": rule.get("level"),
                            "description": rule.get("description"),
                            "regex": regex
                        }
                except re.error:
                    continue
        
        return None
    
    def _display_test_summary(self) -> None:
        """Display test results summary"""
        results = self.test_results
        
        # Summary table
        table = Table(title="Log Testing Summary")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Tests Run", str(results["tests_run"]))
        table.add_row("Tests Passed", str(results["tests_passed"]))
        table.add_row("Tests Failed", str(results["tests_failed"]))
        
        if results["tests_run"] > 0:
            pass_rate = (results["tests_passed"] / results["tests_run"]) * 100
            table.add_row("Pass Rate", f"{pass_rate:.1f}%")
        
        console.print(table)
        
        # Detailed results
        if results["results"]:
            console.print("\n[bold]Detailed Results:[/]")
            
            detail_table = Table()
            detail_table.add_column("Log File", style="cyan")
            detail_table.add_column("Expected", style="white")
            detail_table.add_column("Matched", style="white")
            detail_table.add_column("Status", style="green")
            
            for result in results["results"]:
                expected = str(result["expected_rule"]) if result["expected_rule"] else "N/A"
                matched = result["matched_rule"] if result["matched_rule"] else "None"
                
                if result["test_passed"]:
                    status = "✅ PASS"
                elif result["matched"]:
                    status = "⚠️  MISMATCH"
                else:
                    status = "❌ NO MATCH"
                
                detail_table.add_row(result["log_file"], expected, matched, status)
            
            console.print(detail_table)
        
        # Summary panel
        pass_rate = (results["tests_passed"] / results["tests_run"]) * 100 if results["tests_run"] > 0 else 0
        status = "✅ All tests passed!" if results["tests_failed"] == 0 else f"⚠️  {results['tests_failed']} tests failed"
        
        console.print(Panel(
            f"""
🧪 Log Testing Complete:
   • Tests run: {results['tests_run']}
   • Pass rate: {pass_rate:.1f}%
   • Status: {status}
   
📁 Detailed report: {self.config_dir}/log_test_report.json
            """.strip(),
            title="Testing Summary",
            border_style="green" if results["tests_failed"] == 0 else "yellow"
        ))
    
    def _save_test_report(self) -> None:
        """Save detailed test report"""
        report_file = self.config_dir / "log_test_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)


def main():
    """Main test script"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test Wazuh rules with sample logs")
    parser.add_argument("config_dir", help="Path to configuration directory")
    parser.add_argument("--logs-dir", help="Path to sample logs directory (optional)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    config_dir = Path(args.config_dir)
    if not config_dir.exists():
        console.print(f"[red]❌ Configuration directory not found: {config_dir}[/]")
        sys.exit(1)
    
    logs_dir = Path(args.logs_dir) if args.logs_dir else None
    
    tester = LogTester(config_dir)
    
    if not tester.load_configuration():
        console.print("[red]❌ Failed to load configuration[/]")
        sys.exit(1)
    
    results = tester.test_sample_logs(logs_dir)
    
    # Exit with error code if tests failed
    if results["tests_failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
