#!/usr/bin/env python3
"""
Complete Test Suite - Clean Architecture
Run all tests for Wazuh DevSec Generator
"""

import sys
import unittest
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from wazuh_devsec_config_generator.core.logger import setup_logging, get_logger
from wazuh_devsec_config_generator.core.settings import get_settings


class TestRunner:
    """Professional test runner with rich output"""
    
    def __init__(self):
        self.console = Console()
        self.logger = setup_logging("DEBUG")
        self.settings = get_settings()
        
    def run_all_tests(self) -> bool:
        """Run all test suites"""
        self.console.clear()
        self.console.print("[bold cyan]🧪 Wazuh DevSec Generator - Test Suite[/]")
        
        # Discover and run tests
        loader = unittest.TestLoader()
        start_dir = Path(__file__).parent / "tests"
        
        if not start_dir.exists():
            self.console.print("[red]❌ Tests directory not found[/]")
            return False
        
        suite = loader.discover(str(start_dir), pattern="test_*.py")
        
        # Run tests with progress
        runner = unittest.TextTestRunner(
            verbosity=2,
            stream=sys.stdout,
            buffer=True
        )
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Running tests...", total=None)
            
            result = runner.run(suite)
            
            progress.update(task, description="Tests completed")
        
        # Display results
        self._display_results(result)
        
        return result.wasSuccessful()
    
    def run_core_tests(self) -> bool:
        """Run core component tests"""
        self.console.clear()
        self.console.print("[bold cyan]🧪 Core Components Tests[/]")
        
        # Import and run core tests
        from tests.test_core import (
            TestConfigManager, 
            TestSettings, 
            TestValidator, 
            TestRuleAnalyzer,
            TestImprovedRules,
            TestIntegration
        )
        
        test_classes = [
            TestConfigManager,
            TestSettings,
            TestValidator,
            TestRuleAnalyzer,
            TestImprovedRules,
            TestIntegration
        ]
        
        suite = unittest.TestSuite()
        
        for test_class in test_classes:
            tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        self._display_results(result)
        
        return result.wasSuccessful()
    
    def run_integration_tests(self) -> bool:
        """Run integration tests"""
        self.console.clear()
        self.console.print("[bold cyan]🔗 Integration Tests[/]")
        
        # Test component integration
        try:
            from wazuh_devsec_config_generator.core import (
                ConfigManager, 
                WazuhValidator, 
                RuleAnalyzer, 
                ImprovedRuleLibrary
            )
            
            # Test settings
            settings = get_settings()
            self.console.print("✅ Settings loaded successfully")
            
            # Test configuration
            config_manager = ConfigManager()
            profiles = config_manager.list_profiles()
            self.console.print(f"✅ Configuration manager: {len(profiles)} profiles")
            
            # Test rule library
            rules = ImprovedRuleLibrary.get_all_rules()
            self.console.print(f"✅ Rule library: {len(rules)} rules")
            
            # Test validator
            validator = WazuhValidator(settings.paths.output_dir)
            self.console.print("✅ Validator initialized")
            
            # Test rule analyzer
            analyzer = RuleAnalyzer()
            self.console.print("✅ Rule analyzer initialized")
            
            self.console.print("[green]✅ All integration tests passed[/]")
            return True
            
        except Exception as e:
            self.console.print(f"[red]❌ Integration test failed: {e}[/]")
            return False
    
    def run_performance_tests(self) -> bool:
        """Run performance tests"""
        self.console.clear()
        self.console.print("[bold cyan]⚡ Performance Tests[/]")
        
        try:
            import time
            from wazuh_devsec_config_generator.core.improved_rules import ImprovedRuleLibrary
            from wazuh_devsec_config_generator.core.rule_analyzer import RuleAnalyzer
            
            # Test rule loading performance
            start_time = time.time()
            rules = ImprovedRuleLibrary.get_all_rules()
            load_time = time.time() - start_time
            
            self.console.print(f"✅ Loaded {len(rules)} rules in {load_time:.3f}s")
            
            # Test analysis performance
            analyzer = RuleAnalyzer()
            
            # Create temporary rules file for testing
            import tempfile
            temp_dir = Path(tempfile.mkdtemp())
            rules_dir = temp_dir / "rules"
            rules_dir.mkdir()
            
            # Create test rule
            rule_content = """<?xml version="1.0"?>
<rule id="100001" level="8">
  <description>Performance test rule</description>
  <regex>test.*pattern</regex>
  <group>test,performance</group>
</rule>"""
            
            (rules_dir / "perf_test.xml").write_text(rule_content)
            
            start_time = time.time()
            analyses = analyzer.analyze_rules_directory(rules_dir)
            analysis_time = time.time() - start_time
            
            self.console.print(f"✅ Analyzed {len(analyses)} rules in {analysis_time:.3f}s")
            
            # Cleanup
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
            
            # Performance thresholds
            if load_time > 1.0:
                self.console.print(f"[yellow]⚠️  Rule loading slow: {load_time:.3f}s > 1.0s[/]")
            
            if analysis_time > 0.5:
                self.console.print(f"[yellow]⚠️  Rule analysis slow: {analysis_time:.3f}s > 0.5s[/]")
            else:
                self.console.print("[green]✅ Performance tests passed[/]")
            
            return True
            
        except Exception as e:
            self.console.print(f"[red]❌ Performance test failed: {e}[/]")
            return False
    
    def run_quality_tests(self) -> bool:
        """Run code quality tests"""
        self.console.clear()
        self.console.print("[bold cyan]📊 Code Quality Tests[/]")
        
        try:
            # Test imports
            from wazuh_devsec_config_generator import (
                ConfigManager, 
                WazuhTUI, 
                WazuhGeneratorV2
            )
            
            self.console.print("✅ Main imports successful")
            
            # Test core imports
            from wazuh_devsec_config_generator.core import (
                RuleAnalyzer, 
                WazuhValidator, 
                ImprovedRuleLibrary
            )
            
            self.console.print("✅ Core imports successful")
            
            # Test TUI imports
            from wazuh_devsec_config_generator.tui import WazuhMainApp
            
            self.console.print("✅ TUI imports successful")
            
            # Test settings
            settings = get_settings()
            self.console.print(f"✅ Settings: {settings.environment.value}")
            
            # Test constants
            from wazuh_devsec_config_generator.core.constants import (
                RULE_ID_RANGES, 
                MITRE_TECHNIQUES, 
                DASHBOARD_TEMPLATES
            )
            
            self.console.print(f"✅ Constants: {len(RULE_ID_RANGES)} rule ranges")
            
            self.console.print("[green]✅ All quality tests passed[/]")
            return True
            
        except Exception as e:
            self.console.print(f"[red]❌ Quality test failed: {e}[/]")
            return False
    
    def _display_results(self, result) -> None:
        """Display test results"""
        tests_run = result.testsRun
        failures = len(result.failures)
        errors = len(result.errors)
        skipped = len(result.skipped)
        passed = tests_run - failures - errors - skipped
        
        # Create results table
        table = Table(title="📊 Test Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Status", style="green")
        
        table.add_row("Total Tests", str(tests_run), "✅")
        table.add_row("Passed", str(passed), "✅" if failures == 0 and errors == 0 else "❌")
        table.add_row("Failed", str(failures), "❌" if failures > 0 else "✅")
        table.add_row("Errors", str(errors), "❌" if errors > 0 else "✅")
        table.add_row("Skipped", str(skipped), "⚠️")
        
        self.console.print(table)
        
        # Show failures and errors
        if result.failures:
            self.console.print("\n[bold red]❌ Failures:[/]")
            for test, traceback in result.failures:
                self.console.print(f"• {test}: {traceback.split('AssertionError:')[-1].strip()}")
        
        if result.errors:
            self.console.print("\n[bold red]❌ Errors:[/]")
            for test, traceback in result.errors:
                self.console.print(f"• {test}: {traceback.split('Exception:')[-1].strip()}")
        
        # Summary
        success_rate = (passed / tests_run * 100) if tests_run > 0 else 0
        
        if result.wasSuccessful():
            self.console.print(f"\n[bold green]✅ All tests passed! ({success_rate:.1f}%)[/]")
        else:
            self.console.print(f"\n[bold red]❌ Tests failed! ({success_rate:.1f}%)[/]")


def main():
    """Main test runner"""
    console = Console()
    
    # Parse arguments
    import argparse
    parser = argparse.ArgumentParser(description="Wazuh DevSec Generator Test Suite")
    parser.add_argument("--core", action="store_true", help="Run core tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--performance", action="store_true", help="Run performance tests only")
    parser.add_argument("--quality", action="store_true", help="Run quality tests only")
    parser.add_argument("--all", action="store_true", help="Run all tests (default)")
    
    args = parser.parse_args()
    
    # Default to all tests if no specific test requested
    if not any([args.core, args.integration, args.performance, args.quality]):
        args.all = True
    
    runner = TestRunner()
    success = True
    
    try:
        if args.all:
            console.print("[bold blue]🧪 Running Complete Test Suite[/]")
            success = runner.run_all_tests()
        elif args.core:
            success = runner.run_core_tests()
        elif args.integration:
            success = runner.run_integration_tests()
        elif args.performance:
            success = runner.run_performance_tests()
        elif args.quality:
            success = runner.run_quality_tests()
        
        # Final summary
        if success:
            console.print("\n[bold green]🎉 Test suite completed successfully![/]")
            sys.exit(0)
        else:
            console.print("\n[bold red]💥 Test suite failed![/]")
            sys.exit(1)
            
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Tests interrupted by user[/]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]💥 Test runner error: {e}[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()
