"""
Core Component Tests - Clean Architecture
Unit tests for core Wazuh DevSec Generator components
"""

import unittest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from wazuh_devsec_config_generator.core.config import ConfigManager, WazuhProfile, ProfileType, IntegrationType
from wazuh_devsec_config_generator.core.settings import WazuhSettings, Environment
from wazuh_devsec_config_generator.core.validator import WazuhValidator, ValidationStatus
from wazuh_devsec_config_generator.core.rule_analyzer import RuleAnalyzer, RuleQuality
from wazuh_devsec_config_generator.core.improved_rules import ImprovedRuleLibrary, RuleCategory
from wazuh_devsec_config_generator.core.exceptions import ConfigurationError, ValidationError


class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config_manager = ConfigManager()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_profile(self):
        """Test profile creation"""
        profile = WazuhProfile(
            name="test-profile",
            type=ProfileType.DEVELOPMENT,
            description="Test profile",
            rules_enabled=["git", "docker"],
            integrations=[IntegrationType.VIRUSTOTAL]
        )
        
        self.config_manager.add_profile(profile)
        
        # Verify profile was added
        retrieved = self.config_manager.get_profile("test-profile")
        self.assertEqual(retrieved.name, "test-profile")
        self.assertEqual(retrieved.type, ProfileType.DEVELOPMENT)
        self.assertEqual(retrieved.rules_enabled, ["git", "docker"])
    
    def test_profile_validation(self):
        """Test profile validation"""
        # Valid profile
        valid_profile = WazuhProfile(
            name="valid",
            type=ProfileType.DEVELOPMENT,
            description="Valid profile"
        )
        self.assertTrue(self.config_manager.validate_profile(valid_profile))
        
        # Invalid profile (missing name)
        invalid_profile = WazuhProfile(
            name="",
            type=ProfileType.DEVELOPMENT,
            description="Invalid profile"
        )
        self.assertFalse(self.config_manager.validate_profile(invalid_profile))
    
    def test_profile_persistence(self):
        """Test profile persistence"""
        profile = WazuhProfile(
            name="persist-test",
            type=ProfileType.PRODUCTION,
            description="Persistence test"
        )
        
        self.config_manager.add_profile(profile)
        
        # Create new config manager instance
        new_manager = ConfigManager()
        retrieved = new_manager.get_profile("persist-test")
        
        self.assertEqual(retrieved.name, "persist-test")
        self.assertEqual(retrieved.type, ProfileType.PRODUCTION)


class TestSettings(unittest.TestCase):
    """Test settings management"""
    
    def test_default_settings(self):
        """Test default settings creation"""
        settings = WazuhSettings()
        
        self.assertEqual(settings.environment, Environment.DEVELOPMENT)
        self.assertFalse(settings.debug)
        self.assertFalse(settings.simulation.enabled)
        self.assertTrue(settings.paths.output_dir.exists())
    
    def test_settings_from_dict(self):
        """Test settings creation from dictionary"""
        config_data = {
            "environment": "production",
            "debug": True,
            "simulation": {
                "enabled": True,
                "mock_services": False
            },
            "paths": {
                "output_dir": "/custom/output"
            }
        }
        
        settings = WazuhSettings.from_dict(config_data)
        
        self.assertEqual(settings.environment, Environment.PRODUCTION)
        self.assertTrue(settings.debug)
        self.assertTrue(settings.simulation.enabled)
        self.assertFalse(settings.simulation.mock_services)
    
    def test_settings_validation(self):
        """Test settings validation"""
        # Invalid log level
        config_data = {
            "logging": {
                "level": "INVALID"
            }
        }
        
        with self.assertRaises(ConfigurationError):
            WazuhSettings.from_dict(config_data)
    
    def test_enabled_integrations(self):
        """Test enabled integrations detection"""
        settings = WazuhSettings()
        settings.integrations.virustotal_api_key = "test-key"
        settings.integrations.elasticsearch_url = "http://localhost:9200"
        
        enabled = settings.get_enabled_integrations()
        
        self.assertIn(IntegrationType.VIRUSTOTAL, enabled)
        self.assertIn(IntegrationType.ELASTICSEARCH, enabled)
        self.assertNotIn(IntegrationType.SURICATA, enabled)


class TestValidator(unittest.TestCase):
    """Test validation system"""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.validator = WazuhValidator(self.temp_dir)
        
        # Create test files
        self._create_test_files()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_files(self):
        """Create test files for validation"""
        # Create rules directory and test rule
        rules_dir = self.temp_dir / "etc/rules"
        rules_dir.mkdir(parents=True)
        
        rule_content = """<?xml version="1.0"?>
<group name="test">
  <rule id="100001" level="10">
    <description>Test rule</description>
    <mitre>T1059</mitre>
    <regex>test.*pattern</regex>
    <group>test,devsec</group>
  </rule>
</group>"""
        
        (rules_dir / "test_rules.xml").write_text(rule_content)
        
        # Create CDB list
        cdb_dir = self.temp_dir / "etc/lists/cdb"
        cdb_dir.mkdir(parents=True)
        
        (cdb_dir / "test_list.txt").write_text("key1:value1\nkey2:value2\n")
        
        # Create dashboard
        dashboards_dir = self.temp_dir / "dashboards"
        dashboards_dir.mkdir(parents=True)
        
        dashboard_content = {
            "id": "test-dashboard",
            "title": "Test Dashboard",
            "panels": [
                {"id": "panel1", "title": "Test Panel", "type": "table"}
            ]
        }
        
        (dashboards_dir / "test_dashboard.json").write_text(json.dumps(dashboard_content))
    
    def test_validate_all(self):
        """Test comprehensive validation"""
        report = self.validator.validate_all()
        
        self.assertIsInstance(report, type(report))
        self.assertGreater(report.total_checks, 0)
        self.assertGreaterEqual(report.passed, 0)
        self.assertGreaterEqual(report.failed, 0)
    
    def test_rule_validation(self):
        """Test rule validation"""
        report = self.validator.validate_all()
        
        # Check for rule validation results
        rule_results = [r for r in report.results if r.component == "rules"]
        self.assertGreater(len(rule_results), 0)
        
        # Should have at least one passed rule
        passed_rules = [r for r in rule_results if r.status == ValidationStatus.PASSED]
        self.assertGreater(len(passed_rules), 0)
    
    def test_cdb_validation(self):
        """Test CDB list validation"""
        report = self.validator.validate_all()
        
        # Check for CDB validation results
        cdb_results = [r for r in report.results if r.component == "cdb_lists"]
        self.assertGreater(len(cdb_results), 0)
    
    def test_dashboard_validation(self):
        """Test dashboard validation"""
        report = self.validator.validate_all()
        
        # Check for dashboard validation results
        dashboard_results = [r for r in report.results if r.component == "dashboards"]
        self.assertGreater(len(dashboard_results), 0)


class TestRuleAnalyzer(unittest.TestCase):
    """Test rule analysis system"""
    
    def setUp(self):
        self.analyzer = RuleAnalyzer()
        self.temp_dir = Path(tempfile.mkdtemp())
        self._create_test_rules()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_rules(self):
        """Create test rule files"""
        rules_dir = self.temp_dir / "rules"
        rules_dir.mkdir()
        
        # Good rule
        good_rule = """<?xml version="1.0"?>
<rule id="100001" level="10">
  <description>Good test rule</description>
  <mitre>T1059</mitre>
  <regex>specific.*pattern</regex>
  <group>test,devsec</group>
</rule>"""
        
        (rules_dir / "good_rules.xml").write_text(good_rule)
        
        # Bad rule (missing required fields)
        bad_rule = """<?xml version="1.0"?>
<rule id="100002">
  <description>Bad test rule</description>
  <regex>.*</regex>
</rule>"""
        
        (rules_dir / "bad_rules.xml").write_text(bad_rule)
    
    def test_analyze_rules_directory(self):
        """Test rule directory analysis"""
        analyses = self.analyzer.analyze_rules_directory(self.temp_dir / "rules")
        
        self.assertGreater(len(analyses), 0)
        
        # Should have both good and bad rules
        good_rules = [a for a in analyses.values() if a.quality == RuleQuality.EXCELLENT]
        bad_rules = [a for a in analyses.values() if a.quality in [RuleQuality.POOR, RuleQuality.CRITICAL]]
        
        self.assertGreater(len(good_rules), 0)
        self.assertGreater(len(bad_rules), 0)
    
    def test_false_positive_analysis(self):
        """Test false positive risk analysis"""
        # Test high-risk regex
        fp_analysis = self.analyzer._analyze_false_positive_risk(
            r"git clone.*http", 
            "Git clone detection"
        )
        
        self.assertEqual(fp_analysis["risk"], "high")
        self.assertIsNotNone(fp_analysis["recommendation"])
        
        # Test low-risk regex
        fp_analysis = self.analyzer._analyze_false_positive_risk(
            r"git clone.*github\.com", 
            "GitHub clone detection"
        )
        
        self.assertEqual(fp_analysis["risk"], "low")
    
    def test_quality_score_calculation(self):
        """Test quality score calculation"""
        # Perfect score
        score = self.analyzer._calculate_quality_score(0, 0)
        self.assertEqual(score, 100.0)
        
        # Some issues
        score = self.analyzer._calculate_quality_score(2, 3)
        self.assertLess(score, 100.0)
        self.assertGreaterEqual(score, 0.0)
    
    def test_improvement_suggestions(self):
        """Test improvement suggestions"""
        analyses = self.analyzer.analyze_rules_directory(self.temp_dir / "rules")
        suggestions = self.analyzer.suggest_improvements(analyses)
        
        self.assertIsInstance(suggestions, list)
        # Should suggest improvements for bad rules
        self.assertGreater(len(suggestions), 0)


class TestImprovedRules(unittest.TestCase):
    """Test improved rules library"""
    
    def test_get_all_rules(self):
        """Test getting all improved rules"""
        rules = ImprovedRuleLibrary.get_all_rules()
        
        self.assertGreater(len(rules), 0)
        
        # Check rule structure
        for rule in rules:
            self.assertIsNotNone(rule.rule_id)
            self.assertIsNotNone(rule.title)
            self.assertIsNotNone(rule.regex)
            self.assertIsNotNone(rule.category)
            self.assertIsNotNone(rule.false_positive_risk)
    
    def test_get_rules_by_category(self):
        """Test getting rules by category"""
        git_rules = ImprovedRuleLibrary.get_rules_by_category(RuleCategory.GIT)
        docker_rules = ImprovedRuleLibrary.get_rules_by_category(RuleCategory.DOCKER)
        
        self.assertGreater(len(git_rules), 0)
        self.assertGreater(len(docker_rules), 0)
        
        # Verify category filtering
        for rule in git_rules:
            self.assertEqual(rule.category, RuleCategory.GIT)
        
        for rule in docker_rules:
            self.assertEqual(rule.category, RuleCategory.DOCKER)
    
    def test_false_positive_reduction_analysis(self):
        """Test false positive reduction analysis"""
        analysis = ImprovedRuleLibrary.analyze_false_positive_reduction()
        
        self.assertIn("original", analysis)
        self.assertIn("improved", analysis)
        self.assertIn("reduction", analysis)
        
        # Should show improvement
        reduction = analysis["reduction"]
        for category, improvements in reduction.items():
            self.assertIsInstance(improvements, dict)
            self.assertIn("high", improvements)
            self.assertIn("medium", improvements)
            self.assertIn("low", improvements)
    
    def test_rule_quality_attributes(self):
        """Test rule quality attributes"""
        rules = ImprovedRuleLibrary.get_all_rules()
        
        for rule in rules:
            # Check required fields
            self.assertIsNotNone(rule.rule_id)
            self.assertIsInstance(rule.rule_id, int)
            self.assertGreater(rule.rule_id, 0)
            
            self.assertIsNotNone(rule.level)
            self.assertIsInstance(rule.level, int)
            self.assertGreaterEqual(rule.level, 0)
            self.assertLessEqual(rule.level, 15)
            
            self.assertIsNotNone(rule.title)
            self.assertIsInstance(rule.title, str)
            self.assertGreater(len(rule.title), 0)
            
            # Check quality attributes
            self.assertIsNotNone(rule.false_positive_risk)
            self.assertIn(rule.false_positive_risk, ["low", "medium", "high", "critical"])
            
            self.assertIsNotNone(rule.whitelist_patterns)
            self.assertIsInstance(rule.whitelist_patterns, list)


class TestIntegration(unittest.TestCase):
    """Integration tests for core components"""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_config_to_validation_flow(self):
        """Test configuration to validation flow"""
        # Create configuration
        config_manager = ConfigManager()
        profile = WazuhProfile(
            name="integration-test",
            type=ProfileType.DEVELOPMENT,
            description="Integration test profile",
            rules_enabled=["git"],
            integrations=[]
        )
        
        config_manager.add_profile(profile)
        
        # Generate configuration (mock)
        factory = ConfigurationFactory(self.temp_dir)
        
        with patch.object(factory, 'create_configuration') as mock_generate:
            mock_generate.return_value = {"rules_count": 5}
            result = factory.create_configuration(profile.name)
        
        # Validate configuration
        validator = WazuhValidator(self.temp_dir)
        
        # Should not crash even with empty directory
        report = validator.validate_all()
        self.assertIsInstance(report, type(report))
    
    def test_rule_analysis_integration(self):
        """Test rule analysis integration"""
        # Create test rules
        rules_dir = self.temp_dir / "rules"
        rules_dir.mkdir()
        
        rule_content = """<?xml version="1.0"?>
<rule id="100001" level="8">
  <description>Integration test rule</description>
  <regex>test.*pattern</regex>
  <group>test,integration</group>
</rule>"""
        
        (rules_dir / "integration_rules.xml").write_text(rule_content)
        
        # Analyze rules
        analyzer = RuleAnalyzer()
        analyses = analyzer.analyze_rules_directory(rules_dir)
        
        self.assertEqual(len(analyses), 1)
        
        # Get improvement suggestions
        suggestions = analyzer.suggest_improvements(analyses)
        self.assertIsInstance(suggestions, list)


if __name__ == "__main__":
    unittest.main()
