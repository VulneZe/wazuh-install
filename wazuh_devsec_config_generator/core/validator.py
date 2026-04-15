"""
Centralized validation system for Wazuh DevSec Generator
Clean, modular validation with comprehensive error handling
"""

import json
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

from .constants import (
    VALIDATION_PATTERNS, 
    QUALITY_THRESHOLDS, 
    ERROR_MESSAGES, 
    SUCCESS_MESSAGES,
    RuleCategory,
    RuleLevel,
    IntegrationStatus
)


class ValidationStatus(str, Enum):
    """Validation status levels"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"


@dataclass
class ValidationResult:
    """Result of a validation operation"""
    status: ValidationStatus
    component: str
    message: str
    details: Optional[Dict[str, Any]] = None
    file_path: Optional[Path] = None
    line_number: Optional[int] = None
    severity: str = "medium"


@dataclass
class ValidationReport:
    """Comprehensive validation report"""
    timestamp: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    skipped: int
    results: List[ValidationResult]
    score: float
    recommendations: List[str]


class WazuhValidator:
    """Centralized Wazuh configuration validator"""
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self.results: List[ValidationResult] = []
        
    def validate_all(self) -> ValidationReport:
        """Run comprehensive validation of all components"""
        self.results = []
        
        # Validate rules
        self._validate_rules()
        
        # Validate decoders
        self._validate_decoders()
        
        # Validate CDB lists
        self._validate_cdb_lists()
        
        # Validate active response
        self._validate_active_response()
        
        # Validate configuration
        self._validate_configuration()
        
        # Validate dashboards
        self._validate_dashboards()
        
        # Generate report
        return self._generate_report()
    
    def _validate_rules(self) -> None:
        """Validate rule XML files"""
        rules_dir = self.config_dir / "etc/rules"
        
        if not rules_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="rules",
                message="Rules directory not found",
                file_path=rules_dir
            ))
            return
        
        rule_files = list(rules_dir.glob("*.xml"))
        
        for rule_file in rule_files:
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                # Validate XML structure
                self._validate_xml_structure(rule_file, root, "rule")
                
                # Validate rule elements
                for rule_elem in root.findall(".//rule"):
                    self._validate_rule_element(rule_file, rule_elem)
                    
            except ET.ParseError as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="rules",
                    message=f"XML parsing error: {e}",
                    file_path=rule_file,
                    severity="high"
                ))
            except Exception as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="rules",
                    message=f"Unexpected error: {e}",
                    file_path=rule_file,
                    severity="medium"
                ))
    
    def _validate_xml_structure(self, file_path: Path, root: ET.Element, component_type: str) -> None:
        """Validate basic XML structure"""
        if component_type not in ["rule", "decoder", "command"]:
            return
        
        patterns = VALIDATION_PATTERNS["xml"]["required_elements"].get(component_type, [])
        
        for element_name in patterns:
            elements = root.findall(f".//{element_name}")
            if not elements:
                self.results.append(ValidationResult(
                    status=ValidationStatus.WARNING,
                    component=component_type,
                    message=f"Missing required element: {element_name}",
                    file_path=file_path,
                    severity="medium"
                ))
    
    def _validate_rule_element(self, file_path: Path, rule_elem: ET.Element) -> None:
        """Validate individual rule element"""
        rule_id = rule_elem.get("id")
        level = rule_elem.get("level")
        description = rule_elem.findtext("description")
        
        # Validate required fields
        if not rule_id:
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="rules",
                message="Missing rule ID",
                file_path=file_path,
                severity="high"
            ))
            return
        
        # Validate ID format
        if not rule_id.isdigit():
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="rules",
                message=f"Invalid rule ID format: {rule_id}",
                file_path=file_path,
                severity="high"
            ))
        
        # Validate level
        if not level:
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="rules",
                message="Missing rule level",
                file_path=file_path,
                severity="high"
            ))
        else:
            try:
                level_int = int(level)
                if level_int < 0 or level_int > 15:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.FAILED,
                        component="rules",
                        message=f"Invalid rule level: {level} (must be 0-15)",
                        file_path=file_path,
                        severity="high"
                    ))
            except ValueError:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="rules",
                    message=f"Invalid level format: {level}",
                    file_path=file_path,
                    severity="high"
                ))
        
        # Validate description
        if not description or not description.strip():
            self.results.append(ValidationResult(
                status=ValidationStatus.WARNING,
                component="rules",
                message="Missing or empty description",
                file_path=file_path,
                severity="medium"
            ))
        
        # Validate MITRE tag
        mitre_tag = rule_elem.findtext("mitre")
        if mitre_tag:
            if not re.match(r"T\d{4}(\.\d{3})?", mitre_tag):
                self.results.append(ValidationResult(
                    status=ValidationStatus.WARNING,
                    component="rules",
                    message=f"Invalid MITRE format: {mitre_tag}",
                    file_path=file_path,
                    severity="medium"
                ))
        
        # Validate regex
        regex = rule_elem.findtext("regex")
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="rules",
                    message=f"Invalid regex: {e}",
                    file_path=file_path,
                    severity="high"
                ))
    
    def _validate_decoders(self) -> None:
        """Validate decoder XML files"""
        decoders_dir = self.config_dir / "etc/decoders"
        
        if not decoders_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="decoders",
                message="Decoders directory not found",
                file_path=decoders_dir
            ))
            return
        
        decoder_files = list(decoders_dir.glob("*.xml"))
        
        for decoder_file in decoder_files:
            try:
                tree = ET.parse(decoder_file)
                root = tree.getroot()
                
                # Validate XML structure
                self._validate_xml_structure(decoder_file, root, "decoder")
                
                # Validate decoder elements
                for decoder_elem in root.findall(".//decoder"):
                    self._validate_decoder_element(decoder_file, decoder_elem)
                    
            except ET.ParseError as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="decoders",
                    message=f"XML parsing error: {e}",
                    file_path=decoder_file,
                    severity="high"
                ))
            except Exception as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="decoders",
                    message=f"Unexpected error: {e}",
                    file_path=decoder_file,
                    severity="medium"
                ))
    
    def _validate_decoder_element(self, file_path: Path, decoder_elem: ET.Element) -> None:
        """Validate individual decoder element"""
        name = decoder_elem.get("name")
        
        if not name:
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="decoders",
                message="Missing decoder name",
                file_path=file_path,
                severity="high"
            ))
        
        # Validate regex
        regex = decoder_elem.findtext("regex")
        if regex:
            try:
                re.compile(regex)
            except re.error as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="decoders",
                    message=f"Invalid regex: {e}",
                    file_path=file_path,
                    severity="high"
                ))
    
    def _validate_cdb_lists(self) -> None:
        """Validate CDB list files"""
        lists_dir = self.config_dir / "etc/lists/cdb"
        
        if not lists_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.WARNING,
                component="cdb_lists",
                message="CDB lists directory not found",
                file_path=lists_dir,
                severity="low"
            ))
            return
        
        list_files = list(lists_dir.glob("*.txt"))
        
        for list_file in list_files:
            try:
                content = list_file.read_text(encoding='utf-8')
                lines = [line.strip() for line in content.split('\n') if line.strip()]
                
                # Validate CDB format
                pattern = VALIDATION_PATTERNS["cdb"]["format_pattern"]
                invalid_lines = []
                
                for i, line in enumerate(lines, 1):
                    if not re.match(pattern, line):
                        invalid_lines.append(f"Line {i}: {line}")
                
                if invalid_lines:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.WARNING,
                        component="cdb_lists",
                        message=f"Invalid CDB format in {len(invalid_lines)} lines",
                        file_path=list_file,
                        details={"invalid_lines": invalid_lines[:5]},  # Show first 5
                        severity="medium"
                    ))
                else:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.PASSED,
                        component="cdb_lists",
                        message=f"Valid CDB format: {len(lines)} entries",
                        file_path=list_file
                    ))
                    
            except UnicodeDecodeError as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="cdb_lists",
                    message=f"Encoding error: {e}",
                    file_path=list_file,
                    severity="high"
                ))
            except Exception as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="cdb_lists",
                    message=f"Unexpected error: {e}",
                    file_path=list_file,
                    severity="medium"
                ))
    
    def _validate_active_response(self) -> None:
        """Validate active response components"""
        ar_dir = self.config_dir / "etc/active-response"
        
        if not ar_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.WARNING,
                component="active_response",
                message="Active response directory not found",
                file_path=ar_dir,
                severity="low"
            ))
            return
        
        # Validate scripts
        scripts_dir = ar_dir / "bin"
        if scripts_dir.exists():
            script_files = list(scripts_dir.glob("*.py"))
            
            for script_file in script_files:
                try:
                    content = script_file.read_text()
                    
                    # Basic Python validation
                    if script_file.suffix == ".py":
                        if len(content) < 100:
                            self.results.append(ValidationResult(
                                status=ValidationStatus.WARNING,
                                component="active_response",
                                message="Script appears incomplete",
                                file_path=script_file,
                                severity="low"
                            ))
                        else:
                            self.results.append(ValidationResult(
                                status=ValidationStatus.PASSED,
                                component="active_response",
                                message="Valid Python script",
                                file_path=script_file
                            ))
                
                except Exception as e:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.FAILED,
                        component="active_response",
                        message=f"Script validation error: {e}",
                        file_path=script_file,
                        severity="medium"
                    ))
        
        # Validate commands
        commands_dir = ar_dir / "commands"
        if commands_dir.exists():
            command_files = list(commands_dir.glob("*.xml"))
            
            for command_file in command_files:
                try:
                    tree = ET.parse(command_file)
                    root = tree.getroot()
                    
                    # Validate command elements
                    for command_elem in root.findall(".//command"):
                        self._validate_command_element(command_file, command_elem)
                        
                except ET.ParseError as e:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.FAILED,
                        component="active_response",
                        message=f"XML parsing error: {e}",
                        file_path=command_file,
                        severity="high"
                    ))
    
    def _validate_command_element(self, file_path: Path, command_elem: ET.Element) -> None:
        """Validate individual command element"""
        name = command_elem.findtext("name")
        executable = command_elem.findtext("executable")
        
        if not name:
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="active_response",
                message="Missing command name",
                file_path=file_path,
                severity="high"
            ))
        
        if not executable:
            self.results.append(ValidationResult(
                status=ValidationStatus.FAILED,
                component="active_response",
                message="Missing command executable",
                file_path=file_path,
                severity="high"
            ))
    
    def _validate_configuration(self) -> None:
        """Validate ossec.conf fragments"""
        conf_dir = self.config_dir / "etc/ossec.conf.d"
        
        if not conf_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.WARNING,
                component="ossec_conf",
                message="ossec.conf.d directory not found",
                file_path=conf_dir,
                severity="low"
            ))
            return
        
        conf_files = list(conf_dir.glob("*.xml"))
        
        for conf_file in conf_files:
            try:
                tree = ET.parse(conf_file)
                root = tree.getroot()
                
                # Validate configuration elements
                valid_elements = ["syscheck", "rootcheck", "localfile", "remote", 
                                "vulnerability-detection", "sca", "active-response"]
                
                if root.tag in valid_elements or any(child.tag in valid_elements for child in root):
                    self.results.append(ValidationResult(
                        status=ValidationStatus.PASSED,
                        component="ossec_conf",
                        message="Valid configuration fragment",
                        file_path=conf_file
                    ))
                else:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.WARNING,
                        component="ossec_conf",
                        message=f"Unknown configuration element: {root.tag}",
                        file_path=conf_file,
                        severity="medium"
                    ))
                    
            except ET.ParseError as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="ossec_conf",
                    message=f"XML parsing error: {e}",
                    file_path=conf_file,
                    severity="high"
                ))
    
    def _validate_dashboards(self) -> None:
        """Validate dashboard JSON files"""
        dashboards_dir = self.config_dir / "dashboards"
        
        if not dashboards_dir.exists():
            self.results.append(ValidationResult(
                status=ValidationStatus.SKIPPED,
                component="dashboards",
                message="Dashboards directory not found (optional)",
                file_path=dashboards_dir,
                severity="low"
            ))
            return
        
        dashboard_files = list(dashboards_dir.glob("*.json"))
        
        for dashboard_file in dashboard_files:
            try:
                with open(dashboard_file, 'r') as f:
                    dashboard = json.load(f)
                
                # Validate dashboard structure
                required_fields = VALIDATION_PATTERNS["json"]["required_fields"]
                missing_fields = [field for field in required_fields if field not in dashboard]
                
                if missing_fields:
                    self.results.append(ValidationResult(
                        status=ValidationStatus.WARNING,
                        component="dashboards",
                        message=f"Missing required fields: {missing_fields}",
                        file_path=dashboard_file,
                        severity="medium"
                    ))
                else:
                    # Count panels
                    panels = dashboard.get("panels", [])
                    panel_count = len(panels) if isinstance(panels, list) else 1
                    
                    self.results.append(ValidationResult(
                        status=ValidationStatus.PASSED,
                        component="dashboards",
                        message=f"Valid dashboard with {panel_count} panels",
                        file_path=dashboard_file,
                        details={"panel_count": panel_count}
                    ))
                    
            except json.JSONDecodeError as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="dashboards",
                    message=f"JSON parsing error: {e}",
                    file_path=dashboard_file,
                    severity="high"
                ))
            except Exception as e:
                self.results.append(ValidationResult(
                    status=ValidationStatus.FAILED,
                    component="dashboards",
                    message=f"Unexpected error: {e}",
                    file_path=dashboard_file,
                    severity="medium"
                ))
    
    def _generate_report(self) -> ValidationReport:
        """Generate comprehensive validation report"""
        from datetime import datetime
        
        total = len(self.results)
        passed = len([r for r in self.results if r.status == ValidationStatus.PASSED])
        failed = len([r for r in self.results if r.status == ValidationStatus.FAILED])
        warnings = len([r for r in self.results if r.status == ValidationStatus.WARNING])
        skipped = len([r for r in self.results if r.status == ValidationStatus.SKIPPED])
        
        # Calculate score
        if total > 0:
            score = (passed / total) * 100
        else:
            score = 0.0
        
        # Generate recommendations
        recommendations = self._generate_recommendations()
        
        return ValidationReport(
            timestamp=datetime.now().isoformat(),
            total_checks=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            skipped=skipped,
            results=self.results,
            score=score,
            recommendations=recommendations
        )
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        # Analyze common issues
        component_issues = {}
        for result in self.results:
            if result.status in [ValidationStatus.FAILED, ValidationStatus.WARNING]:
                component_issues[result.component] = component_issues.get(result.component, 0) + 1
        
        # Generate recommendations based on issues
        if component_issues.get("rules", 0) > 3:
            recommendations.append("Review and fix rule validation issues")
        
        if component_issues.get("decoders", 0) > 2:
            recommendations.append("Check decoder XML structure and syntax")
        
        if component_issues.get("cdb_lists", 0) > 1:
            recommendations.append("Fix CDB list format issues")
        
        if component_issues.get("active_response", 0) > 2:
            recommendations.append("Review active response scripts and commands")
        
        # Quality-based recommendations
        if len([r for r in self.results if r.severity == "high"]) > 5:
            recommendations.append("Address high-severity issues before deployment")
        
        return recommendations
