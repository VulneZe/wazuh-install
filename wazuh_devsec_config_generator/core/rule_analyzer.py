"""
Rule analysis and optimization system
Analyzes rules for false positives, logic errors, and best practices
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import xml.etree.ElementTree as ET

from rich.console import Console
from rich.table import Table
from rich.panel import Panel


class RuleQuality(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    CRITICAL = "critical"


class FalsePositiveRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class RuleIssue:
    """Issue found in a rule"""
    type: str
    severity: str
    description: str
    recommendation: str
    line: Optional[int] = None


@dataclass
class RuleAnalysis:
    """Analysis result for a rule"""
    rule_id: str
    title: str
    quality: RuleQuality
    false_positive_risk: FalsePositiveRisk
    issues: List[RuleIssue]
    score: float
    recommendations: List[str]


class RuleAnalyzer:
    """Analyze Wazuh rules for quality and false positives"""
    
    def __init__(self):
        self.console = Console()
        
        # Known false positive patterns
        self.false_positive_patterns = {
            "git": {
                "high_risk": [
                    r"git clone.*github\.com",  # GitHub is often legitimate
                    r"git pull",                # Normal git operation
                    r"git fetch",               # Normal git operation
                    r"git status",              # Normal git operation
                ],
                "medium_risk": [
                    r"git add.*\.(md|txt|json|yaml|yml)",  # Adding non-sensitive files
                    r"git commit.*\[(fix|feat|docs|test)\]",  # Standard commit messages
                ]
            },
            "docker": {
                "high_risk": [
                    r"docker run.*ubuntu",      # Ubuntu images are common
                    r"docker run.*alpine",     # Alpine images are common
                    r"docker ps",              # Normal docker operation
                    r"docker logs",            # Normal docker operation
                ],
                "medium_risk": [
                    r"docker run.*-p 8080",    # Port 8080 is common for dev
                    r"docker run.*-p 3000",    # Port 3000 is common for dev
                ]
            },
            "ide": {
                "high_risk": [
                    r"code.*\.js",            # JavaScript files are normal
                    r"code.*\.py",            # Python files are normal
                    r"code.*\.java",          # Java files are normal
                    r"idea.*\.java",          # Java files in IntelliJ
                ],
                "medium_risk": [
                    r"code.*\.env\.example",  # Environment example files
                    r"code.*config\.js",      # Config files are normal
                ]
            }
        }
        
        # Best practices patterns
        self.best_practices = {
            "required_fields": ["id", "level", "description"],
            "recommended_fields": ["mitre", "group"],
            "level_ranges": {
                "info": (0, 3),
                "low": (4, 6),
                "medium": (7, 9),
                "high": (10, 12),
                "critical": (13, 15)
            }
        }
    
    def analyze_rules_directory(self, rules_dir: Path) -> Dict[str, RuleAnalysis]:
        """Analyze all rules in a directory"""
        analyses = {}
        
        if not rules_dir.exists():
            self.console.print(f"[red]Rules directory not found: {rules_dir}[/]")
            return analyses
        
        for rule_file in rules_dir.glob("*.xml"):
            try:
                tree = ET.parse(rule_file)
                root = tree.getroot()
                
                # Find all rule elements
                for rule_elem in root.findall(".//rule"):
                    rule_id = rule_elem.get("id")
                    if rule_id:
                        analysis = self._analyze_rule(rule_elem, rule_file)
                        analyses[rule_id] = analysis
                        
            except ET.ParseError as e:
                self.console.print(f"[red]Error parsing {rule_file}: {e}[/]")
        
        return analyses
    
    def _analyze_rule(self, rule_elem: ET.Element, file_path: Path) -> RuleAnalysis:
        """Analyze a single rule"""
        rule_id = rule_elem.get("id", "unknown")
        title = rule_elem.findtext("description", "No description").strip()
        
        issues = []
        recommendations = []
        
        # Check required fields
        for field in self.best_practices["required_fields"]:
            if field == "id":
                if not rule_elem.get("id"):
                    issues.append(RuleIssue(
                        "missing_field", "critical", 
                        f"Missing required field: {field}",
                        f"Add {field} attribute to rule element"
                    ))
            elif field == "level":
                if not rule_elem.get("level"):
                    issues.append(RuleIssue(
                        "missing_field", "critical",
                        f"Missing required field: {field}",
                        f"Add {field} attribute to rule element"
                    ))
            elif field == "description":
                if not rule_elem.findtext("description"):
                    issues.append(RuleIssue(
                        "missing_field", "critical",
                        f"Missing required field: {field}",
                        f"Add <description> element to rule"
                    ))
        
        # Check level appropriateness
        level_str = rule_elem.get("level", "0")
        try:
            level = int(level_str)
            if level < 0 or level > 15:
                issues.append(RuleIssue(
                    "invalid_level", "critical",
                    f"Invalid level: {level} (must be 0-15)",
                    "Use level between 0 and 15"
                ))
            elif level > 12:
                # High level rules should have strong justification
                if not rule_elem.findtext("regex"):
                    issues.append(RuleIssue(
                        "high_level_no_regex", "medium",
                        f"High level ({level}) without regex may cause false positives",
                        "Add specific regex pattern or lower level"
                    ))
        except ValueError:
            issues.append(RuleIssue(
                "invalid_level", "critical",
                f"Invalid level format: {level_str}",
                "Use numeric level (0-15)"
            ))
        
        # Check regex for false positives
        regex = rule_elem.findtext("regex")
        if regex:
            fp_analysis = self._analyze_false_positive_risk(regex, title)
            if fp_analysis["risk"] != "low":
                issues.append(RuleIssue(
                    "false_positive_risk", fp_analysis["risk"],
                    f"High false positive risk in regex: {regex}",
                    fp_analysis["recommendation"]
                ))
        
        # Check MITRE tagging
        mitre_tag = rule_elem.findtext("mitre")
        if not mitre_tag:
            recommendations.append("Add MITRE ATT&CK technique for better threat intelligence")
        else:
            # Validate MITRE format
            if not re.match(r"T\d{4}(\.\d{3})?", mitre_tag):
                issues.append(RuleIssue(
                    "invalid_mitre", "medium",
                    f"Invalid MITRE format: {mitre_tag}",
                    "Use format T#### or T####.### (e.g., T1059 or T1059.001)"
                ))
        
        # Check group tagging
        group = rule_elem.get("group", "")
        if not group:
            recommendations.append("Add group attribute for better rule organization")
        
        # Calculate quality score
        score = self._calculate_quality_score(len(issues), len(recommendations))
        quality = self._determine_quality(score)
        fp_risk = self._determine_false_positive_risk(issues)
        
        return RuleAnalysis(
            rule_id=rule_id,
            title=title,
            quality=quality,
            false_positive_risk=fp_risk,
            issues=issues,
            score=score,
            recommendations=recommendations
        )
    
    def _analyze_false_positive_risk(self, regex: str, title: str) -> Dict[str, Any]:
        """Analyze regex for false positive risk"""
        regex_lower = regex.lower()
        title_lower = title.lower()
        
        # Check against known false positive patterns
        for category, patterns in self.false_positive_patterns.items():
            if category in title_lower:
                for pattern in patterns["high_risk"]:
                    if re.search(pattern, regex_lower):
                        return {
                            "risk": "high",
                            "pattern": pattern,
                            "recommendation": f"Consider making regex more specific to avoid legitimate {category} operations"
                        }
                
                for pattern in patterns["medium_risk"]:
                    if re.search(pattern, regex_lower):
                        return {
                            "risk": "medium", 
                            "pattern": pattern,
                            "recommendation": f"Add additional context to reduce false positives in {category}"
                        }
        
        # Generic false positive checks
        generic_risks = [
            (r".*\..*\..*", "high", "Very broad pattern - make more specific"),
            (r".*\*.*", "medium", "Wildcard pattern may be too broad"),
            (r".*\?.*", "low", "Optional character pattern"),
        ]
        
        for pattern, risk, rec in generic_risks:
            if re.search(pattern, regex):
                return {"risk": risk, "pattern": pattern, "recommendation": rec}
        
        return {"risk": "low", "pattern": None, "recommendation": None}
    
    def _calculate_quality_score(self, issue_count: int, recommendation_count: int) -> float:
        """Calculate quality score (0-100)"""
        # Start with 100, subtract points for issues and recommendations
        score = 100.0
        
        # Critical issues: -20 points each
        # High issues: -15 points each  
        # Medium issues: -10 points each
        # Low issues: -5 points each
        # Recommendations: -2 points each
        
        # This is simplified - in real implementation we'd count by severity
        score -= (issue_count * 10) + (recommendation_count * 2)
        
        return max(0.0, min(100.0, score))
    
    def _determine_quality(self, score: float) -> RuleQuality:
        """Determine quality level from score"""
        if score >= 90:
            return RuleQuality.EXCELLENT
        elif score >= 80:
            return RuleQuality.GOOD
        elif score >= 70:
            return RuleQuality.FAIR
        elif score >= 60:
            return RuleQuality.POOR
        else:
            return RuleQuality.CRITICAL
    
    def _determine_false_positive_risk(self, issues: List[RuleIssue]) -> FalsePositiveRisk:
        """Determine overall false positive risk"""
        fp_issues = [issue for issue in issues if issue.type == "false_positive_risk"]
        
        if not fp_issues:
            return FalsePositiveRisk.LOW
        
        # Find highest risk
        risk_levels = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        max_risk = max(risk_levels.get(issue.severity, 0) for issue in fp_issues)
        
        if max_risk >= 4:
            return FalsePositiveRisk.CRITICAL
        elif max_risk >= 3:
            return FalsePositiveRisk.HIGH
        elif max_risk >= 2:
            return FalsePositiveRisk.MEDIUM
        else:
            return FalsePositiveRisk.LOW
    
    def display_analysis_report(self, analyses: Dict[str, RuleAnalysis]) -> None:
        """Display comprehensive analysis report"""
        if not analyses:
            self.console.print("[yellow]No rules to analyze[/]")
            return
        
        # Summary statistics
        total_rules = len(analyses)
        quality_counts = {}
        fp_risk_counts = {}
        
        for analysis in analyses.values():
            quality_counts[analysis.quality] = quality_counts.get(analysis.quality, 0) + 1
            fp_risk_counts[analysis.false_positive_risk] = fp_risk_counts.get(analysis.false_positive_risk, 0) + 1
        
        # Display summary
        self.console.print(Panel(
            f"""
📊 Analyse des Règles - Résumé
• Total des règles: {total_rules}
• Qualité: {quality_counts.get('excellent', 0)} excellentes, {quality_counts.get('good', 0)} bonnes, {quality_counts.get('fair', 0)} moyennes
• Risque faux positifs: {fp_risk_counts.get('low', 0)} faible, {fp_risk_counts.get('medium', 0)} moyen, {fp_risk_counts.get('high', 0)} élevé
• Score moyen: {sum(a.score for a in analyses.values()) / total_rules:.1f}/100
            """.strip(),
            title="Analyse des Règles Wazuh",
            border_style="blue"
        ))
        
        # Quality breakdown table
        quality_table = Table(title="📈 Répartition par Qualité")
        quality_table.add_column("Qualité", style="cyan")
        quality_table.add_column("Nombre", style="white")
        quality_table.add_column("Pourcentage", style="green")
        
        for quality in [RuleQuality.EXCELLENT, RuleQuality.GOOD, RuleQuality.FAIR, RuleQuality.POOR, RuleQuality.CRITICAL]:
            count = quality_counts.get(quality, 0)
            percentage = (count / total_rules * 100) if total_rules > 0 else 0
            quality_table.add_row(quality.value, str(count), f"{percentage:.1f}%")
        
        self.console.print(quality_table)
        
        # Rules with issues
        problematic_rules = [analysis for analysis in analyses.values() 
                           if analysis.issues or analysis.false_positive_risk != FalsePositiveRisk.LOW]
        
        if problematic_rules:
            self.console.print(f"\n[bold yellow]⚠️  {len(problematic_rules)} règles nécessitent une attention:[/]")
            
            issues_table = Table(title="🚨 Règles avec Problèmes")
            issues_table.add_column("ID", style="cyan")
            issues_table.add_column("Titre", style="white", width=40)
            issues_table.add_column("Qualité", style="red")
            issues_table.add_column("Risque FP", style="yellow")
            issues_table.add_column("Problèmes", style="red")
            
            for analysis in problematic_rules[:10]:  # Show top 10
                issues_table.add_row(
                    analysis.rule_id,
                    analysis.title[:37] + "..." if len(analysis.title) > 40 else analysis.title,
                    analysis.quality.value,
                    analysis.false_positive_risk.value,
                    str(len(analysis.issues))
                )
            
            self.console.print(issues_table)
            
            # Show detailed issues for worst rules
            worst_rules = sorted(problematic_rules, key=lambda x: x.score)[:3]
            
            for analysis in worst_rules:
                self.console.print(Panel(
                    f"""
[red]❌ {analysis.rule_id} - {analysis.title}[/]
Qualité: {analysis.quality.value} | Score: {analysis.score:.1f}/100
Risque FP: {analysis.false_positive_risk.value}

Problèmes:
""" + "\n".join(f"• {issue.description}" for issue in analysis.issues[:3]) + """

Recommandations:
""" + "\n".join(f"• {rec}" for rec in analysis.recommendations[:3]),
                    title="Détails des Problèmes",
                    border_style="red"
                ))
    
    def suggest_improvements(self, analyses: Dict[str, RuleAnalysis]) -> List[str]:
        """Suggest improvements based on analysis"""
        suggestions = []
        
        # Find common issues
        issue_types = {}
        for analysis in analyses.values():
            for issue in analysis.issues:
                issue_types[issue.type] = issue_types.get(issue.type, 0) + 1
        
        # Suggest improvements based on common issues
        if issue_types.get("missing_field", 0) > 0:
            suggestions.append("Ajouter les champs requis (id, level, description) à toutes les règles")
        
        if issue_types.get("false_positive_risk", 0) > len(analyses) * 0.3:
            suggestions.append("Réviser les regex pour réduire les faux positifs")
        
        if issue_types.get("invalid_mitre", 0) > 0:
            suggestions.append("Corriger le format des tags MITRE ATT&CK")
        
        # Quality-based suggestions
        poor_rules = [a for a in analyses.values() if a.quality in [RuleQuality.POOR, RuleQuality.CRITICAL]]
        if len(poor_rules) > len(analyses) * 0.2:
            suggestions.append("Réviser et améliorer les règles de faible qualité")
        
        return suggestions
