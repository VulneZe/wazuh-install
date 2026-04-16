"""
Wazuh Security Modules Configurator
Configuration des modules de sécurité avancés de Wazuh
Security Modules Configurator - Security modules configuration strategy
"""

import os
import re
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..utils.logger import WazuhLogger
from ..utils.cache import cached
from ..utils.exceptions import ConfigurationError, FileOperationError
from ..config.paths import WazuhPaths


class SecurityModulesConfigurator(BaseConfigurator):
    """Configuration des modules de sécurité Wazuh (Vulnerability Detector, CIS, FIM, MITRE)"""
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        super().__init__(wazuh_path)
        self.paths = WazuhPaths()
        self.ossec_conf_path = self.paths.ossec_conf
        self._logger = WazuhLogger(__name__, use_json=False)
        self.file_handler = FileHandler()
        
        # Chemins des fichiers de configuration des modules
        self.vuln_detector_enabled = False
        self.cis_enabled = False
        self.fim_enabled = False
        self.mitre_enabled = False
    
    @cached(ttl=300)
    def check(self) -> ConfigResult:
        """Vérifier la configuration des modules de sécurité"""
        self._logger.info("Vérification des modules de sécurité Wazuh...")
        self._logger.info("=" * 60)
        
        results = []
        
        # Vérifier Vulnerability Detector
        vuln_result = self._check_vulnerability_detector()
        results.append(vuln_result)
        
        # Vérifier CIS Benchmarks
        cis_result = self._check_cis_benchmarks()
        results.append(cis_result)
        
        # Vérifier FIM
        fim_result = self._check_fim()
        results.append(fim_result)
        
        # Vérifier MITRE ATT&CK
        mitre_result = self._check_mitre_attack()
        results.append(mitre_result)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Modules de sécurité: {success_count}/{total_count} vérifications OK",
            details={
                "vulnerability_detector": vuln_result.success,
                "cis_benchmarks": cis_result.success,
                "fim": fim_result.success,
                "mitre_attack": mitre_result.success
            }
        )
    
    def apply(self) -> ConfigResult:
        """Appliquer la configuration des modules de sécurité"""
        self._logger.info("Application de la configuration des modules de sécurité...")
        self._logger.info("=" * 60)
        
        results = []
        
        # Appliquer Vulnerability Detector
        vuln_result = self._apply_vulnerability_detector()
        results.append(vuln_result)
        
        # Appliquer CIS Benchmarks
        cis_result = self._apply_cis_benchmarks()
        results.append(cis_result)
        
        # Appliquer FIM
        fim_result = self._apply_fim()
        results.append(fim_result)
        
        # Appliquer MITRE ATT&CK
        mitre_result = self._apply_mitre_attack()
        results.append(mitre_result)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Modules de sécurité: {success_count}/{total_count} configurations appliquées",
            details={
                "vulnerability_detector": vuln_result.success,
                "cis_benchmarks": cis_result.success,
                "fim": fim_result.success,
                "mitre_attack": mitre_result.success
            }
        )
    
    def validate(self) -> ConfigResult:
        """Valider la configuration des modules de sécurité"""
        self._logger.info("Validation de la configuration des modules de sécurité...")
        self._logger.info("=" * 60)
        
        results = []
        
        # Valider Vulnerability Detector
        vuln_result = self._validate_vulnerability_detector()
        results.append(vuln_result)
        
        # Valider CIS Benchmarks
        cis_result = self._validate_cis_benchmarks()
        results.append(cis_result)
        
        # Valider FIM
        fim_result = self._validate_fim()
        results.append(fim_result)
        
        # Valider MITRE ATT&CK
        mitre_result = self._validate_mitre_attack()
        results.append(mitre_result)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Modules de sécurité: {success_count}/{total_count} validations OK",
            details={
                "vulnerability_detector": vuln_result.success,
                "cis_benchmarks": cis_result.success,
                "fim": fim_result.success,
                "mitre_attack": mitre_result.success
            }
        )
    
    def rollback(self) -> ConfigResult:
        """Annuler les changements de configuration des modules de sécurité"""
        self._logger.info("Annulation de la configuration des modules de sécurité...")
        self._logger.info("=" * 60)
        
        results = []
        
        # Restaurer les sauvegardes
        for file_path, backup_path in self.backup_files.items():
            if self.file_handler.restore_file(backup_path, file_path):
                self._logger.info(f"Restauration réussie: {file_path}")
                results.append(True)
            else:
                self._logger.error(f"Erreur restauration: {file_path}")
                results.append(False)
        
        self._logger.info("=" * 60)
        
        return ConfigResult(
            success=all(results),
            message=f"Restauration: {sum(results)}/{len(results)} fichiers restaurés"
        )
    
    # ==================== VULNERABILITY DETECTOR ====================
    
    @cached(ttl=300)
    def _check_vulnerability_detector(self) -> ConfigResult:
        """Vérifier la configuration du Vulnerability Detector"""
        self._logger.info("Vérification Vulnerability Detector...")
        
        if not os.path.exists(self.ossec_conf_path):
            self._logger.error(f"Fichier ossec.conf non trouvé: {self.ossec_conf_path}")
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si le module est activé
            vuln_enabled = '<vulnerability-detector>' in content
            cve_enabled = '<vulnerability-detector><provider name="nvd">' in content
            reports_enabled = '<vulnerability-detector><reports>' in content
            
            if vuln_enabled:
                self._logger.info("Vulnerability Detector activé")
                self.vuln_detector_enabled = True
            else:
                self._logger.warning("Vulnerability Detector non activé")
            
            if cve_enabled:
                self._logger.info("Intégration CVE/NVD configurée")
            else:
                self._logger.warning("Intégration CVE/NVD non configurée")
            
            if reports_enabled:
                self._logger.info("Rapports de vulnérabilités configurés")
            else:
                self._logger.warning("Rapports de vulnérabilités non configurés")
            
            success = vuln_enabled and cve_enabled and reports_enabled
            
            return ConfigResult(
                success=success,
                message=f"Vulnerability Detector: {'OK' if success else 'Configuration incomplète'}",
                details={
                    "enabled": vuln_enabled,
                    "cve_integration": cve_enabled,
                    "reports": reports_enabled
                }
            )
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier vérification Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue vérification Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _apply_vulnerability_detector(self) -> ConfigResult:
        """Appliquer la configuration du Vulnerability Detector"""
        self._logger.info("Configuration Vulnerability Detector...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            # Sauvegarder le fichier
            self.backup_config(self.ossec_conf_path)
            
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si la configuration existe déjà
            if '<vulnerability-detector>' in content:
                self._logger.warning("Vulnerability Detector déjà configuré, mise à jour...")
                return ConfigResult(success=True, message="Déjà configuré")
            
            # Configuration complète du Vulnerability Detector
            vuln_config = """
  <!-- Vulnerability Detector -->
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>86400</interval>
    <ignore_time>64800</ignore_time>
    <run_on_start>yes</run_on_start>
    
    <!-- Integration CVE/NVD -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_interval>3600</update_interval>
      <download_url>https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz</download_url>
      <download_url>https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz</download_url>
      <download_url>https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz</download_url>
    </provider>
    
    <!-- Rapports de vulnérabilités -->
    <reports>
      <enabled>yes</enabled>
      <interval>3600</interval>
    </reports>
  </vulnerability-detector>
"""
            
            # Insérer la configuration avant la fin du fichier
            if '</ossec_config>' in content:
                content = content.replace('</ossec_config>', vuln_config + '</ossec_config>')
            else:
                content += vuln_config
            
            self.file_handler.write_file(self.ossec_conf_path, content)
            self._logger.info("Vulnerability Detector configuré")
            
            return ConfigResult(success=True, message="Vulnerability Detector configuré avec succès")
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier configuration Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue configuration Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _validate_vulnerability_detector(self) -> ConfigResult:
        """Valider la configuration du Vulnerability Detector"""
        self._logger.info("Validation Vulnerability Detector...")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifications de validation
            checks = {
                "enabled": '<enabled>yes</enabled>' in content and '<vulnerability-detector>' in content,
                "cve_integration": '<provider name="nvd">' in content and '<enabled>yes</enabled>' in content,
                "reports": '<reports>' in content and '<enabled>yes</enabled>' in content,
                "interval": '<interval>86400</interval>' in content
            }
            
            success = all(checks.values())
            
            if success:
                self._logger.info("Vulnerability Detector validé")
            else:
                self._logger.error("Vulnerability Detector: validation échouée")
                for check, passed in checks.items():
                    if not passed:
                        self._logger.error(f"   - {check}: échec")
            
            return ConfigResult(success=success, message=f"Validation: {'OK' if success else 'Échouée'}", details=checks)
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier validation Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue validation Vulnerability Detector: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    # ==================== CIS BENCHMARKS ====================
    
    @cached(ttl=300)
    def _check_cis_benchmarks(self) -> ConfigResult:
        """Vérifier la configuration CIS Benchmarks"""
        self._logger.info("Vérification CIS Benchmarks...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si CIS est activé
            cis_enabled = '<rule id="100100"' in content or '<rule id="100200"' in content
            cis_rules = len(re.findall(r'<rule id="10\d+', content))
            
            if cis_enabled:
                self._logger.info(f"CIS Benchmarks activé ({cis_rules} règles)")
                self.cis_enabled = True
            else:
                self._logger.warning("CIS Benchmarks non activé")
            
            return ConfigResult(
                success=cis_enabled,
                message=f"CIS Benchmarks: {'Activé' if cis_enabled else 'Non activé'}",
                details={"enabled": cis_enabled, "rules_count": cis_rules}
            )
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier vérification CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue vérification CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _apply_cis_benchmarks(self) -> ConfigResult:
        """Appliquer la configuration CIS Benchmarks"""
        self._logger.info("Configuration CIS Benchmarks...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            # Sauvegarder le fichier
            self.backup_config(self.ossec_conf_path)
            
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si CIS existe déjà
            if '<rule id="100100"' in content:
                self._logger.warning("CIS Benchmarks déjà configuré, mise à jour...")
                return ConfigResult(success=True, message="Déjà configuré")
            
            # Configuration CIS Benchmarks (extrait des règles principales)
            cis_config = """
  <!-- CIS Benchmarks -->
  <ruleset>
    <!-- CIS Benchmark Level 1 -->
    <rule id="100100" level="critical">
      <description>Ensure auditing is enabled</description>
      <group>auditd</group>
    </rule>
    
    <rule id="100200" level="high">
      <description>Ensure system logs are rotated</description>
      <group>logrotate</group>
    </rule>
    
    <rule id="100300" level="medium">
      <description>Ensure file permissions are configured</description>
      <group>permissions</group>
    </rule>
    
    <rule id="100400" level="high">
      <description>Ensure SSH configuration is secure</description>
      <group>ssh</group>
    </rule>
    
    <rule id="100500" level="medium">
      <description>Ensure firewall is enabled</description>
      <group>firewall</group>
    </rule>
  </ruleset>
"""
            
            # Insérer la configuration
            if '</ossec_config>' in content:
                content = content.replace('</ossec_config>', cis_config + '</ossec_config>')
            else:
                content += cis_config
            
            self.file_handler.write_file(self.ossec_conf_path, content)
            self._logger.info("CIS Benchmarks configuré")
            
            return ConfigResult(success=True, message="CIS Benchmarks configuré avec succès")
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier configuration CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue configuration CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _validate_cis_benchmarks(self) -> ConfigResult:
        """Valider la configuration CIS Benchmarks"""
        self._logger.info("Validation CIS Benchmarks...")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            checks = {
                "rules_present": '<rule id="100100"' in content,
                "critical_rules": '<rule id="100100"' in content,
                "high_rules": '<rule id="100200"' in content,
                "medium_rules": '<rule id="100300"' in content
            }
            
            success = all(checks.values())
            
            if success:
                self._logger.info("CIS Benchmarks validé")
            else:
                self._logger.error("CIS Benchmarks: validation échouée")
            
            return ConfigResult(success=success, message=f"Validation: {'OK' if success else 'Échouée'}", details=checks)
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier validation CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue validation CIS Benchmarks: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    # ==================== FILE INTEGRITY MONITORING (FIM) ====================
    
    @cached(ttl=300)
    def _check_fim(self) -> ConfigResult:
        """Vérifier la configuration FIM"""
        self._logger.info("Vérification File Integrity Monitoring (FIM)...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si FIM est activé
            fim_enabled = '<syscheck>' in content
            critical_dirs = len(re.findall(r'<directories check_all="yes">/etc</directories>', content))
            alert_rules = len(re.findall(r'<alert_on_start>yes</alert_on_start>', content))
            
            if fim_enabled:
                self._logger.info(f"FIM activé ({critical_dirs} répertoires surveillés)")
                self.fim_enabled = True
            else:
                self._logger.warning("FIM non activé")
            
            return ConfigResult(
                success=fim_enabled,
                message=f"FIM: {'Activé' if fim_enabled else 'Non activé'}",
                details={"enabled": fim_enabled, "directories": critical_dirs, "alerts": alert_rules}
            )
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier vérification FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue vérification FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _apply_fim(self) -> ConfigResult:
        """Appliquer la configuration FIM"""
        self._logger.info("Configuration File Integrity Monitoring (FIM)...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            # Sauvegarder le fichier
            self.backup_config(self.ossec_conf_path)
            
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si FIM existe déjà
            if '<syscheck>' in content:
                self._logger.warning("FIM déjà configuré, mise à jour...")
                return ConfigResult(success=True, message="Déjà configuré")
            
            # Configuration FIM complète
            fim_config = """
  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>3600</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_on_new_files>yes</alert_on_new_files>
    <alert_on_start>yes</alert_on_start>
    
    <!-- Répertoires critiques à surveiller -->
    <directories check_all="yes">/etc</directories>
    <directories check_all="yes">/usr/bin</directories>
    <directories check_all="yes">/usr/sbin</directories>
    <directories check_all="yes">/bin</directories>
    <directories check_all="yes">/sbin</directories>
    <directories check_all="yes">/var/www</directories>
    <directories check_all="yes">/var/log</directories>
    
    <!-- Exclusions des faux positifs -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/mnttab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    
    <!-- Règles d'alerte personnalisées -->
    <alert_on_new_files>yes</alert_on_new_files>
    <alert_on_read_only>yes</alert_on_read_only>
  </syscheck>
"""
            
            # Insérer la configuration
            if '</ossec_config>' in content:
                content = content.replace('</ossec_config>', fim_config + '</ossec_config>')
            else:
                content += fim_config
            
            self.file_handler.write_file(self.ossec_conf_path, content)
            self._logger.info("FIM configuré")
            
            return ConfigResult(success=True, message="FIM configuré avec succès")
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier configuration FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue configuration FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _validate_fim(self) -> ConfigResult:
        """Valider la configuration FIM"""
        self._logger.info("Validation File Integrity Monitoring (FIM)...")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            checks = {
                "enabled": '<syscheck>' in content and '<disabled>no</disabled>' in content,
                "critical_dirs": '<directories' in content and '/etc' in content,
                "frequency": '<frequency>' in content,
                "alerts": '<alert_on_new_files>yes</alert_on_new_files>' in content,
                "exclusions": '<ignore>' in content
            }
            
            success = all(checks.values())
            
            if success:
                self._logger.info("FIM validé")
            else:
                self._logger.error("FIM: validation échouée")
                for check, passed in checks.items():
                    if not passed:
                        self._logger.error(f"   - {check}: échec")
            
            return ConfigResult(success=success, message=f"Validation: {'OK' if success else 'Échouée'}", details=checks)
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier validation FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue validation FIM: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    # ==================== MITRE ATT&CK ====================
    
    @cached(ttl=300)
    def _check_mitre_attack(self) -> ConfigResult:
        """Vérifier la configuration MITRE ATT&CK"""
        self._logger.info("Vérification MITRE ATT&CK...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si MITRE est activé
            mitre_enabled = '<rule id="100300"' in content or '<group>mitre</group>' in content
            mitre_rules = len(re.findall(r'<group>mitre</group>', content))
            
            if mitre_enabled:
                self._logger.info(f"MITRE ATT&CK activé ({mitre_rules} règles)")
                self.mitre_enabled = True
            else:
                self._logger.warning("MITRE ATT&CK non activé")
            
            return ConfigResult(
                success=mitre_enabled,
                message=f"MITRE ATT&CK: {'Activé' if mitre_enabled else 'Non activé'}",
                details={"enabled": mitre_enabled, "rules_count": mitre_rules}
            )
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier vérification MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue vérification MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _apply_mitre_attack(self) -> ConfigResult:
        """Appliquer la configuration MITRE ATT&CK"""
        self._logger.info("Configuration MITRE ATT&CK...")
        
        if not os.path.exists(self.ossec_conf_path):
            return ConfigResult(success=False, message="Fichier ossec.conf non trouvé")
        
        try:
            # Sauvegarder le fichier
            self.backup_config(self.ossec_conf_path)
            
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            # Vérifier si MITRE existe déjà
            if '<group>mitre</group>' in content:
                self._logger.warning("MITRE ATT&CK déjà configuré, mise à jour...")
                return ConfigResult(success=True, message="Déjà configuré")
            
            # Configuration MITRE ATT&CK
            mitre_config = """
  <!-- MITRE ATT&CK -->
  <ruleset>
    <!-- MITRE ATT&CK Tactic: Initial Access -->
    <rule id="100300" level="high">
      <description>MITRE ATT&CK - Initial Access</description>
      <group>mitre</group>
      <field name="mitre.id">T1190</field>
      <field name="mitre.name">Exploit Public-Facing Application</field>
    </rule>
    
    <rule id="100301" level="critical">
      <description>MITRE ATT&CK - Initial Access</description>
      <group>mitre</group>
      <field name="mitre.id">T1078</field>
      <field name="mitre.name">Valid Accounts</field>
    </rule>
    
    <!-- MITRE ATT&CK Tactic: Privilege Escalation -->
    <rule id="100302" level="high">
      <description>MITRE ATT&CK - Privilege Escalation</description>
      <group>mitre</group>
      <field name="mitre.id">T1068</field>
      <field name="mitre.name">Exploitation for Privilege Escalation</field>
    </rule>
    
    <rule id="100303" level="high">
      <description>MITRE ATT&CK - Privilege Escalation</description>
      <group>mitre</group>
      <field name="mitre.id">T1548</field>
      <field name="mitre.name">Abuse Elevation Control Mechanism</field>
    </rule>
    
    <!-- MITRE ATT&CK Tactic: Lateral Movement -->
    <rule id="100304" level="high">
      <description>MITRE ATT&CK - Lateral Movement</description>
      <group>mitre</group>
      <field name="mitre.id">T1021</field>
      <field name="mitre.name">Remote Services</field>
    </rule>
    
    <!-- MITRE ATT&CK Tactic: Persistence -->
    <rule id="100305" level="medium">
      <description>MITRE ATT&CK - Persistence</description>
      <group>mitre</group>
      <field name="mitre.id">T1543</field>
      <field name="mitre.name">Create or Modify System Process</field>
    </rule>
  </ruleset>
"""
            
            # Insérer la configuration
            if '</ossec_config>' in content:
                content = content.replace('</ossec_config>', mitre_config + '</ossec_config>')
            else:
                content += mitre_config
            
            self.file_handler.write_file(self.ossec_conf_path, content)
            self._logger.info("MITRE ATT&CK configuré")
            
            return ConfigResult(success=True, message="MITRE ATT&CK configuré avec succès")
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier configuration MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue configuration MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
    
    def _validate_mitre_attack(self) -> ConfigResult:
        """Valider la configuration MITRE ATT&CK"""
        self._logger.info("Validation MITRE ATT&CK...")
        
        try:
            content = self.file_handler.read_file(self.ossec_conf_path)
            
            checks = {
                "rules_present": '<group>mitre</group>' in content,
                "initial_access": '<field name="mitre.id">T1190</field>' in content,
                "privilege_escalation": '<field name="mitre.id">T1068</field>' in content,
                "lateral_movement": '<field name="mitre.id">T1021</field>' in content,
                "persistence": '<field name="mitre.id">T1543</field>' in content
            }
            
            success = all(checks.values())
            
            if success:
                self._logger.info("MITRE ATT&CK validé")
            else:
                self._logger.error("MITRE ATT&CK: validation échouée")
                for check, passed in checks.items():
                    if not passed:
                        self._logger.error(f"   - {check}: échec")
            
            return ConfigResult(success=success, message=f"Validation: {'OK' if success else 'Échouée'}", details=checks)
            
        except FileOperationError as e:
            self._logger.error(f"Erreur fichier validation MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
        except Exception as e:
            self._logger.error(f"Erreur inattendue validation MITRE ATT&CK: {e}")
            return ConfigResult(success=False, message=f"Erreur: {e}")
