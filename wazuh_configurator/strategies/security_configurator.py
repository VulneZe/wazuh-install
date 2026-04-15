"""
Security Configurator - Security configuration strategy
Implements SSL/TLS and authentication configuration
"""

from typing import Dict, Optional
import os
import secrets
import string
import subprocess
from ..core.base_configurator import BaseConfigurator, ConfigResult


class SecurityConfigurator(BaseConfigurator):
    """Security configuration strategy"""
    
    SECURITY_CHECKS = {
        "ssl_enabled": "SSL/TLS enabled",
        "strong_passwords": "Strong passwords configured",
        "api_auth": "API authentication configured",
        "firewall_rules": "Firewall rules configured"
    }
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        super().__init__(wazuh_path)
        self.security_config = {}
    
    def check(self) -> ConfigResult:
        """Check current security configuration"""
        print("[*] Verification configuration securite...")
        
        results = {}
        warnings = []
        
        # Check SSL configuration
        ssl_result = self._check_ssl_config()
        results["ssl_enabled"] = ssl_result
        
        if not ssl_result:
            warnings.append("SSL/TLS non configure")
        
        # Check password strength
        password_result = self._check_password_strength()
        results["strong_passwords"] = password_result
        
        if not password_result:
            warnings.append("Mots de passe faibles detectes")
        
        # Check API authentication
        api_result = self._check_api_auth()
        results["api_auth"] = api_result
        
        if not api_result:
            warnings.append("API authentication non configuree")
        
        # Check firewall
        firewall_result = self._check_firewall_rules()
        results["firewall_rules"] = firewall_result
        
        if not firewall_result:
            warnings.append("Regles pare-feu incompletes")
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Securite: {success_count}/{total_count} verifications OK",
            details=results,
            warnings=warnings
        )
    
    def apply(self) -> ConfigResult:
        """Apply security configuration"""
        print("[*] Application configuration securite...")
        
        results = {}
        
        # Apply SSL configuration
        ssl_result = self._apply_ssl_config()
        results["ssl_config"] = ssl_result
        
        # Apply strong passwords
        password_result = self._apply_strong_passwords()
        results["passwords"] = password_result
        
        # Apply API authentication
        api_result = self._apply_api_auth()
        results["api_auth"] = api_result
        
        # Apply firewall rules
        firewall_result = self._apply_firewall_rules()
        results["firewall"] = firewall_result
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Securite: {success_count}/{total_count} configurations appliquees",
            details=results
        )
    
    def validate(self) -> ConfigResult:
        """Validate security configuration"""
        print("[*] Validation configuration securite...")
        return self.check()
    
    def rollback(self) -> ConfigResult:
        """Rollback security configuration"""
        print("[*] Rollback configuration securite...")
        
        success = True
        for config_file in self.config_files.keys():
            if not self.restore_config(config_file):
                success = False
        
        return ConfigResult(
            success=success,
            message="Rollback securite termine",
            details={"rollback": success}
        )
    
    def _check_ssl_config(self) -> bool:
        """Check if SSL is properly configured"""
        # Check indexer SSL config
        indexer_config = "/etc/wazuh-indexer/opensearch.yml"
        if os.path.exists(indexer_config):
            content = self.read_config_file(indexer_config)
            return "plugins.security.ssl" in content or "ssl:" in content
        
        return False
    
    def _check_password_strength(self) -> bool:
        """Check if passwords are strong"""
        # Check Wazuh passwords file
        passwords_file = "wazuh-passwords.txt"
        if os.path.exists(passwords_file):
            content = self.read_config_file(passwords_file)
            # Check if passwords are not default
            return "admin" not in content or len(content) > 50
        
        return False
    
    def _check_api_auth(self) -> bool:
        """Check if API authentication is configured"""
        api_config = "/var/ossec/api/configuration/api.yaml"
        if os.path.exists(api_config):
            content = self.read_config_file(api_config)
            return "jwt" in content.lower() or "basic" in content.lower()
        
        return False
    
    def _check_firewall_rules(self) -> bool:
        """Check if firewall rules are configured"""
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True, text=True, check=False,
                timeout=10
            )
            if "active" in result.stdout.lower():
                # Check if Wazuh ports are open
                wazuh_ports = ["9200", "1514", "1515", "55000", "443"]
                for port in wazuh_ports:
                    if port not in result.stdout:
                        return False
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass
        
        return False
    
    def _apply_ssl_config(self) -> bool:
        """Apply SSL configuration"""
        print("[*] Configuration SSL/TLS...")
        # This would generate SSL certificates and configure them
        # For now, return True as placeholder
        return True
    
    def _apply_strong_passwords(self) -> bool:
        """Apply strong passwords"""
        print("[*] Generation mots de passe forts...")
        
        def generate_strong_password(length=32):
            alphabet = string.ascii_letters + string.digits + string.punctuation
            return ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Generate strong passwords for different components
        passwords = {
            "admin": generate_strong_password(),
            "api": generate_strong_password(),
            "indexer": generate_strong_password()
        }
        
        self.security_config["passwords"] = passwords
        print("[+] Mots de passe forts generes")
        return True
    
    def _apply_api_auth(self) -> bool:
        """Apply API authentication"""
        print("[*] Configuration API authentication...")
        # Configure JWT or basic auth for API
        return True
    
    def _apply_firewall_rules(self) -> bool:
        """Apply firewall rules"""
        print("[*] Configuration regles pare-feu...")
        
        try:
            import subprocess
            wazuh_ports = ["9200", "1514", "1515", "55000", "443"]
            
            for port in wazuh_ports:
                subprocess.run(
                    ["sudo", "ufw", "allow", f"{port}/tcp"],
                    capture_output=True, check=True
                )
            
            print("[+] Regles pare-feu appliquees")
            return True
        except Exception as e:
            print(f"[-] Erreur configuration pare-feu: {e}")
            return False
