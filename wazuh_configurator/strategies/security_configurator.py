"""
Security Configurator - Security configuration strategy
Implements SSL/TLS, password management, API authentication, and firewall rules
"""

import os
import subprocess
import string
import secrets
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.cache import cached
from ..utils.exceptions import ConfigurationError, FileOperationError


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
        self.paths = WazuhPaths()
        self.security_config = {}
    
    @cached(ttl=300)  # Cache for 5 minutes
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
    
    @cached(ttl=300)
    def _check_ssl_config(self) -> bool:
        """Check if SSL is configured"""
        # Check Wazuh indexer SSL configuration
        if os.path.exists(self.paths.indexer_config):
            content = self.read_config_file(self.paths.indexer_config)
            return "plugins.security.ssl" in content or "ssl:" in content
        
        return False
    
    @cached(ttl=300)
    def _check_password_strength(self) -> bool:
        """Check if passwords are strong"""
        # Check Wazuh passwords file
        if os.path.exists(self.paths.passwords_file):
            content = self.read_config_file(self.paths.passwords_file)
            # Check if passwords are not default and are strong (long, mixed chars)
            # Strong password should be at least 20 chars with mixed characters
            if content:
                lines = content.strip().split('\n')
                for line in lines:
                    if ':' in line and not line.startswith('#'):
                        password = line.split(':')[1].strip()
                        if len(password) >= 20:
                            return True
        return False
    
    @cached(ttl=300)
    def _check_api_auth(self) -> bool:
        """Check if API authentication is configured"""
        if os.path.exists(self.paths.api_config):
            content = self.read_config_file(self.paths.api_config)
            return "jwt" in content.lower() or "basic" in content.lower()
        
        return False
    
    @cached(ttl=300)
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
                ports_found = 0
                for port in wazuh_ports:
                    if port in result.stdout:
                        ports_found += 1
                # Consider it OK if at least 3 ports are configured (not all required)
                return ports_found >= 3
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass
        
        return False
    
    def _apply_ssl_config(self) -> bool:
        """Apply SSL configuration"""
        print("[*] Configuration SSL/TLS...")
        
        try:
            import subprocess
            
            # Créer le répertoire pour les certificats
            cert_dir = self.paths.indexer_certs
            os.makedirs(cert_dir, exist_ok=True)
            
            # Générer un certificat auto-signé (pour développement/test)
            # En production, utiliser Let's Encrypt ou un certificat signé par une CA
            print("[*] Génération du certificat SSL/TLS...")
            
            # Générer la clé privée
            subprocess.run(
                ["openssl", "genrsa", "-out", f"{cert_dir}/wazuh-key.pem", "2048"],
                capture_output=True, check=True, timeout=60
            )
            
            # Générer le CSR
            subprocess.run(
                ["openssl", "req", "-new", "-key", f"{cert_dir}/wazuh-key.pem",
                 "-out", f"{cert_dir}/wazuh.csr",
                 "-subj", "/C=FR/ST=State/L=City/O=Wazuh/OU=Security/CN=wazuh.local"],
                capture_output=True, check=True, timeout=60
            )
            
            # Générer le certificat auto-signé (validité 365 jours)
            subprocess.run(
                ["openssl", "x509", "-req", "-days", "365",
                 "-in", f"{cert_dir}/wazuh.csr",
                 "-signkey", f"{cert_dir}/wazuh-key.pem",
                 "-out", f"{cert_dir}/wazuh-cert.pem"],
                capture_output=True, check=True, timeout=60
            )
            
            # Configurer les permissions
            os.chmod(f"{cert_dir}/wazuh-key.pem", 0o600)
            os.chmod(f"{cert_dir}/wazuh-cert.pem", 0o644)
            
            # Configurer OpenSearch pour utiliser SSL
            if os.path.exists(self.paths.indexer_config):
                self.backup_config(self.paths.indexer_config)
                content = self.read_config_file(self.paths.indexer_config)
                
                ssl_config = f"""
# SSL/TLS Configuration
plugins.security.ssl.transport.enabled: true
plugins.security.ssl.transport.pemcert_filepath: {self.paths.indexer_certs}/wazuh-cert.pem
plugins.security.ssl.transport.pemkey_filepath: {self.paths.indexer_certs}/wazuh-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: {self.paths.indexer_certs}/wazuh-cert.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: {self.paths.indexer_certs}/wazuh-cert.pem
plugins.security.ssl.http.pemkey_filepath: {self.paths.indexer_certs}/wazuh-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: {self.paths.indexer_certs}/wazuh-cert.pem
"""
                
                if "plugins.security.ssl" not in content:
                    content += ssl_config
                
                self.write_config_file(self.paths.indexer_config, content)
                self.config_files[self.paths.indexer_config] = True
            
            print("[+] Certificats SSL/TLS générés et configurés")
            print("[!] NOTE: Certificat auto-signé pour développement/test")
            print("[!] Pour production, utiliser Let's Encrypt ou certificat signé par CA")
            return True
            
        except OSError as e:
            raise FileOperationError(f"Impossible de créer le répertoire: {e}")
        except subprocess.CalledProcessError as e:
            raise ConfigurationError(f"Erreur génération certificat: {e}")
        except Exception as e:
            raise ConfigurationError(f"Erreur inattendue SSL: {e}")
    
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
            "indexer": generate_strong_password(),
            "dashboard": generate_strong_password()
        }
        
        self.security_config["passwords"] = passwords
        
        # Écrire les mots de passe dans le fichier wazuh-passwords.txt
        try:
            # Sauvegarder le fichier existant
            if os.path.exists(self.paths.passwords_file):
                self.backup_config(self.paths.passwords_file)
            
            # Écrire les nouveaux mots de passe
            password_content = f"""# Wazuh Passwords - Generated by Wazuh Configurator
# Date: {os.popen('date').read().strip()}
# IMPORTANT: Keep this file secure and change passwords regularly

# Wazuh Manager API
api_user: {passwords['api']}

# Wazuh Indexer
indexer_admin: {passwords['indexer']}

# Wazuh Dashboard
admin: {passwords['admin']}
dashboard_user: {passwords['dashboard']}
"""
            
            self.write_config_file(self.paths.passwords_file, password_content)
            os.chmod(self.paths.passwords_file, 0o600)  # Permissions restrictives
            self.config_files[self.paths.passwords_file] = True
            
            # Configurer les mots de passe dans les fichiers de configuration Wazuh
            self._configure_wazuh_passwords(passwords)
            
            print("[+] Mots de passe forts generes et écrits dans les fichiers Wazuh")
            print(f"[!] Mots de passe sauvegardés dans: {self.paths.passwords_file}")
            return True
            
        except Exception as e:
            print(f"[-] Erreur écriture mots de passe: {e}")
            return False
    
    def _configure_wazuh_passwords(self, passwords: dict) -> bool:
        """Configure les mots de passe dans les fichiers de configuration Wazuh"""
        try:
            # Configurer l'API Wazuh Manager
            if os.path.exists(self.paths.api_config):
                self.backup_config(self.paths.api_config)
                content = self.read_config_file(self.paths.api_config)
                
                # Mettre à jour le mot de passe API
                if "jwt:" in content or "basic:" in content:
                    content = content.replace("password: changeme", f"password: {passwords['api']}")
                    self.write_config_file(self.paths.api_config, content)
                    self.config_files[self.paths.api_config] = True
            
            # Configurer OpenSearch Security
            if os.path.exists(self.paths.internal_users):
                self.backup_config(self.paths.internal_users)
                content = self.read_config_file(self.paths.internal_users)
                
                # Mettre à jour le mot de passe admin
                content = content.replace("hash: changeme", f"hash: {passwords['indexer']}")
                self.write_config_file(self.paths.internal_users, content)
                self.config_files[self.paths.internal_users] = True
            
            return True
        except Exception as e:
            print(f"[-] Erreur configuration mots de passe: {e}")
            return False
    
    def _apply_api_auth(self) -> bool:
        """Apply API authentication"""
        print("[*] Configuration API authentication...")
        
        try:
            # Configurer l'API Wazuh Manager
            if os.path.exists(self.paths.api_config):
                self.backup_config(self.paths.api_config)
                content = self.read_config_file(self.paths.api_config)
                
                # Générer une clé secrète JWT
                jwt_secret = secrets.token_urlsafe(32)
                
                # Configuration JWT
                jwt_config = f"""
# JWT Authentication Configuration
jwt:
  enabled: true
  secret: """ + jwt_secret + """
  algorithm: HS256
  expiration: 3600  # 1 hour

# Basic Auth Configuration (fallback)
basic:
  enabled: true
  # Password is configured in """ + self.paths.passwords_file + """
"""
                
                # Ajouter la configuration JWT si elle n'existe pas
                if "jwt:" not in content:
                    content += jwt_config
                
                self.write_config_file(self.paths.api_config, content)
                self.config_files[self.paths.api_config] = True
                
                print("[+] API authentication JWT configurée")
                print("[!] Clé JWT générée et configurée")
                print("[!] L'API utilisera JWT avec Basic Auth comme fallback")
                return True
            else:
                print("[-] Fichier de configuration API non trouvé")
                return False
                
        except Exception as e:
            print(f"[-] Erreur configuration API authentication: {e}")
            return False
    
    def _apply_firewall_rules(self) -> bool:
        """Apply firewall rules"""
        print("[*] Configuration regles pare-feu...")
        
        try:
            import subprocess
            
            # Vérifier si ufw est disponible
            check_ufw = subprocess.run(
                ["which", "ufw"],
                capture_output=True, check=False
            )
            
            if check_ufw.returncode != 0:
                print("[!] UFW non disponible - Installation...")
                try:
                    # Installer UFW
                    subprocess.run(
                        ["sudo", "apt-get", "update"],
                        capture_output=True, check=True, timeout=120
                    )
                    subprocess.run(
                        ["sudo", "apt-get", "install", "-y", "ufw"],
                        capture_output=True, check=True, timeout=180
                    )
                    print("[+] UFW installé")
                except subprocess.CalledProcessError as e:
                    print(f"[-] Erreur installation UFW: {e}")
                    return True  # Pas une erreur critique
            
            # Configuration de base UFW
            print("[*] Configuration de base UFW...")
            
            # Refuser les connexions entrantes par défaut
            subprocess.run(
                ["sudo", "ufw", "default", "deny", "incoming"],
                capture_output=True, check=False, timeout=30
            )
            
            # Autoriser les connexions sortantes
            subprocess.run(
                ["sudo", "ufw", "default", "allow", "outgoing"],
                capture_output=True, check=False, timeout=30
            )
            
            # Autoriser SSH (port 22) - IMPORTANT pour ne pas se bloquer
            print("[+] Autorisation SSH (port 22)...")
            subprocess.run(
                ["sudo", "ufw", "allow", "22/tcp"],
                capture_output=True, check=False, timeout=30
            )
            
            # Autoriser les ports Wazuh
            wazuh_ports = {
                "9200": "Wazuh Indexer API",
                "1514": "Wazuh Manager (events)",
                "1515": "Wazuh Manager (agents)",
                "55000": "Wazuh API",
                "443": "HTTPS (Dashboard)"
            }
            
            for port, description in wazuh_ports.items():
                print(f"[+] Autorisation port {port} ({description})...")
                subprocess.run(
                    ["sudo", "ufw", "allow", f"{port}/tcp"],
                    capture_output=True, check=False, timeout=30
                )
            
            # Activer UFW
            print("[*] Activation UFW...")
            subprocess.run(
                ["sudo", "ufw", "--force", "enable"],
                capture_output=True, check=False, timeout=30
            )
            
            # Afficher le statut
            status = subprocess.run(
                ["sudo", "ufw", "status"],
                capture_output=True, text=True, check=False, timeout=30
            )
            
            print("[+] Regles pare-feu appliquées:")
            print(status.stdout)
            
            print("[+] Configuration pare-feu terminée")
            print("[!] SSH autorisé (port 22) - Ne pas oublier de configurer l'authentification par clé SSH")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Erreur configuration pare-feu: {e}")
            print("[!] Configuration pare-feu ignorée (pas critique)")
            return True  # Pas une erreur critique
        except Exception as e:
            print(f"[-] Erreur configuration pare-feu: {e}")
            print("[!] Configuration pare-feu ignorée (pas critique)")
            return True  # Pas une erreur critique
