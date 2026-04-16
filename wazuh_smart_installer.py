#!/usr/bin/env python3
"""
Wazuh Smart Installer - Installation avec résolution automatique des problèmes
Résout les problèmes courants d'installation Wazuh
"""

import subprocess
import sys
import os
import platform
import socket
import time
import json
import argparse
from pathlib import Path
import re


# ===================== BANNER =====================
def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(r"""
 ██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██╔═══██╗██╔════╝██╔══██╗
██║     ██║   ██║█████╗  ██║  ██║
██║     ██║   ██║██╔══╝  ██║  ██║
╚██████╗╚██████╔╝███████╗██████╔╝
 ╚═════╝ ╚═════╝ ╚══════╝╚═════╝ 
                               
    Smart Installer v2.0 - Intelligent Wazuh Installation
    By VulneZe - github.com/VulneZe/wazuh-install
    ====================================================
    """)

class WazuhSmartInstaller:
    """Installateur intelligent Wazuh avec détection et résolution de problèmes"""
    
    WAZUH_VERSION = "4.14"
    INSTALL_SCRIPT_URL = f"https://packages.wazuh.com/{WAZUH_VERSION}/wazuh-install.sh"
    
    # Ports utilisés par Wazuh
    WAZUH_PORTS = {
        "indexer": [9200, 9300],
        "server": [1514, 1515, 55000],
        "dashboard": [443, 5601]
    }
    
    # Problèmes courants et leurs solutions
    COMMON_ISSUES = {
        "port_conflict": "Conflit de ports détecté",
        "memory_insufficient": "Mémoire insuffisante (min 4GB recommandé)",
        "java_missing": "Java/OpenJDK manquant",
        "firewall_blocked": "Pare-feu bloquant les ports Wazuh",
        "disk_space": "Espace disque insuffisant (min 20GB recommandé)",
        "permissions": "Permissions insuffisantes (sudo requis)",
        "network": "Problèmes de connectivité réseau",
        "version_mismatch": "Incompatibilité de versions",
        "dependencies_missing": "Dépendances manquantes"
    }
    
    def __init__(self):
        self.os_type = self.detect_os()
        self.issues_found = []
        self.solutions_applied = []
        self.REQUIRED_DEPENDENCIES = [
            "curl",
            "wget",
            "bash",
            "python3",
            "tar",
            "gzip"
        ]
    
    def detect_os(self):
        """Détecter le système d'exploitation"""
        system = platform.system().lower()
        if system == "linux":
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read()
                    if "ubuntu" in content.lower():
                        return "ubuntu"
                    elif "debian" in content.lower():
                        return "debian"
                    elif "centos" in content.lower() or "rhel" in content.lower():
                        return "rhel"
                    elif "fedora" in content.lower():
                        return "fedora"
            except:
                return "linux"
        return system
    
    def check_root(self):
        """Vérifier si l'utilisateur a les droits root"""
        return os.geteuid() == 0
    
    def check_memory(self):
        """Vérifier la mémoire disponible"""
        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = f.read()
                match = re.search(r"MemTotal:\s+(\d+)", meminfo)
                if match:
                    mem_kb = int(match.group(1))
                    mem_gb = mem_kb / (1024 * 1024)
                    if mem_gb < 4:
                        self.issues_found.append("memory_insufficient")
                        return False, mem_gb
                    return True, mem_gb
        except:
            pass
        return True, 0
    
    def check_disk_space(self):
        """Vérifier l'espace disque"""
        try:
            result = subprocess.run(
                ["df", "-BG", "/"],
                capture_output=True, text=True, check=True
            )
            lines = result.stdout.split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                available_gb = int(parts[3].replace('G', ''))
                if available_gb < 20:
                    self.issues_found.append("disk_space")
                    return False, available_gb
                return True, available_gb
        except:
            pass
        return True, 0
    
    def check_java(self):
        """Vérifier si Java est installé"""
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True, text=True, check=False
            )
            if result.returncode == 0:
                return True
            self.issues_found.append("java_missing")
            return False
        except:
            self.issues_found.append("java_missing")
            return False
    
    def check_port_conflicts(self):
        """Vérifier les conflits de ports"""
        conflicts = []
        for component, ports in self.WAZUH_PORTS.items():
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    conflicts.append((component, port))
        
        if conflicts:
            self.issues_found.append("port_conflict")
            return False, conflicts
        return True, []
    
    def check_firewall(self):
        """Vérifier si le pare-feu bloque les ports"""
        try:
            # Vérifier si ufw est actif
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True, text=True, check=False
            )
            if "active" in result.stdout.lower():
                # Vérifier si les ports Wazuh sont ouverts
                all_ports = []
                for ports in self.WAZUH_PORTS.values():
                    all_ports.extend(ports)
                
                for port in all_ports:
                    port_result = subprocess.run(
                        ["ufw", "status"],
                        capture_output=True, text=True, check=False
                    )
                    if str(port) not in port_result.stdout and f"{port}/tcp" not in port_result.stdout:
                        self.issues_found.append("firewall_blocked")
                        return False
        except:
            pass
        return True
    
    def check_network(self):
        """Vérifier la connectivité réseau"""
        try:
            # Test de connexion à internet
            socket.create_connection(("8.8.8.8", 53), 5)
            # Test de résolution DNS
            socket.gethostbyname("packages.wazuh.com")
            return True
        except:
            return False
    
    def check_dependencies(self):
        """Vérifier si toutes les dépendances sont installées"""
        print("[*] Vérification des dépendances...")
        missing = []
        
        for dep in self.REQUIRED_DEPENDENCIES:
            if not self._check_command(dep):
                missing.append(dep)
                print(f"[-] Dépendance manquante: {dep}")
            else:
                print(f"[+] Dépendance présente: {dep}")
        
        if missing:
            print(f"[!] {len(missing)} dépendances manquantes")
            self.issues_found.append("dependencies_missing")
            return False, missing
        else:
            print("[+] Toutes les dépendances sont présentes")
            return True, []
    
    def install_dependencies(self, missing_deps):
        """Installer les dépendances manquantes automatiquement"""
        print(f"[*] Installation des {len(missing_deps)} dépendances manquantes...")
        
        try:
            if self.os_type in ["debian", "ubuntu"]:
                subprocess.run(
                    ["apt-get", "update"],
                    capture_output=True,
                    check=True,
                    timeout=120
                )
                for dep in missing_deps:
                    print(f"[*] Installation de {dep}...")
                    subprocess.run(
                        ["apt-get", "install", "-y", dep],
                        capture_output=True,
                        check=True,
                        timeout=120
                    )
                    print(f"[+] {dep} installé")
            elif self.os_type in ["rhel", "centos", "fedora"]:
                for dep in missing_deps:
                    print(f"[*] Installation de {dep}...")
                    subprocess.run(
                        ["yum", "install", "-y", dep],
                        capture_output=True,
                        check=True,
                        timeout=120
                    )
                    print(f"[+] {dep} installé")
            
            self.solutions_applied.append("dependencies_installed")
            print("[+] Dépendances installées avec succès")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[-] Erreur lors de l'installation des dépendances: {e}")
            return False
        except:
            self.issues_found.append("network")
            return False
    
    def pre_install_check(self):
        """Vérification complète avant installation"""
        print("[*] Verification de l'environnement avant installation...")
        print("=" * 60)
        
        # Vérifier OS
        print(f"[+] OS détecté: {self.os_type}")
        
        # Vérifier root
        if self.check_root():
            print("[+] Droits root: OK")
        else:
            print("[-] Droits root: Manquant (sudo requis)")
            self.issues_found.append("permissions")
        
        # Vérifier dépendances
        deps_ok, missing_deps = self.check_dependencies()
        if not deps_ok:
            print(f"[-] Dépendances manquantes: {missing_deps}")
        
        # Vérifier mémoire
        mem_ok, mem_gb = self.check_memory()
        if mem_ok:
            print(f"[+] Mémoire: {mem_gb:.1f} GB")
        else:
            print(f"[-] Mémoire: {mem_gb:.1f} GB (insuffisant)")
        
        # Vérifier espace disque
        disk_ok, disk_gb = self.check_disk_space()
        if disk_ok:
            print(f"[+] Espace disque: {disk_gb} GB disponibles")
        else:
            print(f"[-] Espace disque: {disk_gb} GB (insuffisant)")
        
        # Vérifier Java
        java_ok = self.check_java()
        if java_ok:
            print("[+] Java: Installé")
        else:
            print("[-] Java: Manquant")
        
        # Vérifier ports
        ports_ok, conflicts = self.check_port_conflicts()
        if ports_ok:
            print("[+] Ports: Aucun conflit")
        else:
            print(f"[-] Ports: Conflits détectés {conflicts}")
        
        # Vérifier pare-feu
        firewall_ok = self.check_firewall()
        if firewall_ok:
            print("[+] Pare-feu: OK")
        else:
            print("[!] Pare-feu: Peut bloquer les ports")
        
        # Vérifier réseau
        network_ok = self.check_network()
        if network_ok:
            print("[+] Réseau: OK")
        else:
            print("[-] Réseau: Problèmes détectés")
        
        print("=" * 60)
        
        if self.issues_found:
            print(f"[!] Problèmes détectés: {len(self.issues_found)}")
            for issue in self.issues_found:
                print(f"   - {self.COMMON_ISSUES.get(issue, issue)}")
            return False
        else:
            print("[+] Environnement prêt pour l'installation")
            return True
    
    def fix_java(self):
        """Installer Java automatiquement"""
        print("[*] Installation de Java...")
        try:
            if self.os_type in ["ubuntu", "debian"]:
                subprocess.run(
                    ["sudo", "apt", "update"],
                    capture_output=True, check=True
                )
                subprocess.run(
                    ["sudo", "apt", "install", "-y", "default-jdk"],
                    capture_output=True, check=True
                )
            elif self.os_type in ["rhel", "fedora", "centos"]:
                subprocess.run(
                    ["sudo", "yum", "install", "-y", "java-11-openjdk"],
                    capture_output=True, check=True
                )
            self.solutions_applied.append("java_installed")
            print("[+] Java installé avec succès")
            return True
        except Exception as e:
            print(f"[-] Erreur lors de l'installation de Java: {e}")
            return False
    
    def fix_firewall(self):
        """Configurer le pare-feu automatiquement"""
        print("[*] Configuration du pare-feu...")
        try:
            all_ports = []
            for ports in self.WAZUH_PORTS.values():
                all_ports.extend(ports)
            
            if self.os_type in ["ubuntu", "debian"]:
                for port in all_ports:
                    subprocess.run(
                        ["sudo", "ufw", "allow", f"{port}/tcp"],
                        capture_output=True, check=True
                    )
            elif self.os_type in ["rhel", "fedora", "centos"]:
                for port in all_ports:
                    subprocess.run(
                        ["sudo", "firewall-cmd", "--permanent", "--add-port", f"{port}/tcp"],
                        capture_output=True, check=True
                    )
                subprocess.run(
                    ["sudo", "firewall-cmd", "--reload"],
                    capture_output=True, check=True
                )
            
            self.solutions_applied.append("firewall_configured")
            print("[+] Pare-feu configuré avec succès")
            return True
        except Exception as e:
            print(f"[-] Erreur lors de la configuration du pare-feu: {e}")
            return False
    
    def auto_fix_issues(self):
        """Résoudre automatiquement les problèmes détectés"""
        if not self.issues_found:
            return True
        
        print("\n[*] Tentative de résolution automatique des problèmes...")
        
        for issue in self.issues_found:
            if issue == "java_missing":
                self.fix_java()
            elif issue == "firewall_blocked":
                self.fix_firewall()
            elif issue == "dependencies_missing":
                deps_ok, missing_deps = self.check_dependencies()
                if not deps_ok:
                    self.install_dependencies(missing_deps)
            elif issue == "permissions":
                print("[!] Exécutez avec sudo: sudo python3 wazuh_smart_installer.py")
            elif issue in ["memory_insufficient", "disk_space"]:
                print("[!] Problème matériel non résoluble automatiquement")
            elif issue == "port_conflict":
                print("[!] Libérez les ports en conflit manuellement")
            elif issue == "network":
                print("[!] Vérifiez votre connexion internet")
        
        # Revérifier après corrections
        self.issues_found = []
        return self.pre_install_check()
    
    def download_install_script(self):
        """Télécharger le script d'installation Wazuh"""
        print("[*] Téléchargement du script d'installation Wazuh...")
        
        # Vérifier si curl est installé
        curl_installed = self._check_command("curl")
        wget_installed = self._check_command("wget")
        
        if curl_installed:
            return self._download_with_curl()
        elif wget_installed:
            return self._download_with_wget()
        else:
            # Installer curl automatiquement
            print("[!] curl non installé, installation automatique...")
            if self._install_curl():
                return self._download_with_curl()
            else:
                print("[-] Impossible d'installer curl")
                return False
    
    def _check_command(self, command: str) -> bool:
        """Vérifier si une commande est disponible"""
        try:
            subprocess.run(
                ["which", command],
                capture_output=True,
                check=True,
                timeout=10
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _download_with_curl(self) -> bool:
        """Télécharger avec curl"""
        try:
            subprocess.run([
                "curl", "-sO", self.INSTALL_SCRIPT_URL
            ], check=True, timeout=60)
            print("[+] Script téléchargé avec succès (curl)")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[-] Erreur téléchargement avec curl: {e}")
            return False
    
    def _download_with_wget(self) -> bool:
        """Télécharger avec wget"""
        try:
            subprocess.run([
                "wget", "-q", self.INSTALL_SCRIPT_URL
            ], check=True, timeout=60)
            print("[+] Script téléchargé avec succès (wget)")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[-] Erreur téléchargement avec wget: {e}")
            return False
    
    def _install_curl(self) -> bool:
        """Installer curl automatiquement"""
        try:
            print("[*] Installation de curl...")
            if self.os_type == "debian" or self.os_type == "ubuntu":
                subprocess.run(
                    ["apt-get", "update"],
                    capture_output=True,
                    check=True,
                    timeout=120
                )
                subprocess.run(
                    ["apt-get", "install", "-y", "curl"],
                    capture_output=True,
                    check=True,
                    timeout=120
                )
            elif self.os_type == "rhel" or self.os_type == "centos" or self.os_type == "fedora":
                subprocess.run(
                    ["yum", "install", "-y", "curl"],
                    capture_output=True,
                    check=True,
                    timeout=120
                )
            print("[+] Curl installé avec succès")
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"[-] Erreur lors de l'installation de curl: {e}")
            return False
    
    def install_all_in_one(self, overwrite=False):
        """Installation all-in-one avec monitoring"""
        try:
            print("[*] Installation Wazuh All-in-One avec monitoring...")
            print("   - Wazuh Indexer")
            print("   - Wazuh Server")
            print("   - Wazuh Dashboard")
            
            if overwrite:
                print("[!] Mode overwrite activé - L'installation existante sera écrasée")
                install_cmd = ["sudo", "bash", "./wazuh-install.sh", "-a", "-o"]
            else:
                install_cmd = ["sudo", "bash", "./wazuh-install.sh", "-a"]
            
            # Lancer l'installation avec monitoring
            process = subprocess.Popen(
                install_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            
            # Monitorer la sortie en temps réel
            for line in process.stdout:
                print(line, end='')
                # Détecter les erreurs courantes
                if "error" in line.lower() or "failed" in line.lower():
                    print(f"[!] Erreur détectée: {line.strip()}")
            
            process.wait()
            
            if process.returncode == 0:
                print("[+] Installation Wazuh All-in-One terminée avec succès!")
                self.post_install_validation()
                return True
            else:
                print(f"[-] Erreur lors de l'installation (code: {process.returncode})")
                return False
        except Exception as e:
            print(f"[-] Erreur lors de l'installation: {e}")
            return False
    
    def post_install_validation(self):
        """Validation après installation"""
        print("\n[*] Validation post-installation...")
        
        services = ["wazuh-indexer", "wazuh-server", "wazuh-dashboard"]
        all_ok = True
        
        for service in services:
            try:
                result = subprocess.run([
                    "systemctl", "is-active", service
                ], capture_output=True, text=True)
                status = result.stdout.strip()
                if status == "active":
                    print(f"[+] {service}: Actif")
                else:
                    print(f"[-] {service}: Inactif ({status})")
                    all_ok = False
            except:
                print(f"[!] {service}: Impossible de vérifier")
                all_ok = False
        
        # Vérifier les ports
        print("\n[*] Vérification des ports...")
        for component, ports in self.WAZUH_PORTS.items():
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    print(f"[+] Port {port} ({component}): Ouvert")
                else:
                    print(f"[-] Port {port} ({component}): Fermé")
                    all_ok = False
        
        if all_ok:
            print("\n[+] Installation validée avec succès!")
            self.show_credentials()
        else:
            print("\n[!] Installation terminée mais certains services ne sont pas actifs")
        
        return all_ok
    
    def show_credentials(self):
        """Afficher les identifiants d'accès"""
        try:
            print("\n[*] Identifiants d'accès:")
            print("   - Interface web: https://<WAZUH_DASHBOARD_IP_ADDRESS>")
            print("   - Utilisateur: admin")
            print("   - Mot de passe: Voir wazuh-passwords.txt")
            
            if os.path.exists("wazuh-install-files.tar"):
                print("\n[*] Extraction des mots de passe...")
                subprocess.run([
                    "sudo", "tar", "-O", "-xvf", "wazuh-install-files.tar",
                    "wazuh-install-files/wazuh-passwords.txt"
                ], check=False)
        except:
            print("[!] Impossible d'extraire les mots de passe automatiquement")


def main():
    """Wazuh Smart Installer - Installation intelligente avec résolution automatique des problèmes"""
    banner()
    
    parser = argparse.ArgumentParser(
        description="Wazuh Smart Installer - Installation intelligente avec résolution automatique des problèmes",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--version', action='version', version='2.0.0')
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande install
    install_parser = subparsers.add_parser('install', help='Installer Wazuh')
    install_parser.add_argument('--auto-fix', '-a', action='store_true', help='Résoudre automatiquement les problèmes détectés')
    install_parser.add_argument('--skip-check', '-s', action='store_true', help='Sauter la vérification pré-installation')
    install_parser.add_argument('--overwrite', '-o', action='store_true', help='Forcer la réinstallation (écraser l\'installation existante)')
    
    # Commande check
    subparsers.add_parser('check', help='Vérifier l\'environnement sans installer')
    
    # Commande status
    subparsers.add_parser('status', help='Vérifier le statut des services Wazuh')
    
    # Commande uninstall
    uninstall_parser = subparsers.add_parser('uninstall', help='Désinstaller Wazuh')
    uninstall_parser.add_argument('--force', '-f', action='store_true', help='Forcer la désinstallation complète (supprimer toutes les configurations et données)')
    
    args = parser.parse_args()
    
    if args.command == 'install':
        installer = WazuhSmartInstaller()
        
        print(f"[+] OS détecté: {installer.os_type}")
        
        # Vérification pré-installation
        if not args.skip_check:
            env_ok = installer.pre_install_check()
            
            if not env_ok and args.auto_fix:
                installer.auto_fix_issues()
            
            if not env_ok and not args.auto_fix:
                print("\n[-] Problèmes détectés. Utilisez --auto-fix pour tenter une résolution automatique")
                sys.exit(1)
        
        # Télécharger le script
        installer.download_install_script()
        
        # Installation
        installer.install_all_in_one(overwrite=args.overwrite)
    
    elif args.command == 'check':
        installer = WazuhSmartInstaller()
        installer.pre_install_check()
    
    elif args.command == 'status':
        installer = WazuhSmartInstaller()
        installer.post_install_validation()
    
    elif args.command == 'uninstall':
        try:
            print("[*] Désinstallation de Wazuh...")
            if args.force:
                print("[!] Mode force activé - Suppression complète des configurations et données")
                subprocess.run([
                    "sudo", "bash", "./wazuh-install.sh", "-u", "-o"
                ], check=True)
            else:
                subprocess.run([
                    "sudo", "bash", "./wazuh-install.sh", "-u"
                ], check=True)
            print("[+] Wazuh désinstallé avec succès!")
            print("[!] Note: Si vous rencontrez des erreurs lors de la réinstallation, utilisez: python3 wazuh_smart_installer.py uninstall --force")
        except subprocess.CalledProcessError as e:
            print(f"[-] Erreur lors de la désinstallation: {e}")
            print("[!] Si le dashboard est encore détecté, essayez: python3 wazuh_smart_installer.py uninstall --force")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
