#!/usr/bin/env python3
"""
Wazuh Installer - Installation simple et automatisée de Wazuh
Basé sur la documentation officielle Wazuh
"""

import subprocess
import sys
import os
import platform
from pathlib import Path
import click

class WazuhInstaller:
    """Installateur Wazuh simple et fonctionnel"""
    
    WAZUH_VERSION = "4.14"
    INSTALL_SCRIPT_URL = f"https://packages.wazuh.com/{WAZUH_VERSION}/wazuh-install.sh"
    
    def __init__(self):
        self.os_type = self.detect_os()
        self.installation_type = None
        self.components = []
    
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
    
    def download_install_script(self):
        """Télécharger le script d'installation Wazuh"""
        try:
            print(f"📥 Téléchargement du script d'installation Wazuh {self.WAZUH_VERSION}...")
            subprocess.run([
                "curl", "-sO", self.INSTALL_SCRIPT_URL
            ], check=True)
            print("✅ Script téléchargé avec succès")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors du téléchargement: {e}")
            return False
    
    def install_all_in_one(self):
        """Installation all-in-one (indexer, server, dashboard sur la même machine)"""
        try:
            print("🚀 Installation Wazuh All-in-One...")
            print("   - Wazuh Indexer")
            print("   - Wazuh Server")
            print("   - Wazuh Dashboard")
            
            subprocess.run([
                "sudo", "bash", "./wazuh-install.sh", "-a"
            ], check=True)
            
            print("✅ Installation Wazuh All-in-One terminée avec succès!")
            self.show_credentials()
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de l'installation: {e}")
            return False
    
    def install_distributed(self):
        """Installation distribuée (composants sur différentes machines)"""
        print("📋 Installation distribuée de Wazuh")
        print("Cette méthode nécessite plusieurs machines.")
        print("Veuillez consulter la documentation Wazuh pour les détails:")
        print("https://documentation.wazuh.com/current/installation-guide/index.html")
        return False
    
    def install_component(self, component):
        """Installer un composant spécifique"""
        try:
            print(f"🔧 Installation de {component}...")
            
            if component == "indexer":
                subprocess.run([
                    "sudo", "bash", "./wazuh-install.sh", "-i"
                ], check=True)
            elif component == "server":
                subprocess.run([
                    "sudo", "bash", "./wazuh-install.sh", "-w"
                ], check=True)
            elif component == "dashboard":
                subprocess.run([
                    "sudo", "bash", "./wazuh-install.sh", "-d"
                ], check=True)
            
            print(f"✅ {component} installé avec succès!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de l'installation de {component}: {e}")
            return False
    
    def uninstall_wazuh(self):
        """Désinstaller Wazuh"""
        try:
            print("🗑️ Désinstallation de Wazuh...")
            subprocess.run([
                "sudo", "bash", "./wazuh-install.sh", "-u"
            ], check=True)
            print("✅ Wazuh désinstallé avec succès!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Erreur lors de la désinstallation: {e}")
            return False
    
    def show_credentials(self):
        """Afficher les identifiants d'accès"""
        try:
            print("\n📋 Identifiants d'accès:")
            print("   - Interface web: https://<WAZUH_DASHBOARD_IP_ADDRESS>")
            print("   - Utilisateur: admin")
            print("   - Mot de passe: Voir wazuh-passwords.txt")
            
            # Essayer d'extraire le mot de passe
            if os.path.exists("wazuh-install-files.tar"):
                print("\n🔑 Extraction des mots de passe...")
                subprocess.run([
                    "sudo", "tar", "-O", "-xvf", "wazuh-install-files.tar",
                    "wazuh-install-files/wazuh-passwords.txt"
                ], check=False)
        except:
            print("⚠️ Impossible d'extraire les mots de passe automatiquement")
    
    def check_wazuh_status(self):
        """Vérifier le statut des services Wazuh"""
        services = ["wazuh-indexer", "wazuh-server", "wazuh-dashboard"]
        for service in services:
            try:
                result = subprocess.run([
                    "systemctl", "is-active", service
                ], capture_output=True, text=True)
                status = result.stdout.strip()
                if status == "active":
                    print(f"✅ {service}: Actif")
                else:
                    print(f"❌ {service}: Inactif ({status})")
            except:
                print(f"⚠️ {service}: Impossible de vérifier le statut")


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Wazuh Installer - Installation simple et automatisée de Wazuh"""
    pass


@cli.command()
@click.option('--type', '-t', 
              type=click.Choice(['all-in-one', 'distributed', 'indexer', 'server', 'dashboard']),
              default='all-in-one',
              help='Type d\'installation')
def install(type):
    """Installer Wazuh"""
    installer = WazuhInstaller()
    
    print(f"🖥️ OS détecté: {installer.os_type}")
    
    # Télécharger le script d'installation
    if not installer.download_install_script():
        sys.exit(1)
    
    # Installation selon le type choisi
    if type == 'all-in-one':
        installer.install_all_in_one()
    elif type == 'distributed':
        installer.install_distributed()
    elif type in ['indexer', 'server', 'dashboard']:
        installer.install_component(type)
    
    # Vérifier le statut après installation
    if type in ['all-in-one', 'indexer', 'server', 'dashboard']:
        print("\n📊 Statut des services Wazuh:")
        installer.check_wazuh_status()


@cli.command()
def uninstall():
    """Désinstaller Wazuh"""
    installer = WazuhInstaller()
    installer.uninstall_wazuh()


@cli.command()
def status():
    """Vérifier le statut des services Wazuh"""
    installer = WazuhInstaller()
    installer.check_wazuh_status()


@cli.command()
def credentials():
    """Afficher les identifiants d'accès"""
    installer = WazuhInstaller()
    installer.show_credentials()


if __name__ == "__main__":
    cli()
