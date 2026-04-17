#!/usr/bin/env python3
"""
Wazuh Interactive Menu
Interface shell interactive pour tous les outils Wazuh
"""

import os
import sys
import subprocess


def clear_screen():
    """Effacer l'écran"""
    os.system('clear' if os.name == 'posix' else 'cls')


def banner():
    """Afficher la bannière"""
    print(r"""
 ██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██╔═══██╗██╔════╝██╔══██╗
██║     ██║   ██║█████╗  ██║  ██║
██║     ██║   ██║██╔══╝  ██║  ██║
╚██████╗╚██████╔╝███████╗██████╔╝
 ╚═════╝ ╚═════╝ ╚══════╝╚═════╝ 
                               
    Wazuh Interactive Menu v1.0
    By VulneZe - github.com/VulneZe/wazuh-install
    ====================================================
    """)


def main_menu():
    """Menu principal"""
    while True:
        clear_screen()
        banner()
        print("[1] Smart Installer - Installation Wazuh")
        print("[2] Configurator - Configuration Wazuh")
        print("[3] Quitter")
        print("=" * 60)
        
        choice = input("Choisissez une option [1-3]: ").strip()
        
        if choice == '1':
            smart_installer_menu()
        elif choice == '2':
            configurator_menu()
        elif choice == '3':
            print("\n[+] Au revoir!")
            sys.exit(0)
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def smart_installer_menu():
    """Menu Smart Installer"""
    while True:
        clear_screen()
        banner()
        print("=== Smart Installer ===")
        print("[1] Vérifier l'environnement")
        print("[2] Installer avec auto-fix (Recommandé)")
        print("[3] Installer sans auto-fix")
        print("[4] Installer en sautant les vérifications")
        print("[5] Vérifier le statut des services")
        print("[6] Désinstaller Wazuh")
        print("[7] Désinstaller Wazuh (Force - Suppression complète)")
        print("[0] Retour au menu principal")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-7]: ").strip()
        
        if choice == '1':
            run_smart_installer('check')
        elif choice == '2':
            run_smart_installer('install --auto-fix')
        elif choice == '3':
            run_smart_installer('install')
        elif choice == '4':
            run_smart_installer('install --skip-check')
        elif choice == '5':
            run_smart_installer('status')
        elif choice == '6':
            run_smart_installer('uninstall')
        elif choice == '7':
            run_smart_installer('uninstall --force')
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def configurator_menu():
    """Menu Configurator"""
    # Demander la configuration manager dès le début
    clear_screen()
    banner()
    print("=== Configuration des Services Wazuh ===")
    print("Cette configuration sera utilisée pour toutes les opérations du configurator")
    print("(Appuyez sur Entrée pour utiliser les valeurs par défaut)")
    print("=" * 60)
    
    manager_host = input("Adresse IP/hostname du Manager (défaut: localhost): ").strip() or "localhost"
    indexer_host = input("Adresse IP/hostname de l'Indexer (défaut: localhost): ").strip() or "localhost"
    dashboard_host = input("Adresse IP/hostname du Dashboard (défaut: localhost): ").strip() or "localhost"
    
    manager_port = input("Port Manager (défaut: 1514): ").strip() or "1514"
    indexer_port = input("Port Indexer (défaut: 9200): ").strip() or "9200"
    dashboard_port = input("Port Dashboard (défaut: 443): ").strip() or "443"
    
    # Sauvegarder la configuration
    config = {
        'manager_host': manager_host,
        'indexer_host': indexer_host,
        'dashboard_host': dashboard_host,
        'manager_port': manager_port,
        'indexer_port': indexer_port,
        'dashboard_port': dashboard_port
    }
    
    while True:
        clear_screen()
        banner()
        print("=== Configurator ===")
        print(f"Manager: {manager_host}:{manager_port}")
        print(f"Indexer: {indexer_host}:{indexer_port}")
        print(f"Dashboard: {dashboard_host}:{dashboard_port}")
        print("=" * 60)
        print("[1] Vérifier toutes les configurations")
        print("[2] Appliquer toutes les configurations")
        print("[3] Valider toutes les configurations")
        print("[4] Rollback toutes les configurations")
        print("[5] Mode Fix (Vérifier + Corriger + Valider)")
        print("[6] Configuration spécifique")
        print("[7] Modifier la configuration des services")
        print("[0] Retour au menu principal")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-7]: ").strip()
        
        if choice == '1':
            run_configurator('check', config)
        elif choice == '2':
            run_configurator('apply', config)
        elif choice == '3':
            run_configurator('validate', config)
        elif choice == '4':
            run_configurator('rollback', config)
        elif choice == '5':
            run_configurator('fix', config)
        elif choice == '6':
            specific_config_menu(config)
        elif choice == '7':
            return  # Retour pour redemander la configuration
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def specific_config_menu(config):
    """Menu configuration spécifique"""
    while True:
        clear_screen()
        banner()
        print("=== Configuration Spécifique ===")
        print(f"Manager: {config['manager_host']}:{config['manager_port']}")
        print(f"Indexer: {config['indexer_host']}:{config['indexer_port']}")
        print(f"Dashboard: {config['dashboard_host']}:{config['dashboard_port']}")
        print("=" * 60)
        print("[1] Security - SSL/TLS, mots de passe, pare-feu")
        print("[2] Performance - JVM, logs, disque, connexions")
        print("[3] Dashboard - Visualisations et dashboards Wazuh")
        print("[4] Règles SOCFortress - Règles avancées de détection")
        print("[0] Retour au menu Configurator")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-4]: ").strip()
        
        if choice == '1':
            config_action_menu('security', config)
        elif choice == '2':
            config_action_menu('performance', config)
        elif choice == '3':
            config_action_menu('dashboard', config)
        elif choice == '4':
            socfortress_rules_menu(config)
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def config_action_menu(config_name, config):
    """Menu actions pour configuration spécifique"""
    while True:
        clear_screen()
        banner()
        print(f"=== Configuration: {config_name} ===")
        print(f"Manager: {config['manager_host']}:{config['manager_port']}")
        print(f"Indexer: {config['indexer_host']}:{config['indexer_port']}")
        print(f"Dashboard: {config['dashboard_host']}:{config['dashboard_port']}")
        print("=" * 60)
        print("[1] Vérifier")
        print("[2] Appliquer")
        print("[3] Valider")
        print("[4] Rollback")
        print("[5] Fix (Vérifier + Corriger + Valider)")
        print("[0] Retour")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-5]: ").strip()
        
        if choice == '1':
            run_configurator(f'check --config {config_name}', config)
        elif choice == '2':
            run_configurator(f'apply --config {config_name}', config)
        elif choice == '3':
            run_configurator(f'validate --config {config_name}', config)
        elif choice == '4':
            run_configurator(f'rollback --config {config_name}', config)
        elif choice == '5':
            run_configurator(f'fix --config {config_name}', config)
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def run_smart_installer(args):
    """Exécuter le Smart Installer"""
    clear_screen()
    print(f"[*] Exécution: wazuh_smart_installer.py {args}")
    print("=" * 60)
    
    try:
        result = subprocess.run(
            [sys.executable, 'wazuh_smart_installer.py'] + args.split(),
            capture_output=False,
            text=True
        )
        print(f"\n[+] Code de retour: {result.returncode}")
    except Exception as e:
        print(f"[-] Erreur: {e}")
    
    input("\nAppuyez sur Entrée pour continuer...")


def run_configurator(args, config):
    """Exécuter le Configurator"""
    clear_screen()
    print(f"[*] Exécution: wazuh_configurator.py {args}")
    print("=" * 60)
    
    # Construire la commande avec les options de config
    cmd_args = args.split()
    
    # Ajouter les options de configuration si elles ne sont pas déjà dans args
    if not any("--manager-host" in arg for arg in cmd_args):
        if config['manager_host'] != "localhost":
            cmd_args.extend(["--manager-host", config['manager_host']])
    if not any("--indexer-host" in arg for arg in cmd_args):
        if config['indexer_host'] != "localhost":
            cmd_args.extend(["--indexer-host", config['indexer_host']])
    if not any("--dashboard-host" in arg for arg in cmd_args):
        if config['dashboard_host'] != "localhost":
            cmd_args.extend(["--dashboard-host", config['dashboard_host']])
    if not any("--manager-port" in arg for arg in cmd_args):
        if config['manager_port'] != "1514":
            cmd_args.extend(["--manager-port", config['manager_port']])
    if not any("--indexer-port" in arg for arg in cmd_args):
        if config['indexer_port'] != "9200":
            cmd_args.extend(["--indexer-port", config['indexer_port']])
    if not any("--dashboard-port" in arg for arg in cmd_args):
        if config['dashboard_port'] != "443":
            cmd_args.extend(["--dashboard-port", config['dashboard_port']])
    
    try:
        result = subprocess.run(
            [sys.executable, 'wazuh_configurator.py'] + cmd_args,
            capture_output=False,
            text=True
        )
        print(f"\n[+] Code de retour: {result.returncode}")
    except Exception as e:
        print(f"[-] Erreur: {e}")
    
    input("\nAppuyez sur Entrée pour continuer...")


def socfortress_rules_menu(config):
    """Menu pour les règles SOCFortress"""
    while True:
        clear_screen()
        banner()
        print("=== Règles SOCFortress ===")
        print("Règles avancées de détection pour Wazuh")
        print("https://github.com/socfortress/Wazuh-Rules")
        print("=" * 60)
        print(f"Manager: {config['manager_host']}:{config['manager_port']}")
        print("=" * 60)
        print("[1] Télécharger et installer toutes les règles")
        print("[2] Télécharger les règles (installation manuelle)")
        print("[3] Voir les catégories de règles disponibles")
        print("[4] Sélectionner des catégories spécifiques")
        print("[0] Retour au menu Configurator")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-4]: ").strip()
        
        if choice == '1':
            install_socfortress_rules(config)
        elif choice == '2':
            download_socfortress_rules(config)
        elif choice == '3':
            show_socfortress_categories()
        elif choice == '4':
            select_socfortress_categories(config)
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def install_socfortress_rules(config):
    """Installer les règles SOCFortress automatiquement"""
    clear_screen()
    print("=== Installation des Règles SOCFortress ===")
    print("=" * 60)
    print("[*] Téléchargement et installation des règles...")
    print("[*] Cette opération va:")
    print("    - Télécharger le script d'installation SOCFortress")
    print("    - Exécuter le script sur le Manager Wazuh")
    print("    - Installer toutes les règles de détection avancées")
    print()
    print("⚠️  ATTENTION:")
    print("    - Assurez-vous d'avoir une sauvegarde de vos règles personnalisées")
    print("    - Les ID de règles en double peuvent causer des conflits")
    print("    - Le service Wazuh-Manager peut redémarrer")
    print()
    
    confirm = input("Continuer? (o/n): ").strip().lower()
    if confirm != 'o':
        print("[+] Installation annulée")
        input("Appuyez sur Entrée pour continuer...")
        return
    
    print("[*] Téléchargement du script...")
    try:
        # Télécharger et exécuter le script SOCFortress
        subprocess.run(
            f"curl -so /tmp/wazuh_socfortress_rules.sh https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh_socfortress_rules.sh",
            shell=True,
            check=True
        )
        print("[+] Script téléchargé avec succès")
        
        print("[*] Exécution du script...")
        subprocess.run(
            "bash /tmp/wazuh_socfortress_rules.sh",
            shell=True,
            check=True
        )
        print("[+] Règles SOCFortress installées avec succès")
    except subprocess.CalledProcessError as e:
        print(f"[-] Erreur lors de l'installation: {e}")
    except Exception as e:
        print(f"[-] Erreur: {e}")
    
    input("Appuyez sur Entrée pour continuer...")


def download_socfortress_rules(config):
    """Télécharger les règles SOCFortress pour installation manuelle"""
    clear_screen()
    print("=== Téléchargement des Règles SOCFortress ===")
    print("=" * 60)
    print("[*] Téléchargement des règles pour installation manuelle...")
    print()
    print("Les règles seront téléchargées dans /tmp/wazuh_socfortress_rules/")
    print("Vous devrez les copier manuellement dans /var/ossec/rules/")
    print()
    
    confirm = input("Continuer? (o/n): ").strip().lower()
    if confirm != 'o':
        print("[+] Téléchargement annulé")
        input("Appuyez sur Entrée pour continuer...")
        return
    
    try:
        print("[*] Clonage du dépôt...")
        subprocess.run(
            "git clone https://github.com/socfortress/Wazuh-Rules.git /tmp/wazuh_socfortress_rules",
            shell=True,
            check=True
        )
        print("[+] Dépôt cloné avec succès")
        print("[*] Les règles se trouvent dans /tmp/wazuh_socfortress_rules/")
        print("[*] Copiez les fichiers .xml dans /var/ossec/rules/")
    except subprocess.CalledProcessError as e:
        print(f"[-] Erreur lors du téléchargement: {e}")
    except Exception as e:
        print(f"[-] Erreur: {e}")
    
    input("Appuyez sur Entrée pour continuer...")


def show_socfortress_categories():
    """Afficher les catégories de règles SOCFortress disponibles"""
    clear_screen()
    print("=== Catégories de Règles SOCFortress ===")
    print("=" * 60)
    print("Catégories de règles disponibles:")
    print()
    print("[1] Sysmon pour Windows - Détection avancée Windows")
    print("[2] Sysmon pour Linux - Détection avancée Linux")
    print("[3] Office 365 - Détection Microsoft Office 365")
    print("[4] Microsoft Defender - Détection Defender")
    print("[5] Sophos - Détection Sophos")
    print("[6] MISP - Intégration MISP")
    print("[7] Osquery - Détection Osquery")
    print("[8] Yara - Détection Yara")
    print("[9] Suricata - Détection Suricata")
    print("[10] Packetbeat - Détection Packetbeat")
    print("[11] Falco - Détection Falco")
    print("[12] Modsecurity - Détection Modsecurity")
    print("[13] F-Secure - Détection F-Secure")
    print("[14] AlienVault - Détection AlienVault")
    print("[15] Duo - Détection Duo")
    print("[16] Mimecast - Détection Mimecast")
    print("[17] Snyk - Détection Snyk")
    print("[18] Software - Détection Software")
    print("[19] Crowdstrike - Détection Crowdstrike")
    print("[20] Windows PowerShell - Détection PowerShell")
    print("[21] Windows Sigma Rules - Règles Sigma Windows")
    print("[22] Active Response - Réponses actives")
    print("[23] Et bien plus encore...")
    print()
    print("Pour la liste complète, visitez:")
    print("https://github.com/socfortress/Wazuh-Rules")
    
    input("Appuyez sur Entrée pour continuer...")


def select_socfortress_categories(config):
    """Sélectionner des catégories spécifiques de règles SOCFortress"""
    clear_screen()
    print("=== Sélection de Catégories SOCFortress ===")
    print("=" * 60)
    print("Fonctionnalité en développement...")
    print("Pour l'instant, utilisez l'option [1] pour installer toutes les règles")
    print("ou [2] pour télécharger et sélectionner manuellement.")
    print()
    
    input("Appuyez sur Entrée pour continuer...")


def main():
    """Point d'entrée principal"""
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[+] Interruption par l'utilisateur. Au revoir!")
        sys.exit(0)


if __name__ == "__main__":
    main()
