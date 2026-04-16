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
    while True:
        clear_screen()
        banner()
        print("=== Configurator ===")
        print("[1] Vérifier toutes les configurations")
        print("[2] Appliquer toutes les configurations")
        print("[3] Valider toutes les configurations")
        print("[4] Rollback toutes les configurations")
        print("[5] Mode Fix (Vérifier + Corriger + Valider)")
        print("[6] Configuration spécifique")
        print("[0] Retour au menu principal")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-6]: ").strip()
        
        if choice == '1':
            run_configurator('check')
        elif choice == '2':
            run_configurator('apply')
        elif choice == '3':
            run_configurator('validate')
        elif choice == '4':
            run_configurator('rollback')
        elif choice == '5':
            run_configurator('fix')
        elif choice == '6':
            specific_config_menu()
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def specific_config_menu():
    """Menu configuration spécifique"""
    while True:
        clear_screen()
        banner()
        print("=== Configuration Spécifique ===")
        print("[1] Security - SSL/TLS, mots de passe, pare-feu")
        print("[2] Performance - JVM, logs, disque, connexions")
        print("[3] Monitoring - Services, logs, alertes")
        print("[4] Security Modules - Vulnerability Detector, CIS, FIM, MITRE")
        print("[5] Dashboard - Visualisations et dashboards Wazuh")
        print("[0] Retour au menu Configurator")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-5]: ").strip()
        
        if choice == '1':
            config_action_menu('security')
        elif choice == '2':
            config_action_menu('performance')
        elif choice == '3':
            config_action_menu('monitoring')
        elif choice == '4':
            config_action_menu('security-modules')
        elif choice == '5':
            config_action_menu('dashboard')
        elif choice == '0':
            return
        else:
            print("\n[-] Option invalide, réessayez...")
            input("Appuyez sur Entrée pour continuer...")


def config_action_menu(config_name):
    """Menu actions pour configuration spécifique"""
    while True:
        clear_screen()
        banner()
        print(f"=== Configuration: {config_name} ===")
        print("[1] Vérifier")
        print("[2] Appliquer")
        print("[3] Valider")
        print("[4] Rollback")
        print("[5] Fix (Vérifier + Corriger + Valider)")
        print("[0] Retour")
        print("=" * 60)
        
        choice = input("Choisissez une option [0-5]: ").strip()
        
        if choice == '1':
            run_configurator(f'check --config {config_name}')
        elif choice == '2':
            run_configurator(f'apply --config {config_name}')
        elif choice == '3':
            run_configurator(f'validate --config {config_name}')
        elif choice == '4':
            run_configurator(f'rollback --config {config_name}')
        elif choice == '5':
            run_configurator(f'fix --config {config_name}')
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


def run_configurator(args):
    """Exécuter le Configurator"""
    clear_screen()
    print(f"[*] Exécution: wazuh_configurator.py {args}")
    print("=" * 60)
    
    try:
        result = subprocess.run(
            [sys.executable, 'wazuh_configurator.py'] + args.split(),
            capture_output=False,
            text=True
        )
        print(f"\n[+] Code de retour: {result.returncode}")
    except Exception as e:
        print(f"[-] Erreur: {e}")
    
    input("\nAppuyez sur Entrée pour continuer...")


def main():
    """Point d'entrée principal"""
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[+] Interruption par l'utilisateur. Au revoir!")
        sys.exit(0)


if __name__ == "__main__":
    main()
