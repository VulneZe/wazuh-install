#!/usr/bin/env python3
"""
Wazuh Configurator - Main CLI interface
Advanced configuration management for Wazuh with design patterns
"""

import os
import sys
import argparse
from wazuh_configurator.strategies import (
    SecurityConfigurator,
    PerformanceConfigurator,
    DashboardConfigurator
)
from wazuh_configurator.core import ConfigManager
from wazuh_configurator.core.wazuh_detector import WazuhDetector
from wazuh_configurator.utils.logger import WazuhLogger

# Initialize logger
logger = WazuhLogger(__name__, use_json=False)

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(r"""
 ██████╗ ██████╗ ███████╗██████╗ 
██╔════╝██╔═══██╗██╔════╝██╔══██╗
██║     ██║   ██║█████╗  ██║  ██║
██║     ██║   ██║██╔══╝  ██║  ██║
╚██████╗╚██████╔╝███████╗██████╔╝
 ╚═════╝ ╚═════╝ ╚══════╝╚═════╝ 
                               
    Configurator v1.0 - Advanced Configuration Management
    By VulneZe - github.com/VulneZe/wazuh-install
    ====================================================
    """)


def detect_wazuh():
    """Detect existing Wazuh installation"""
    logger.info("Detection de l'installation Wazuh...")
    
    detector = WazuhDetector()
    installation = detector.detect_installation()
    
    if installation.installed:
        logger.info(f"Wazuh version: {installation.version}")
        logger.info(f"Composants: {list(installation.components.keys())}")
        logger.info("Services status:")
        for service, status in installation.services_status.items():
            logger.info(f"   - {service}: {status}")
        return installation
    else:
        logger.error("Wazuh non installe sur ce systeme")
        return None


def check_configs(config_manager):
    """Check all configurations"""
    logger.info("Verification des configurations...")
    
    results = {}
    all_warnings = []
    all_errors = []
    
    for name, configurator in config_manager.configurators.items():
        logger.info(f"Verification {name}...")
        result = configurator.check()
        results[name] = result
        
        status = "[+]" if result.success else "[-]"
        logger.info(f"{status} {name}: {result.message}")
        
        if result.warnings:
            for warning in result.warnings:
                logger.warning(f"[!] {warning}")
                all_warnings.append(f"{name}: {warning}")
        
        if not result.success:
            all_errors.append(f"{name}: {result.message}")
    
    return results, all_warnings, all_errors


def apply_configs(config_manager, config_names=None):
    """Apply configurations"""
    all_warnings = []
    all_errors = []
    
    if config_names:
        logger.info(f"Application configurations: {', '.join(config_names)}")
        for name in config_names:
            result = config_manager.apply_config(name)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {name}: {result.message}")
            
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"[!] {warning}")
                    all_warnings.append(f"{name}: {warning}")
            
            if not result.success:
                all_errors.append(f"{name}: {result.message}")
        
        return all_warnings, all_errors
    else:
        logger.info("Application des configurations...")
        results = {}
        for name, configurator in config_manager.configurators.items():
            logger.info(f"Application {name}...")
            result = configurator.apply()
            results[name] = result
            
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {name}: {result.message}")
            
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"[!] {warning}")
                    all_warnings.append(f"{name}: {warning}")
            
            if not result.success:
                all_errors.append(f"{name}: {result.message}")
        
        return results, all_warnings, all_errors


def print_summary(all_warnings, all_errors):
    """Afficher le récapitulatif des warnings et erreurs"""
    if not all_warnings and not all_errors:
        logger.info("[+] Aucun warning ou erreur détecté")
        return
    
    print("\n" + "=" * 60)
    print("RÉCAPITULATIF")
    print("=" * 60)
    
    if all_warnings:
        print(f"\n[!] WARNINGS ({len(all_warnings)}):")
        for i, warning in enumerate(all_warnings, 1):
            print(f"   {i}. {warning}")
    
    if all_errors:
        print(f"\n[-] ERREURS ({len(all_errors)}):")
        for i, error in enumerate(all_errors, 1):
            print(f"   {i}. {error}")
    
    print("=" * 60 + "\n")


def interactive_menu():
    """Menu interactif pour le configurateur"""
    print("\n" + "=" * 60)
    print("MENU INTERACTIF")
    print("=" * 60)
    
    # Demander les IP/ports si nécessaire
    print("\nConfiguration des services Wazuh:")
    print("(Appuyez sur Entrée pour utiliser les valeurs par défaut)")
    
    manager_host = input("Adresse IP/hostname du Manager (défaut: localhost): ").strip() or "localhost"
    indexer_host = input("Adresse IP/hostname de l'Indexer (défaut: localhost): ").strip() or "localhost"
    dashboard_host = input("Adresse IP/hostname du Dashboard (défaut: localhost): ").strip() or "localhost"
    
    manager_port = input("Port Manager (défaut: 1514): ").strip() or "1514"
    indexer_port = input("Port Indexer (défaut: 9200): ").strip() or "9200"
    dashboard_port = input("Port Dashboard (défaut: 5601): ").strip() or "5601"
    
    # Choisir la commande
    print("\nCommandes disponibles:")
    print("1. check - Vérifier les configurations")
    print("2. apply - Appliquer les configurations")
    print("3. validate - Valider les configurations")
    print("4. rollback - Annuler les configurations")
    print("5. fix - Corriger les configurations")
    print("0. Quitter")
    
    command_choice = input("\nChoisissez une commande (0-5): ").strip()
    
    command_map = {
        "1": "check",
        "2": "apply",
        "3": "validate",
        "4": "rollback",
        "5": "fix",
        "0": None
    }
    
    command = command_map.get(command_choice)
    if command is None:
        print("\nAu revoir!")
        return None, None, None, None, None, None, None, None
    
    # Choisir la configuration
    print("\nConfigurations disponibles:")
    print("1. security - Configuration de sécurité")
    print("2. performance - Configuration de performance")
    print("3. dashboard - Configuration des dashboards")
    print("4. all - Toutes les configurations")
    
    config_choice = input("\nChoisissez une configuration (1-4): ").strip()
    
    config_map = {
        "1": "security",
        "2": "performance",
        "3": "dashboard",
        "4": "all"
    }
    
    config = config_map.get(config_choice, "all")
    
    return command, config, manager_host, indexer_host, dashboard_host, manager_port, indexer_port, dashboard_port


def main():
    banner()
    
    # Si aucun argument, afficher le menu interactif
    if len(sys.argv) == 1:
        command, config, manager_host, indexer_host, dashboard_host, manager_port, indexer_port, dashboard_port = interactive_menu()
        if command is None:
            return
        
        # Simuler les arguments
        sys.argv.extend([command, "--config", config])
        if manager_host != "localhost":
            sys.argv.extend(["--manager-host", manager_host])
        if indexer_host != "localhost":
            sys.argv.extend(["--indexer-host", indexer_host])
        if dashboard_host != "localhost":
            sys.argv.extend(["--dashboard-host", dashboard_host])
        if manager_port != "1514":
            sys.argv.extend(["--manager-port", manager_port])
        if indexer_port != "9200":
            sys.argv.extend(["--indexer-port", indexer_port])
        if dashboard_port != "5601":
            sys.argv.extend(["--dashboard-port", dashboard_port])
    
    parser = argparse.ArgumentParser(
        description="Wazuh Configurator - Advanced Configuration Management",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global arguments
    parser.add_argument('--remote-host', '-r', help='Adresse IP/hostname de la machine Wazuh distante')
    parser.add_argument('--ssh-user', '-u', help='Utilisateur SSH pour connexion distante')
    parser.add_argument('--ssh-key', '-k', help='Chemin de la clé SSH pour connexion distante')
    parser.add_argument('--ssh-password', '-p', help='Mot de passe SSH pour connexion distante')
    parser.add_argument('--ssh-port', default=22, type=int, help='Port SSH (défaut: 22)')
    parser.add_argument('--manager-host', help='Adresse IP/hostname du Wazuh Manager (défaut: localhost)')
    parser.add_argument('--indexer-host', help='Adresse IP/hostname du Wazuh Indexer (défaut: localhost)')
    parser.add_argument('--dashboard-host', help='Adresse IP/hostname du Wazuh Dashboard (défaut: localhost)')
    parser.add_argument('--manager-port', default=1514, type=int, help='Port Manager (défaut: 1514)')
    parser.add_argument('--indexer-port', default=9200, type=int, help='Port Indexer (défaut: 9200)')
    parser.add_argument('--dashboard-port', default=5601, type=int, help='Port Dashboard (défaut: 5601)')
    parser.add_argument('--custom-ports', help='Ports personnalisés (format: indexer:9200,manager:1514,api:55000)')
    parser.add_argument('--wazuh-path', default='/var/ossec', help='Chemin d installation Wazuh (défaut: /var/ossec)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Arguments globaux pour tous les sous-parsers
    common_args = [
        ('--remote-host', '-r', 'Adresse IP/hostname de la machine Wazuh distante'),
        ('--ssh-user', '-u', 'Utilisateur SSH pour connexion distante'),
        ('--ssh-key', '-k', 'Chemin de la clé SSH pour connexion distante'),
        ('--ssh-password', '-p', 'Mot de passe SSH pour connexion distante'),
        ('--ssh-port', 'Port SSH (défaut: 22)'),
        ('--manager-host', 'Adresse IP/hostname du Wazuh Manager (défaut: localhost)'),
        ('--indexer-host', 'Adresse IP/hostname du Wazuh Indexer (défaut: localhost)'),
        ('--dashboard-host', 'Adresse IP/hostname du Wazuh Dashboard (défaut: localhost)'),
        ('--manager-port', 'Port Manager (défaut: 1514)'),
        ('--indexer-port', 'Port Indexer (défaut: 9200)'),
        ('--dashboard-port', 'Port Dashboard (défaut: 5601)'),
        ('--custom-ports', 'Ports personnalisés (format: indexer:9200,manager:1514,api:55000)'),
        ('--wazuh-path', 'Chemin d installation Wazuh (défaut: /var/ossec)')
    ]
    
    def add_common_args(parser):
        """Ajouter les arguments communs à un parser"""
        for arg, help_text in common_args:
            if arg == '--ssh-port':
                parser.add_argument(arg, default=22, type=int, help=help_text)
            elif arg == '--manager-port':
                parser.add_argument(arg, default=1514, type=int, help=help_text)
            elif arg == '--indexer-port':
                parser.add_argument(arg, default=9200, type=int, help=help_text)
            elif arg == '--dashboard-port':
                parser.add_argument(arg, default=5601, type=int, help=help_text)
            elif arg == '--wazuh-path':
                parser.add_argument(arg, default='/var/ossec', help=help_text)
            else:
                parser.add_argument(arg, help=help_text)
    
    # Commande detect
    detect_parser = subparsers.add_parser('detect', help='Detecter installation Wazuh')
    add_common_args(detect_parser)
    
    # Commande check
    check_parser = subparsers.add_parser('check', help='Verifier configurations')
    add_common_args(check_parser)
    check_parser.add_argument('--config', '-c', choices=['security', 'performance', 'dashboard', 'all'], 
                            default='all', help='Configuration a verifier')
    
    # Commande apply
    apply_parser = subparsers.add_parser('apply', help='Appliquer configurations')
    add_common_args(apply_parser)
    apply_parser.add_argument('--config', '-c', choices=['security', 'performance', 'dashboard', 'all'], 
                            default='all', help='Configuration a appliquer')
    
    # Commande validate
    validate_parser = subparsers.add_parser('validate', help='Valider configurations')
    add_common_args(validate_parser)
    validate_parser.add_argument('--config', '-c', choices=['security', 'performance', 'dashboard', 'all'], 
                               default='all', help='Configuration a valider')
    
    # Commande rollback
    rollback_parser = subparsers.add_parser('rollback', help='Rollback configurations')
    add_common_args(rollback_parser)
    rollback_parser.add_argument('--config', '-c', choices=['security', 'performance', 'dashboard', 'all'], 
                              default='all', help='Configuration a rollback')
    
    # Commande fix
    fix_parser = subparsers.add_parser('fix', help='Corriger configurations sur Wazuh existant')
    add_common_args(fix_parser)
    fix_parser.add_argument('--config', '-c', choices=['security', 'performance', 'dashboard', 'all'], 
                          default='all', help='Configuration a corriger')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize config manager with remote configuration if provided
    config_manager = ConfigManager()
    
    # Set remote configuration if provided
    if args.remote_host:
        config_manager.set_remote_config(
            host=args.remote_host,
            ssh_user=args.ssh_user,
            ssh_key=args.ssh_key,
            ssh_password=args.ssh_password,
            ssh_port=args.ssh_port,
            custom_ports=args.custom_ports,
            wazuh_path=args.wazuh_path
        )
    
    init_result = config_manager.initialize()
    
    if not init_result.success:
        logger.error(f"Erreur initialisation: {init_result.message}")
        return
    
    # Connect via SSH if remote mode is enabled
    if args.remote_host:
        if not config_manager.connect_ssh():
            logger.error("Échec de la connexion SSH")
            return
    
    # Register configurators with remote configuration
    config_manager.register_configurator('security', SecurityConfigurator(wazuh_path=args.wazuh_path))
    config_manager.register_configurator('performance', PerformanceConfigurator(wazuh_path=args.wazuh_path))
    config_manager.register_configurator('dashboard', DashboardConfigurator(
        wazuh_path=args.wazuh_path,
        dashboard_host=args.dashboard_host or "localhost",
        dashboard_port=args.dashboard_port or 5601
    ))
    
    # Execute command
    if args.command == 'detect':
        detect_wazuh()
    
    elif args.command == 'check':
        if args.config == 'all':
            results, warnings, errors = check_configs(config_manager)
            print_summary(warnings, errors)
        else:
            result = config_manager.get_configurator(args.config).check()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            
            all_warnings = []
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"   [!] {warning}")
                    all_warnings.append(f"{args.config}: {warning}")
            
            all_errors = [] if result.success else [f"{args.config}: {result.message}"]
            print_summary(all_warnings, all_errors)
    
    elif args.command == 'apply':
        if args.config == 'all':
            results, warnings, errors = apply_configs(config_manager)
            print_summary(warnings, errors)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            
            all_warnings = []
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"[!] {warning}")
                    all_warnings.append(f"{args.config}: {warning}")
            
            all_errors = [] if result.success else [f"{args.config}: {result.message}"]
            print_summary(all_warnings, all_errors)
    
    elif args.command == 'validate':
        if args.config == 'all':
            config_manager.validate_all_configs()
        else:
            result = config_manager.get_configurator(args.config).validate()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
    
    elif args.command == 'rollback':
        if args.config == 'all':
            config_manager.rollback_all_configs()
        else:
            result = config_manager.rollback_config(args.config)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
    
    elif args.command == 'fix':
        logger.info("[*] Mode correction pour Wazuh existant...")
        logger.info("[*] Verification des configurations actuelles...")
        
        all_warnings = []
        all_errors = []
        
        if args.config == 'all':
            results, warnings, errors = check_configs(config_manager)
            all_warnings.extend(warnings)
            all_errors.extend(errors)
        else:
            result = config_manager.get_configurator(args.config).check()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"   [!] {warning}")
                    all_warnings.append(f"{args.config}: {warning}")
            if not result.success:
                all_errors.append(f"{args.config}: {result.message}")
        
        logger.info("\n[*] Application des corrections...")
        if args.config == 'all':
            results, warnings, errors = apply_configs(config_manager)
            all_warnings.extend(warnings)
            all_errors.extend(errors)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"[!] {warning}")
                    all_warnings.append(f"{args.config}: {warning}")
            if not result.success:
                all_errors.append(f"{args.config}: {result.message}")
        
        logger.info("\n[*] Validation des corrections...")
        if args.config == 'all':
            config_manager.validate_all_configs()
        else:
            result = config_manager.get_configurator(args.config).validate()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"[!] {warning}")
                    all_warnings.append(f"{args.config}: {warning}")
            if not result.success:
                all_errors.append(f"{args.config}: {result.message}")
        
        print_summary(all_warnings, all_errors)
    
    # Disconnect SSH if connected
    if args.remote_host:
        config_manager.disconnect_ssh()
        logger.info("[+] Connexion SSH fermée")


if __name__ == "__main__":
    main()
