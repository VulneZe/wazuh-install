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
    MonitoringConfigurator,
    SecurityModulesConfigurator,
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
    for name, configurator in config_manager.configurators.items():
        logger.info(f"Verification {name}...")
        result = configurator.check()
        results[name] = result
        
        status = "[+]" if result.success else "[-]"
        logger.info(f"{status} {name}: {result.message}")
        
        if result.warnings:
            for warning in result.warnings:
                logger.warning(f"[!] {warning}")
    
    return results


def apply_configs(config_manager, config_names=None):
    """Apply configurations"""
    if config_names:
        logger.info(f"Application configurations: {', '.join(config_names)}")
        for name in config_names:
            result = config_manager.apply_config(name)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {name}: {result.message}")
    else:
        logger.info("Application des configurations...")
        results = {}
        for name, configurator in config_manager.configurators.items():
            logger.info(f"Application {name}...")
            result = configurator.apply()
            results[name] = result
            
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {name}: {result.message}")
        return results


def main():
    banner()
    
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
    parser.add_argument('--custom-ports', help='Ports personnalisés (format: indexer:9200,manager:1514,api:55000)')
    parser.add_argument('--wazuh-path', default='/var/ossec', help='Chemin d installation Wazuh (défaut: /var/ossec)')
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande detect
    subparsers.add_parser('detect', help='Detecter installation Wazuh')
    
    # Commande check
    check_parser = subparsers.add_parser('check', help='Verifier configurations')
    check_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'dashboard', 'all'], 
                            default='all', help='Configuration a verifier')
    
    # Commande apply
    apply_parser = subparsers.add_parser('apply', help='Appliquer configurations')
    apply_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'dashboard', 'all'], 
                            default='all', help='Configuration a appliquer')
    
    # Commande validate
    validate_parser = subparsers.add_parser('validate', help='Valider configurations')
    validate_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'dashboard', 'all'], 
                               default='all', help='Configuration a valider')
    
    # Commande rollback
    rollback_parser = subparsers.add_parser('rollback', help='Rollback configurations')
    rollback_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'dashboard', 'all'], 
                              default='all', help='Configuration a rollback')
    
    # Commande fix
    fix_parser = subparsers.add_parser('fix', help='Corriger configurations sur Wazuh existant')
    fix_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'dashboard', 'all'], 
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
    config_manager.register_configurator('monitoring', MonitoringConfigurator(wazuh_path=args.wazuh_path))
    config_manager.register_configurator('security-modules', SecurityModulesConfigurator(wazuh_path=args.wazuh_path))
    config_manager.register_configurator('dashboard', DashboardConfigurator(wazuh_path=args.wazuh_path))
    
    # Execute command
    if args.command == 'detect':
        detect_wazuh()
    
    elif args.command == 'check':
        if args.config == 'all':
            check_configs(config_manager)
        else:
            result = config_manager.get_configurator(args.config).check()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"   [!] {warning}")
    
    elif args.command == 'apply':
        if args.config == 'all':
            apply_configs(config_manager)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
    
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
        
        if args.config == 'all':
            check_results = check_configs(config_manager)
        else:
            result = config_manager.get_configurator(args.config).check()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
            if result.warnings:
                for warning in result.warnings:
                    logger.warning(f"   [!] {warning}")
        
        logger.info("\n[*] Application des corrections...")
        if args.config == 'all':
            apply_results = apply_configs(config_manager)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
        
        logger.info("\n[*] Validation des corrections...")
        if args.config == 'all':
            config_manager.validate_all_configs()
        else:
            result = config_manager.get_configurator(args.config).validate()
            status = "[+]" if result.success else "[-]"
            logger.info(f"{status} {args.config}: {result.message}")
    
    # Disconnect SSH if connected
    if args.remote_host:
        config_manager.disconnect_ssh()
        logger.info("[+] Connexion SSH fermée")


if __name__ == "__main__":
    main()
