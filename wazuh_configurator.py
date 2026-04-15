#!/usr/bin/env python3
"""
Wazuh Configurator - Main CLI interface
Advanced configuration management for Wazuh with design patterns
"""

import sys
import os
import argparse

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wazuh_configurator import ConfigManager, WazuhDetector
from wazuh_configurator.strategies import (
    SecurityConfigurator,
    PerformanceConfigurator,
    MonitoringConfigurator,
    SecurityModulesConfigurator
)


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
    print("[*] Detection de l'installation Wazuh...")
    
    detector = WazuhDetector()
    installation = detector.detect_installation()
    
    if installation.installed:
        print(f"[+] Wazuh version: {installation.version}")
        print(f"[+] Composants: {list(installation.components.keys())}")
        print(f"[+] Services status:")
        for service, status in installation.services_status.items():
            print(f"   - {service}: {status}")
        return installation
    else:
        print("[-] Wazuh non installe sur ce systeme")
        return None


def check_configs(config_manager):
    """Check all configurations"""
    print("[*] Verification de toutes les configurations...")
    
    results = config_manager.check_all_configs()
    
    for name, result in results.items():
        status = "[+]" if result.success else "[-]"
        print(f"{status} {name}: {result.message}")
        
        if result.warnings:
            for warning in result.warnings:
                print(f"   [!] {warning}")
    
    return results


def apply_configs(config_manager, config_names=None):
    """Apply configurations"""
    if config_names:
        print(f"[*] Application configurations: {', '.join(config_names)}")
        for name in config_names:
            result = config_manager.apply_config(name)
            status = "[+]" if result.success else "[-]"
            print(f"{status} {name}: {result.message}")
    else:
        print("[*] Application de toutes les configurations...")
        results = config_manager.apply_all_configs()
        
        for name, result in results.items():
            status = "[+]" if result.success else "[-]"
            print(f"{status} {name}: {result.message}")


def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description="Wazuh Configurator - Advanced Configuration Management",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commandes disponibles')
    
    # Commande detect
    subparsers.add_parser('detect', help='Detecter installation Wazuh')
    
    # Commande check
    check_parser = subparsers.add_parser('check', help='Verifier configurations')
    check_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'all'], 
                            default='all', help='Configuration a verifier')
    
    # Commande apply
    apply_parser = subparsers.add_parser('apply', help='Appliquer configurations')
    apply_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'all'], 
                            default='all', help='Configuration a appliquer')
    
    # Commande validate
    validate_parser = subparsers.add_parser('validate', help='Valider configurations')
    validate_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'all'], 
                               default='all', help='Configuration a valider')
    
    # Commande rollback
    rollback_parser = subparsers.add_parser('rollback', help='Rollback configurations')
    rollback_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'all'], 
                              default='all', help='Configuration a rollback')
    
    # Commande fix
    fix_parser = subparsers.add_parser('fix', help='Corriger configurations sur Wazuh existant')
    fix_parser.add_argument('--config', '-c', choices=['security', 'performance', 'monitoring', 'security-modules', 'all'], 
                          default='all', help='Configuration a corriger')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize config manager
    config_manager = ConfigManager()
    init_result = config_manager.initialize()
    
    if not init_result.success:
        print(f"[-] Erreur initialisation: {init_result.message}")
        return
    
    # Register configurators
    config_manager.register_configurator('security', SecurityConfigurator())
    config_manager.register_configurator('performance', PerformanceConfigurator())
    config_manager.register_configurator('monitoring', MonitoringConfigurator())
    config_manager.register_configurator('security-modules', SecurityModulesConfigurator())
    
    # Execute command
    if args.command == 'detect':
        detect_wazuh()
    
    elif args.command == 'check':
        if args.config == 'all':
            check_configs(config_manager)
        else:
            result = config_manager.get_configurator(args.config).check_current_config()
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")
            
            if result.warnings:
                for warning in result.warnings:
                    print(f"   [!] {warning}")
    
    elif args.command == 'apply':
        if args.config == 'all':
            apply_configs(config_manager)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")
    
    elif args.command == 'validate':
        if args.config == 'all':
            config_manager.validate_all_configs()
        else:
            result = config_manager.get_configurator(args.config).validate_config()
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")
    
    elif args.command == 'rollback':
        if args.config == 'all':
            config_manager.rollback_all_configs()
        else:
            result = config_manager.get_configurator(args.config).rollback_config()
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")
    
    elif args.command == 'fix':
        print("[*] Mode correction pour Wazuh existant...")
        print("[*] Verification des configurations actuelles...")
        
        check_results = check_configs(config_manager)
        
        print("\n[*] Application des corrections...")
        
        if args.config == 'all':
            apply_configs(config_manager)
        else:
            result = config_manager.apply_config(args.config)
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")
        
        print("\n[*] Validation des corrections...")
        if args.config == 'all':
            config_manager.validate_all_configs()
        else:
            result = config_manager.get_configurator(args.config).validate_config()
            status = "[+]" if result.success else "[-]"
            print(f"{status} {args.config}: {result.message}")


if __name__ == "__main__":
    main()
