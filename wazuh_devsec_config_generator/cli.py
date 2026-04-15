#!/usr/bin/env python3
"""
CLI Interface for Wazuh DevSec Generator
Simple and clean command line interface
"""

import sys
import click
from pathlib import Path
from typing import Optional

from .core import get_settings, get_logger
from .core.config import ConfigManager, ProfileType
from .core.factory import ConfigurationFactory
from .ui.smart_verification import SmartVerification
from .ui.terminal import EnhancedTerminalUI, UIConfig, UIStyle


@click.group()
@click.version_option(version="2.0.0", prog_name="wazuh-generator")
@click.option('--verbose', '-v', is_flag=True, help='Mode verbeux')
@click.option('--config', '-c', type=click.Path(), help='Fichier de configuration personnalisé')
@click.pass_context
def cli(ctx, verbose, config):
    """Générateur professionnel de configuration Wazuh pour environnement DevSec"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['config'] = config
    
    # Initialize logger
    settings = get_settings()
    if verbose:
        settings.logging.level = "DEBUG"
    
    logger = get_logger()
    logger.info("Wazuh DevSec Generator CLI initialized")


@cli.command()
@click.option('--profile', '-p', default='development', 
              type=click.Choice(['development', 'production', 'testing', 'custom']),
              help='Profil de configuration à utiliser')
@click.option('--output', '-o', default='output', type=click.Path(), 
              help='Répertoire de sortie')
@click.option('--simulate', '-s', is_flag=True, help='Mode simulation')
@click.pass_context
def generate(ctx, profile, output, simulate):
    """Générer la configuration Wazuh"""
    try:
        settings = get_settings()
        
        # Update output directory
        settings.paths.output_dir = Path(output)
        
        # Get profile
        config_manager = ConfigManager()
        wazuh_profile = config_manager.get_profile(profile)
        
        if not wazuh_profile:
            click.echo(f"❌ Profil '{profile}' non trouvé", err=True)
            sys.exit(1)
        
        click.echo(f"🔧 Génération de la configuration pour le profil: {profile}")
        
        if simulate:
            click.echo("🧪 Mode simulation activé")
        
        # Generate configuration
        factory = ConfigurationFactory(settings.paths.output_dir)
        result = factory.create_configuration(profile)
        
        click.echo("✅ Configuration générée avec succès!")
        click.echo(f"📁 Répertoire de sortie: {settings.paths.output_dir}")
        
        # Show results
        if ctx.obj.get('verbose'):
            click.echo("\n📊 Résultats:")
            click.echo(f"  - Règles: {result.get('rules_count', 0)}")
            click.echo(f"  - Décodeurs: {result.get('decoders_count', 0)}")
            click.echo(f"  - Listes CDB: {result.get('lists_count', 0)}")
            click.echo(f"  - Dashboards: {result.get('dashboards_count', 0)}")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', default='output', type=click.Path(), 
              help='Répertoire de sortie')
@click.pass_context
def verify(ctx, output):
    """Vérifier la configuration générée"""
    try:
        from .core.validator import WazuhValidator
        
        settings = get_settings()
        settings.paths.output_dir = Path(output)
        
        click.echo("🔍 Vérification de la configuration...")
        
        validator = WazuhValidator(settings.paths.output_dir)
        results = validator.validate_all()
        
        if results['valid']:
            click.echo("✅ Configuration valide!")
        else:
            click.echo("❌ Erreurs trouvées:")
            for error in results['errors']:
                click.echo(f"  - {error}")
        
        if ctx.obj.get('verbose'):
            click.echo(f"\n📊 Détails:")
            click.echo(f"  - Règles validées: {results.get('rules_validated', 0)}")
            click.echo(f"  - Décodeurs validés: {results.get('decoders_validated', 0)}")
            click.echo(f"  - Listes validées: {results.get('lists_validated', 0)}")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', default='output', type=click.Path(), 
              help='Répertoire de sortie')
@click.pass_context
def analyze(ctx, output):
    """Analyser la qualité des règles"""
    try:
        from .core.rule_analyzer import RuleAnalyzer
        
        settings = get_settings()
        settings.paths.output_dir = Path(output)
        
        click.echo("📈 Analyse des règles...")
        
        analyzer = RuleAnalyzer()
        analyses = analyzer.analyze_rules_directory(settings.paths.output_dir / "etc/rules")
        
        # Display analysis
        for rule_id, analysis in analyses.items():
            status = "✅" if analysis['quality_score'] >= 70 else "⚠️" if analysis['quality_score'] >= 50 else "❌"
            click.echo(f"{status} {rule_id}: {analysis['quality_score']}/100")
            
            if ctx.obj.get('verbose'):
                click.echo(f"    - Complexité: {analysis['complexity']}")
                click.echo(f"    - Faux positifs: {analysis['false_positive_risk']}")
                click.echo(f"    - Recommandations: {len(analysis['suggestions'])}")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def smart(ctx):
    """Vérification intelligente de l'environnement"""
    try:
        click.echo("🔍 Vérification intelligente de l'environnement...")
        
        # Setup UI
        ui_config = UIConfig(
            style=UIStyle.PROFESSIONAL,
            show_animations=True,
            show_progress_bars=True,
            show_status_icons=True
        )
        ui = EnhancedTerminalUI(ui_config)
        
        # Run smart verification
        verifier = SmartVerification(ui)
        results = verifier.run_comprehensive_verification()
        
        # Display results
        verifier.display_verification_results(results)
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--profile', '-p', default='development', 
              type=click.Choice(['development', 'production', 'testing', 'custom']),
              help='Profil de configuration à utiliser')
@click.option('--output', '-o', default='output', type=click.Path(), 
              help='Répertoire de sortie')
@click.pass_context
def deploy(ctx, profile, output):
    """Déployer la configuration Wazuh"""
    try:
        from .core.simulation import DeploymentSimulator
        
        settings = get_settings()
        settings.paths.output_dir = Path(output)
        
        click.echo("🚀 Déploiement de la configuration...")
        
        simulator = DeploymentSimulator(settings.paths.output_dir)
        results = simulator.simulate_deployment(profile)
        
        if results['success']:
            click.echo("✅ Déploiement simulé réussi!")
        else:
            click.echo("❌ Erreurs de déploiement:")
            for error in results['errors']:
                click.echo(f"  - {error}")
        
        if ctx.obj.get('verbose'):
            click.echo(f"\n📊 Détails du déploiement:")
            for step, result in results['steps'].items():
                status = "✅" if result['success'] else "❌"
                click.echo(f"  {status} {step}: {result['message']}")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
def list_profiles():
    """Lister les profils disponibles"""
    try:
        config_manager = ConfigManager()
        profiles = config_manager.list_profiles()
        
        click.echo("📋 Profils disponibles:")
        for profile_name in profiles:
            profile = config_manager.get_profile(profile_name)
            click.echo(f"  • {profile_name} ({profile.type}): {profile.description}")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--profile', '-p', required=True, 
              type=click.Choice(['development', 'production', 'testing', 'custom']),
              help='Profil à utiliser')
@click.option('--rule', '-r', required=True, help='ID de la règle à tester')
@click.option('--log', '-l', required=True, help='Fichier de log à tester')
def test_rule(profile, rule, log):
    """Tester une règle avec un fichier de log"""
    try:
        from .core.validator import WazuhValidator
        
        settings = get_settings()
        validator = WazuhValidator(settings.paths.output_dir)
        
        click.echo(f"🧪 Test de la règle {rule} avec le log {log}...")
        
        result = validator.test_rule(rule, log)
        
        if result['matched']:
            click.echo("✅ Règle déclenchée!")
            click.echo(f"  - Alert Level: {result['alert_level']}")
            click.echo(f"  - Description: {result['description']}")
        else:
            click.echo("❌ Règle non déclenchée")
        
    except Exception as e:
        click.echo(f"❌ Erreur: {e}", err=True)
        sys.exit(1)


def main():
    """Point d'entrée principal"""
    cli()


def smart_main():
    """Point d'entrée pour la vérification intelligente"""
    import sys
    sys.argv = ['wazuh-smart', 'smart']
    main()


if __name__ == '__main__':
    main()
