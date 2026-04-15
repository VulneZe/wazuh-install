# Wazuh DevSec Generator v2.0

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

Générateur professionnel de configuration Wazuh pour environnement DevSec avec interface terminal améliorée et vérification intelligente.

## Fonctionnalités

- **Architecture propre et modulaire** avec design patterns
- **Interface terminal professionnelle** avec Rich
- **Vérification intelligente** de l'environnement
- **Génération de configuration** Wazuh personnalisée
- **Analyse de qualité des règles** avec détection de faux positifs
- **Templates de dashboards** prêts à l'emploi
- **Mode simulation** complet
- **Tests automatisés** et validation

## Installation

### Prérequis

- Python 3.9+
- Git

### Installation rapide

```bash
# Cloner le dépôt
git clone https://github.com/VOTRE_USERNAME/wazuh-devsec-config-generator.git
cd wazuh-devsec-config-generator

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Installer l'outil en mode développement
pip install -e .
```

### Installation sur Windows

```powershell
# Cloner le dépôt
git clone https://github.com/VOTRE_USERNAME/wazuh-devsec-config-generator.git
cd wazuh-devsec-config-generator

# Créer l'environnement virtuel
python -m venv venv
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt

# Installer l'outil
pip install -e .
```

## Utilisation

### Interface Terminal Améliorée

```bash
# Lancer l'interface principale
wazuh-tui

# Lancer l'interface intelligente
wazuh-smart-ui

# Options spécifiques
wazuh-tui --simulate dev
wazuh-tui --validate
wazuh-tui --test-logs
```

### Vérification Intelligente

```bash
# Analyse complète de l'environnement
wazuh-smart-ui
# Choisir "1. Vérification Intelligente"
```

### Génération de Configuration

```bash
# Générer pour un profil spécifique
wazuh-tui --profile development

# Mode simulation
wazuh-tui --simulate production
```

## Structure du Projet

```
wazuh-devsec-config-generator/
```

## Développement

### Tests

```bash
# Exécuter tous les tests
python test_suite.py

# Tests spécifiques
python test_suite.py --quality
python test_suite.py --performance
python test_suite.py --integration
```

### Code Style

```bash
# Formatter le code
black wazuh_devsec_config_generator/

# Vérifier le style
flake8 wazuh_devsec_config_generator/
```

## Configuration

### Profils

Les profils de configuration sont stockés dans `config/profiles.json`:

- **development**: Environnement de développement
- **production**: Environnement de production
- **testing**: Environnement de test
- **custom**: Profil personnalisé

### Intégrations

Configurez les intégrations dans les settings:

```python
# VirusTotal API key
settings.integrations.virustotal_api_key = "votre_api_key"

# Elasticsearch URL
settings.integrations.elasticsearch_url = "http://localhost:9200"
```

## Fonctionnalités Avancées

### Analyse de Règles

- Détection automatique des faux positifs
- Score de qualité 0-100
- Recommandations d'amélioration
- 30 règles optimisées incluses

### Templates de Dashboards

- Security Overview
- DevSec Monitoring
- Threat Intelligence
- Compliance Reporting
- Incident Response
- Performance Monitoring

### Mode Simulation

Test complet sans installation Wazuh:
- Simulation de déploiement
- Validation de configuration
- Test des logs
- Rapports détaillés

## Support

### Documentation

- [Documentation complète](docs/)
- [Guide d'installation](DEPLOYMENT_GUIDE.md)
- [Architecture](ARCHITECTURE.md)

### Issues

Pour signaler un problème ou demander une fonctionnalité:
1. Vérifiez les [issues existantes](https://github.com/VOTRE_USERNAME/wazuh-devsec-config-generator/issues)
2. Créez une nouvelle issue avec:
   - Description détaillée
   - Steps to reproduce
   - Environnement (OS, Python version)
   - Logs si applicable

## Contribuer

Les contributions sont les bienvenues !

1. Fork le projet
2. Créer une branche (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Commit vos changements (`git commit -am 'Ajout nouvelle fonctionnalité'`)
4. Push vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Créez une Pull Request

### Guidelines de Contribution

- Suivez le style de code existant
- Ajoutez des tests pour les nouvelles fonctionnalités
- Mettez à jour la documentation
- Respectez la [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Ce projet est sous [License MIT](LICENSE).

## Crédits

- Wazuh Project - https://wazuh.com
- Rich Library - https://rich.readthedocs.io
- Pydantic - https://pydantic-docs.helpmanual.io

## Changelog

### v2.0.0
- Architecture complète refaite
- Interface terminal améliorée
- Vérification intelligente
- Mode simulation
- Tests automatisés

### v1.0.0
- Version initiale
- Génération de configuration de base

---

**Développé avec passion pour la sécurité DevSec** !
