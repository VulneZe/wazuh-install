# Wazuh DevSec Generator v2.0

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

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
├── wazuh_devsec_config_generator/    # Package principal
│   ├── core/                        # Modules core
│   ├── tui/                         # Interface terminal
│   ├── ui/                          # Interface améliorée
│   └── templates/                    # Templates Jinja2
├── config/                          # Configuration
├── scripts/                         # Scripts utilitaires
├── tests/                           # Tests
├── requirements.txt                  # Dépendances
└── README.md                        # Documentation
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

## Configuration

### Profils

- **development**: Environnement de développement
- **production**: Environnement de production
- **testing**: Environnement de test
- **custom**: Profil personnalisé

### Intégrations

Configurez les intégrations dans les settings:
- VirusTotal API key
- Elasticsearch URL
- Autres services externes

## License

Ce projet est sous [License MIT](LICENSE).

---

**Développé avec passion pour la sécurité DevSec** !
