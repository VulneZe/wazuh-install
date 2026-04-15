# Wazuh Smart Installer

Installateur intelligent de Wazuh avec **résolution automatique des problèmes** d'installation.

## Fonctionnalités Intelligentes

### Détection Automatique des Problèmes
- **Vérification mémoire**: Minimum 4GB recommandé
- **Espace disque**: Minimum 20GB disponible
- **Conflits de ports**: Détecte les ports déjà utilisés
- **Installation Java**: Vérifie et installe Java si nécessaire
- **Configuration pare-feu**: Configure automatiquement les ports Wazuh
- **Connectivité réseau**: Vérifie l'accès internet et DNS
- **Permissions**: Vérifie les droits sudo

### Résolution Automatique
- **Installation Java**: Installe automatiquement OpenJDK si manquant
- **Configuration pare-feu**: Ouvre automatiquement les ports Wazuh
- **Diagnostic**: Identifie et signale les problèmes non résolubles
- **Solutions**: Propose des solutions pour chaque problème détecté

### Monitoring en Temps Réel
- **Surveillance**: Monitore l'installation en temps réel
- **Détection d'erreurs**: Détecte et signale les erreurs pendant l'installation
- **Validation post-installation**: Vérifie que tous les services sont actifs
- **Vérification des ports**: Confirme que tous les ports sont ouverts

### Installation
- **All-in-One**: Indexer, Server, Dashboard sur la même machine
- **Vérification préalable**: Analyse l'environnement avant installation
- **Mode auto-fix**: Résout automatiquement les problèmes détectés

## Installation

### Prérequis

- Linux (Ubuntu, Debian, RHEL, CentOS, Fedora)
- Accès root (sudo)
- Connexion internet

### Installation de l'outil

```bash
# Cloner le dépôt
git clone https://github.com/VulneZe/wazuh-install.git
cd wazuh-install

# Rendre le script exécutable
chmod +x wazuh_smart_installer.py

# Aucune dépendance externe requise !
# Le script utilise uniquement la bibliothèque standard Python
# Les dépendances manquantes (curl, wget, etc.) sont installées automatiquement
```

## Utilisation

### Vérification de l'Environnement

```bash
# Vérifier l'environnement sans installer
python3 wazuh_smart_installer.py check
```

### Installation avec Résolution Automatique (Recommandé)

```bash
# Vérifier + résoudre automatiquement les problèmes + installer
python3 wazuh_smart_installer.py install --auto-fix

# Ou avec sudo
sudo python3 wazuh_smart_installer.py install --auto-fix
```

### Installation Standard

```bash
# Installer avec vérification mais sans résolution automatique
python3 wazuh_smart_installer.py install

# Sauter la vérification (non recommandé)
python3 wazuh_smart_installer.py install --skip-check
```

### Gestion des Services

```bash
# Vérifier le statut des services
python3 wazuh_smart_installer.py status
```

### Désinstallation

```bash
# Désinstaller Wazuh
python3 wazuh_smart_installer.py uninstall
```

## Wazuh Configurator

Outil avancé de configuration avec **design patterns** pour optimiser les installations Wazuh existantes.

### Fonctionnalités

**Sécurité:**
- Configuration SSL/TLS
- Génération automatique de mots de passe forts
- Configuration de l'authentification API
- Optimisation des règles pare-feu

**Performance:**
- Optimisation de la mémoire JVM selon le système
- Configuration automatique de la rotation des logs
- Programmation du nettoyage disque
- Optimisation du pool de connexions

**Monitoring:**
- Surveillance automatique des services
- Optimisation du niveau de logs
- Activation des alertes
- Configuration des health checks

**Modules de Sécurité Avancés:**
- Vulnerability Detector: Configuration automatique du détecteur de vulnérabilités avec intégration CVE/NVD
- CIS Benchmarks: Configuration des benchmarks CIS et rapports de conformité automatiques
- File Integrity Monitoring (FIM): Configuration des répertoires critiques et règles d'alerte personnalisées
- MITRE ATT&CK: Mapping des attaques et configuration des règles MITRE

**Dashboard:**
- Configuration automatique des dashboards Wazuh via API OpenSearch Dashboards
- Création de visualisations personnalisées (SSH, AD, alertes par niveau)
- Dashboard SOC avec visualisations intégrées
- Validation et rollback des configurations de dashboard

### Prérequis

- Wazuh **déjà installé** sur le système
- Accès root (sudo)
- Python 3.6+

### Utilisation

```bash
# Rendre le script exécutable
chmod +x wazuh_configurator.py
```

#### Détection de l'Installation

```bash
# Détecter l'installation Wazuh existante
python3 wazuh_configurator.py detect
```

#### Vérification des Configurations

```bash
# Vérifier toutes les configurations
python3 wazuh_configurator.py check

# Vérifier une configuration spécifique
python3 wazuh_configurator.py check --config security
python3 wazuh_configurator.py check --config performance
python3 wazuh_configurator.py check --config monitoring
python3 wazuh_configurator.py check --config security-modules
python3 wazuh_configurator.py check --config dashboard
```

#### Application des Configurations

```bash
# Appliquer toutes les configurations
python3 wazuh_configurator.py apply

# Appliquer une configuration spécifique
python3 wazuh_configurator.py apply --config security
python3 wazuh_configurator.py apply --config security-modules
python3 wazuh_configurator.py apply --config dashboard
```

#### Mode Fix (Recommandé pour Wazuh Existant)

```bash
# Vérifier + Corriger + Valider automatiquement
python3 wazuh_configurator.py fix

# Corriger une configuration spécifique
python3 wazuh_configurator.py fix --config security
python3 wazuh_configurator.py fix --config security-modules
python3 wazuh_configurator.py fix --config dashboard
```

#### Validation et Rollback

```bash
# Valider les configurations appliquées
python3 wazuh_configurator.py validate

# Valider une configuration spécifique
python3 wazuh_configurator.py validate --config security-modules
python3 wazuh_configurator.py validate --config dashboard

# Rollback des configurations
python3 wazuh_configurator.py rollback

# Rollback une configuration spécifique
python3 wazuh_configurator.py rollback --config security-modules
python3 wazuh_configurator.py rollback --config dashboard
```

### Architecture Technique

**Design Patterns:**
- **Strategy Pattern**: Configuration strategies (sécurité, performance, monitoring)
- **Singleton Pattern**: ConfigManager thread-safe
- **Factory Pattern**: Enregistrement dynamique des configurateurs

**Qualité Code:**
- Gestion d'erreurs robuste avec exceptions spécifiques
- Vérification des permissions avant opérations
- Timeout sur tous les subprocess (10s)
- Typage complet avec Optional
- Validation des entrées
- Logging structuré

### Workflow Recommandé

```bash
# Pour Wazuh déjà installé:
python3 wazuh_configurator.py detect
python3 wazuh_configurator.py fix
```

L'outil détecte automatiquement Wazuh, vérifie les configurations, applique les corrections et valide les changements.

## Architecture

### All-in-One (Single Machine)

```
┌─────────────────────────────────┐
│  Machine Unique                 │
│  ├─ Wazuh Indexer               │
│  ├─ Wazuh Server                │
│  └─ Wazuh Dashboard            │
└─────────────────────────────────┘
```

### Distribuée (Multiple Machines)

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Machine 1    │  │ Machine 2    │  │ Machine 3    │
│ Wazuh Indexer│  │ Wazuh Server │  │ Wazuh Dash   │
└──────────────┘  └──────────────┘  └──────────────┘
```

## Accès Web

Après installation all-in-one:

- **URL**: `https://<IP_ADDRESS>`
- **Utilisateur**: `admin`
- **Mot de passe**: Voir `wazuh-passwords.txt`

## Documentation Officielle

- [Documentation Wazuh](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Quickstart](https://documentation.wazuh.com/current/quickstart.html)
- [Installation Guide](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)

## Notes

- L'outil utilise le script officiel d'installation Wazuh
- Compatible avec Wazuh 4.14
- Nécessite des droits root pour l'installation
- Le script d'installation Wazuh est téléchargé automatiquement
- Les dépendances manquantes (curl, wget, etc.) sont installées automatiquement
- Le configurateur détecte et optimise les installations Wazuh existantes
- Le code suit les bonnes pratiques Python avec design patterns

## License

MIT License
