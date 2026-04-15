# Wazuh Smart Installer

Installateur intelligent de Wazuh avec **résolution automatique des problèmes** d'installation.

## 🚀 Fonctionnalités Intelligentes

### ✅ Détection Automatique des Problèmes
- **Vérification mémoire**: Minimum 4GB recommandé
- **Espace disque**: Minimum 20GB disponible
- **Conflits de ports**: Détecte les ports déjà utilisés
- **Installation Java**: Vérifie et installe Java si nécessaire
- **Configuration pare-feu**: Configure automatiquement les ports Wazuh
- **Connectivité réseau**: Vérifie l'accès internet et DNS
- **Permissions**: Vérifie les droits sudo

### 🔧 Résolution Automatique
- **Installation Java**: Installe automatiquement OpenJDK si manquant
- **Configuration pare-feu**: Ouvre automatiquement les ports Wazuh
- **Diagnostic**: Identifie et signale les problèmes non résolubles
- **Solutions**: Propose des solutions pour chaque problème détecté

### 📊 Monitoring en Temps Réel
- **Surveillance**: Monitore l'installation en temps réel
- **Détection d'erreurs**: Détecte et signale les erreurs pendant l'installation
- **Validation post-installation**: Vérifie que tous les services sont actifs
- **Vérification des ports**: Confirme que tous les ports sont ouverts

### 🎯 Installation
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
chmod +x wazuh_installer.py

# Installer les dépendances Python
pip install click
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

## License

MIT License
