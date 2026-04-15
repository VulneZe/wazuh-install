# Wazuh Installer

Installateur simple et automatisé de Wazuh basé sur la documentation officielle.

## Fonctionnalités

- **Installation All-in-One**: Indexer, Server, Dashboard sur la même machine
- **Installation Distribuée**: Composants sur différentes machines
- **Installation par Composant**: Installer uniquement ce dont vous avez besoin
- **Gestion des Services**: Vérifier le statut des services Wazuh
- **Désinstallation**: Supprimer proprement Wazuh

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

### Installation All-in-One (Recommandé)

```bash
# Installer tous les composants sur la même machine
python3 wazuh_installer.py install --type all-in-one

# Ou avec sudo
sudo python3 wazuh_installer.py install --type all-in-one
```

### Installation par Composant

```bash
# Installer uniquement l'indexer
python3 wazuh_installer.py install --type indexer

# Installer uniquement le server
python3 wazuh_installer.py install --type server

# Installer uniquement le dashboard
python3 wazuh_installer.py install --type dashboard
```

### Gestion des Services

```bash
# Vérifier le statut des services
python3 wazuh_installer.py status

# Afficher les identifiants d'accès
python3 wazuh_installer.py credentials
```

### Désinstallation

```bash
# Désinstaller Wazuh
python3 wazuh_installer.py uninstall
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
