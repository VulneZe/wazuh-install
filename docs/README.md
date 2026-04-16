# Wazuh Configurator Documentation

## Table des matières

- [API Documentation](./api/README.md)
- [Guide d'utilisation](./usage/README.md)
- [Templates de configuration](./templates/README.md)
- [Architecture](./architecture/README.md)

## Vue d'ensemble

Le Wazuh Configurator est un outil avancé de configuration avec **design patterns** pour optimiser les installations Wazuh existantes. Il utilise le pattern Strategy pour séparer les logiques de configuration et faciliter l'ajout de nouveaux configurators.

## Structure du projet

```
wazuh_configurator/
├── core/
│   ├── base_configurator.py       # Base abstraite pour tous les configurators
│   ├── config_manager.py          # Gestionnaire de configuration (Singleton)
│   └── wazuh_detector.py          # Détection d'installation Wazuh
├── strategies/
│   ├── security_configurator.py    # Configuration de sécurité (SSL, ports, firewall)
│   ├── performance_configurator.py # Optimisation des performances
│   ├── monitoring_configurator.py # Configuration du monitoring
│   ├── security_modules_configurator.py # Modules de sécurité (Vuln Detector, CIS, FIM, MITRE)
│   └── dashboard_configurator.py  # Configuration des dashboards
├── utils/
│   ├── logger.py                  # Logger structuré avec JSON
│   ├── cache.py                   # Cache avec TTL et thread-safety
│   ├── file_handler.py            # Gestionnaire de fichiers
│   ├── ssh_client.py              # Client SSH pour machines distantes
│   └── exceptions.py              # Exceptions personnalisées
└── config/
    └── paths.py                   # Chemins centralisés
```

## Fonctionnalités principales

- **Configuration centralisée**: Tous les chemins sont centralisés dans `config/paths.py`
- **Multi-machine**: Support SSH pour configuration de machines distantes
- **Cache**: Cache avec TTL pour optimiser les opérations répétées
- **Logger structuré**: Logging JSON avec niveaux de sévérité
- **Exceptions personnalisées**: Gestion d'erreurs robuste
- **Pattern Strategy**: Architecture flexible et extensible
- **Validation**: Validation des configurations avant application
- **Rollback**: Restauration automatique en cas d'erreur

## Quick Start

```bash
# Installer les dépendances
pip install -r requirements.txt

# Exécuter le configurator
python3 wazuh_configurator.py --help

# Configuration de sécurité
python3 wazuh_configurator.py --module security --action check
python3 wazuh_configurator.py --module security --action apply

# Configuration avec SSH (machine distante)
python3 wazuh_configurator.py --remote-host 192.168.1.100 --ssh-user admin --ssh-key ~/.ssh/id_rsa --module security --action check
```

## Modules disponibles

1. **Security**: Configuration SSL, ports, firewall, mots de passe
2. **Performance**: Optimisation des performances Wazuh
3. **Monitoring**: Configuration des alertes et health checks
4. **Security Modules**: Vulnerability Detector, CIS Benchmarks, FIM, MITRE ATT&CK
5. **Dashboard**: Configuration des dashboards OpenSearch

## Contributeurs

- VulneZe (github.com/VulneZe)

## Licence

Voir le fichier LICENSE pour plus d'informations.
