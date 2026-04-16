# API Documentation

## Table des matières

- [Core](#core)
  - [BaseConfigurator](#baseconfigurator)
  - [ConfigManager](#configmanager)
  - [WazuhDetector](#wazuhdetector)
- [Strategies](#strategies)
  - [SecurityConfigurator](#securityconfigurator)
  - [PerformanceConfigurator](#performanceconfigurator)
  - [MonitoringConfigurator](#monitoringconfigurator)
  - [SecurityModulesConfigurator](#securitymodulesconfigurator)
  - [DashboardConfigurator](#dashboardconfigurator)
- [Utils](#utils)
  - [WazuhLogger](#wazuhlogger)
  - [Cache](#cache)
  - [FileHandler](#filehandler)
  - [SSHClient](#sshclient)
  - [Exceptions](#exceptions)

---

## Core

### BaseConfigurator

Classe abstraite de base pour tous les configurators. Implémente les méthodes communes et le pattern Template Method.

#### Méthodes

##### `__init__(wazuh_path: str = "/var/ossec")`
Initialise le configurator avec le chemin d'installation Wazuh.

**Paramètres:**
- `wazuh_path` (str): Chemin d'installation Wazuh (défaut: "/var/ossec")

**Exemple:**
```python
configurator = BaseConfigurator(wazuh_path="/var/ossec")
```

##### `check() -> ConfigResult`
Méthode abstraite à implémenter par les sous-classes. Vérifie l'état actuel de la configuration.

**Retourne:** `ConfigResult` - Résultat de la vérification

##### `apply() -> ConfigResult`
Méthode abstraite à implémenter par les sous-classes. Applique la configuration.

**Retourne:** `ConfigResult` - Résultat de l'application

##### `validate() -> ConfigResult`
Méthode abstraite à implémenter par les sous-classes. Valide la configuration.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Méthode abstraite à implémenter par les sous-classes. Annule les changements.

**Retourne:** `ConfigResult` - Résultat du rollback

##### `backup_config(file_path: str) -> bool`
Crée une sauvegarde d'un fichier de configuration avant modification.

**Paramètres:**
- `file_path` (str): Chemin du fichier à sauvegarder

**Retourne:** `bool` - True si la sauvegarde a réussi

**Exemple:**
```python
success = configurator.backup_config("/var/ossec/etc/ossec.conf")
```

##### `restore_config(file_path: str) -> bool`
Restaure un fichier de configuration depuis sa sauvegarde.

**Paramètres:**
- `file_path` (str): Chemin du fichier à restaurer

**Retourne:** `bool` - True si la restauration a réussi

---

### ConfigManager

Gestionnaire de configuration utilisant le pattern Singleton. Gère l'accès centralisé aux configurators.

#### Méthodes

##### `get_instance() -> ConfigManager`
Retourne l'instance unique du ConfigManager (Singleton).

**Retourne:** `ConfigManager` - Instance unique

**Exemple:**
```python
manager = ConfigManager.get_instance()
```

##### `register_configurator(name: str, configurator: BaseConfigurator)`
Enregistre un configurator avec un nom.

**Paramètres:**
- `name` (str): Nom du configurator
- `configurator` (BaseConfigurator): Instance du configurator

**Exemple:**
```python
manager.register_configurator("security", SecurityConfigurator())
```

##### `get_configurator(name: str) -> BaseConfigurator`
Récupère un configurator par son nom.

**Paramètres:**
- `name` (str): Nom du configurator

**Retourne:** `BaseConfigurator` - Instance du configurator ou None

##### `configure_all() -> Dict[str, ConfigResult]`
Applique la configuration à tous les configurators enregistrés.

**Retourne:** `Dict[str, ConfigResult]` - Dictionnaire des résultats par configurator

##### `set_remote_config(remote_host: str, ssh_user: str, ssh_key: Optional[str], ssh_password: Optional[str], ssh_port: int)`
Configure les paramètres pour les opérations distantes via SSH.

**Paramètres:**
- `remote_host` (str): Adresse de la machine distante
- `ssh_user` (str): Utilisateur SSH
- `ssh_key` (Optional[str]): Chemin de la clé SSH privée
- `ssh_password` (Optional[str]): Mot de passe SSH
- `ssh_port` (int): Port SSH (défaut: 22)

---

### WazuhDetector

Détecte automatiquement l'installation Wazuh et les composants installés.

#### Méthodes

##### `__init__()`
Initialise le détecteur Wazuh.

##### `detect_installation() -> WazuhInstallation`
Détecte si Wazuh est installé et rassemble les informations.

**Retourne:** `WazuhInstallation` - Objet contenant les informations de l'installation

**Exemple:**
```python
detector = WazuhDetector()
installation = detector.detect_installation()
print(f"Wazuh installé: {installation.is_installed}")
print(f"Version: {installation.version}")
print(f"Composants: {installation.components}")
```

---

## Strategies

### SecurityConfigurator

Configuration de sécurité Wazuh (SSL, ports, firewall, mots de passe).

#### Méthodes

##### `check() -> ConfigResult`
Vérifie la configuration de sécurité actuelle.

**Retourne:** `ConfigResult` - Résultat de la vérification avec détails sur SSL, ports, firewall

**Exemple:**
```python
configurator = SecurityConfigurator()
result = configurator.check()
print(f"SSL configuré: {result.details.get('ssl_enabled', False)}")
print(f"Ports ouverts: {result.details.get('open_ports', [])}")
```

##### `apply() -> ConfigResult`
Applique la configuration de sécurité recommandée.

**Retourne:** `ConfigResult` - Résultat de l'application

**Détails configurés:**
- SSL/TLS pour les communications
- Ports sécurisés (1514, 1515, 55000)
- Configuration du firewall (UFW)
- Mots de passe par défaut changés

##### `validate() -> ConfigResult`
Valide que la configuration de sécurité est correcte.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Annule les changements de configuration de sécurité.

**Retourne:** `ConfigResult` - Résultat du rollback

---

### PerformanceConfigurator

Optimisation des performances Wazuh.

#### Méthodes

##### `check() -> ConfigResult`
Vérifie la configuration des performances actuelle.

**Retourne:** `ConfigResult` - Résultat de la vérification avec détails sur mémoire, CPU, disque

##### `apply() -> ConfigResult`
Applique les optimisations de performances recommandées.

**Retourne:** `ConfigResult` - Résultat de l'application

**Optimisations:**
- Configuration du cache
- Optimisation de la base de données
- Ajustement des threads
- Configuration de la journalisation

##### `validate() -> ConfigResult`
Valide que la configuration des performances est correcte.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Annule les changements de configuration des performances.

**Retourne:** `ConfigResult` - Résultat du rollback

---

### MonitoringConfigurator

Configuration du monitoring et des alertes.

#### Méthodes

##### `check() -> ConfigResult`
Vérifie la configuration du monitoring actuelle.

**Retourne:** `ConfigResult` - Résultat de la vérification avec détails sur alertes, health checks

##### `apply() -> ConfigResult`
Applique la configuration de monitoring recommandée.

**Retourne:** `ConfigResult` - Résultat de l'application

**Configuration:**
- Alertes activées
- Health checks configurés
- Niveau de log approprié
- Notifications configurées

##### `validate() -> ConfigResult`
Valide que la configuration du monitoring est correcte.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Annule les changements de configuration du monitoring.

**Retourne:** `ConfigResult` - Résultat du rollback

---

### SecurityModulesConfigurator

Configuration des modules de sécurité avancés (Vulnerability Detector, CIS Benchmarks, FIM, MITRE ATT&CK).

#### Méthodes

##### `check() -> ConfigResult`
Vérifie la configuration des modules de sécurité actuelle.

**Retourne:** `ConfigResult` - Résultat de la vérification avec détails sur chaque module

**Modules vérifiés:**
- Vulnerability Detector
- CIS Benchmarks
- File Integrity Monitoring (FIM)
- MITRE ATT&CK

##### `apply() -> ConfigResult`
Applique la configuration des modules de sécurité recommandée.

**Retourne:** `ConfigResult` - Résultat de l'application

**Exemple:**
```python
configurator = SecurityModulesConfigurator()
result = configurator.apply()
print(f"Vuln Detector: {result.details.get('vulnerability_detector', False)}")
print(f"CIS Benchmarks: {result.details.get('cis_benchmarks', False)}")
```

##### `validate() -> ConfigResult`
Valide que la configuration des modules de sécurité est correcte.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Annule les changements de configuration des modules de sécurité.

**Retourne:** `ConfigResult` - Résultat du rollback

---

### DashboardConfigurator

Configuration des dashboards Wazuh via API OpenSearch Dashboards.

#### Méthodes

##### `__init__(wazuh_path: str = "/var/ossec", dashboard_url: str = "https://localhost:5601", dashboard_username: str = "admin", dashboard_password: str = None)`
Initialise le configurator de dashboard.

**Paramètres:**
- `wazuh_path` (str): Chemin d'installation Wazuh
- `dashboard_url` (str): URL du dashboard (défaut: "https://localhost:5601")
- `dashboard_username` (str): Nom d'utilisateur (défaut: "admin")
- `dashboard_password` (str): Mot de passe (défaut: None)

##### `check() -> ConfigResult`
Vérifie la configuration des dashboards actuelle.

**Retourne:** `ConfigResult` - Résultat de la vérification avec détails sur dashboards, visualisations

##### `apply() -> ConfigResult`
Applique la configuration des dashboards recommandée.

**Retourne:** `ConfigResult` - Résultat de l'application

**Configuration:**
- Index pattern wazuh-alerts-*
- Visualisations SOC
- Dashboard SOC

##### `validate() -> ConfigResult`
Valide que la configuration des dashboards est correcte.

**Retourne:** `ConfigResult` - Résultat de la validation

##### `rollback() -> ConfigResult`
Annule les changements de configuration des dashboards.

**Retourne:** `ConfigResult` - Résultat du rollback

---

## Utils

### WazuhLogger

Logger structuré avec support JSON et niveaux de sévérité.

#### Méthodes

##### `__init__(name: str, log_file: str = "wazuh_configurator.log", json_format: bool = False)`
Initialise le logger.

**Paramètres:**
- `name` (str): Nom du logger
- `log_file` (str): Fichier de log (défaut: "wazuh_configurator.log")
- `json_format` (bool): Format JSON pour les logs (défaut: False)

##### `info(message: str)`
Log un message de niveau INFO.

##### `warning(message: str)`
Log un message de niveau WARNING.

##### `error(message: str)`
Log un message de niveau ERROR.

##### `debug(message: str)`
Log un message de niveau DEBUG.

**Exemple:**
```python
logger = WazuhLogger("my_configurator", json_format=True)
logger.info("Configuration appliquée avec succès")
logger.error("Erreur lors de la configuration")
```

---

### Cache

Cache avec TTL et thread-safety utilisant le pattern Decorator.

#### Décorateur

##### `@cached(ttl: int = 300)`
Décorateur pour mettre en cache les résultats des fonctions.

**Paramètres:**
- `ttl` (int): Time-to-live en secondes (défaut: 300)

**Exemple:**
```python
from wazuh_configurator.utils.cache import cached

@cached(ttl=300)
def check_configuration():
    # Cette fonction sera mise en cache pendant 300 secondes
    return expensive_operation()
```

---

### FileHandler

Gestionnaire de fichiers pour opérations sécurisées sur fichiers.

#### Méthodes (Statiques)

##### `read_file(file_path: str) -> Optional[str]`
Lit le contenu d'un fichier de manière sécurisée.

**Paramètres:**
- `file_path` (str): Chemin du fichier

**Retourne:** `Optional[str]` - Contenu du fichier ou None en cas d'erreur

##### `write_file(file_path: str, content: str) -> bool`
Écrit du contenu dans un fichier de manière sécurisée.

**Paramètres:**
- `file_path` (str): Chemin du fichier
- `content` (str): Contenu à écrire

**Retourne:** `bool` - True si l'écriture a réussi

##### `backup_file(file_path: str) -> bool`
Crée une sauvegarde d'un fichier.

**Paramètres:**
- `file_path` (str): Chemin du fichier

**Retourne:** `bool` - True si la sauvegarde a réussi

##### `restore_file(file_path: str) -> bool`
Restaure un fichier depuis sa sauvegarde.

**Paramètres:**
- `file_path` (str): Chemin du fichier

**Retourne:** `bool` - True si la restauration a réussi

##### `create_directory(path: str) -> bool`
Crée un répertoire de manière sécurisée.

**Paramètres:**
- `path` (str): Chemin du répertoire

**Retourne:** `bool` - True si la création a réussi

**Exemple:**
```python
content = FileHandler.read_file("/var/ossec/etc/ossec.conf")
FileHandler.write_file("/var/ossec/etc/ossec.conf", new_content)
FileHandler.backup_file("/var/ossec/etc/ossec.conf")
```

---

### SSHClient

Client SSH pour opérations sur machines distantes utilisant Paramiko.

#### Méthodes

##### `__init__(credentials: SSHCredentials)`
Initialise le client SSH.

**Paramètres:**
- `credentials` (SSHCredentials): Credentials de connexion SSH

##### `connect() -> bool`
Établit la connexion SSH.

**Retourne:** `bool` - True si la connexion a réussi

##### `disconnect() -> bool`
Ferme la connexion SSH.

**Retourne:** `bool` - True si la déconnexion a réussi

##### `execute_command(command: str) -> Tuple[str, str, int]`
Exécute une commande sur la machine distante.

**Paramètres:**
- `command` (str): Commande à exécuter

**Retourne:** `Tuple[str, str, int]` - (stdout, stderr, exit_code)

##### `upload_file(local_path: str, remote_path: str) -> bool`
Télécharge un fichier vers la machine distante.

**Paramètres:**
- `local_path` (str): Chemin local du fichier
- `remote_path` (str): Chemin distant du fichier

**Retourne:** `bool` - True si le téléchargement a réussi

##### `download_file(remote_path: str, local_path: str) -> bool`
Télécharge un fichier depuis la machine distante.

**Paramètres:**
- `remote_path` (str): Chemin distant du fichier
- `local_path` (str): Chemin local du fichier

**Retourne:** `bool` - True si le téléchargement a réussi

**Exemple:**
```python
credentials = SSHCredentials(
    host="192.168.1.100",
    username="admin",
    key_path="/home/user/.ssh/id_rsa"
)
ssh_client = SSHClient(credentials)
ssh_client.connect()
stdout, stderr, exit_code = ssh_client.execute_command("systemctl status wazuh-server")
ssh_client.disconnect()
```

---

### Exceptions

Exceptions personnalisées pour une gestion d'erreurs robuste.

#### Classes d'exceptions

##### `WazuhConfiguratorError`
Exception de base pour toutes les erreurs du configurator.

##### `ConfigurationError`
Erreur liée à la configuration.

##### `FileOperationError`
Erreur liée aux opérations sur fichiers.

##### `SSHConnectionError`
Erreur lors de la connexion SSH.

##### `SSHAuthenticationError`
Erreur lors de l'authentification SSH.

##### `SSHCommandError`
Erreur lors de l'exécution d'une commande SSH.

##### `PermissionError`
Erreur liée aux permissions.

##### `ServiceNotAvailableError`
Erreur lorsqu'un service n'est pas disponible.

##### `InvalidConfigurationError`
Erreur lorsque la configuration est invalide.

##### `CacheError`
Erreur liée au cache.

**Exemple:**
```python
from wazuh_configurator.utils.exceptions import FileOperationError, ConfigurationError

try:
    FileHandler.write_file("/etc/ossec.conf", content)
except FileOperationError as e:
    logger.error(f"Erreur fichier: {e}")
except ConfigurationError as e:
    logger.error(f"Erreur configuration: {e}")
```

---

## Types de données

### ConfigResult

Résultat d'une opération de configuration.

**Attributs:**
- `success` (bool): Indique si l'opération a réussi
- `message` (str): Message descriptif du résultat
- `details` (Dict): Détails supplémentaires sur le résultat
- `warnings` (List[str]): Liste d'avertissements

**Exemple:**
```python
result = ConfigResult(
    success=True,
    message="Configuration appliquée avec succès",
    details={"ssl_enabled": True, "ports_open": [1514, 1515]},
    warnings=["Firewall non configuré"]
)
```

### WazuhInstallation

Informations sur l'installation Wazuh détectée.

**Attributs:**
- `is_installed` (bool): Indique si Wazuh est installé
- `version` (str): Version de Wazuh
- `path` (str): Chemin d'installation
- `components` (List[str]): Liste des composants installés

### SSHCredentials

Credentials de connexion SSH.

**Attributs:**
- `host` (str): Adresse de la machine distante
- `username` (str): Utilisateur SSH
- `key_path` (Optional[str]): Chemin de la clé SSH privée
- `password` (Optional[str]): Mot de passe SSH
- `port` (int): Port SSH (défaut: 22)
