# Architecture

## Table des matières

- [Vue d'ensemble de l'architecture](#vue-densemble-de-larchitecture)
- [Diagramme de composants](#diagramme-de-composants)
- [Diagramme de flux de données](#diagramme-de-flux-de-données)
- [Diagramme de classes](#diagramme-de-classes)
- [Design Patterns utilisés](#design-patterns-utilisés)
- [Architecture des modules](#architecture-des-modules)
- [Architecture du cache](#architecture-du-cache)
- [Architecture du logging](#architecture-du-logging)
- [Architecture SSH](#architecture-ssh)

---

## Vue d'ensemble de l'architecture

Le Wazuh Configurator est construit sur une architecture modulaire utilisant le pattern Strategy pour séparer les logiques de configuration et faciliter l'ajout de nouveaux configurators.

```
┌─────────────────────────────────────────────────────────────┐
│                    Wazuh Configurator                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Security   │  │ Performance  │  │  Monitoring   │    │
│  │ Configurator │  │ Configurator │  │ Configurator │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                  │                  │              │
│         └──────────────────┼──────────────────┘              │
│                            │                                 │
│                    ┌───────▼────────┐                       │
│                    │  BaseConfigurator│                     │
│                    │   (Abstract)    │                       │
│                    └───────┬────────┘                       │
│                            │                                 │
│                    ┌───────▼────────┐                       │
│                    │ ConfigManager  │                       │
│                    │   (Singleton)   │                       │
│                    └───────┬────────┘                       │
│                            │                                 │
│  ┌──────────────┐  ┌──────▼───────┐  ┌──────────────┐    │
│  │   Logger     │  │    Cache     │  │ FileHandler  │    │
│  │   (Utils)    │  │   (Utils)    │  │   (Utils)    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Diagramme de composants

### Structure des composants

```
wazuh_configurator/
│
├── core/                              # Core components
│   ├── base_configurator.py            # Base class for all configurators
│   ├── config_manager.py               # Configuration manager (Singleton)
│   └── wazuh_detector.py               # Wazuh installation detector
│
├── strategies/                         # Strategy pattern implementations
│   ├── security_configurator.py        # Security configuration
│   ├── performance_configurator.py     # Performance configuration
│   ├── monitoring_configurator.py      # Monitoring configuration
│   ├── security_modules_configurator.py # Security modules configuration
│   └── dashboard_configurator.py       # Dashboard configuration
│
├── utils/                             # Utility components
│   ├── logger.py                       # Structured logging
│   ├── cache.py                        # Cache with TTL
│   ├── file_handler.py                 # File operations
│   ├── ssh_client.py                   # SSH client for remote operations
│   └── exceptions.py                   # Custom exceptions
│
└── config/                            # Configuration
    └── paths.py                       # Centralized paths
```

### Flux de données

```
User Input
    │
    ▼
┌──────────────┐
│ CLI Parser   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ConfigManager │◄──────────────┐
│  (Singleton) │                │
└──────┬───────┘                │
       │                        │
       ▼                        │
┌──────────────┐                │
│  Strategy    │                │
│  Selection   │                │
└──────┬───────┘                │
       │                        │
       ▼                        │
┌──────────────┐                │
│ Specific     │                │
│ Configurator │                │
└──────┬───────┘                │
       │                        │
       ▼                        │
┌──────────────┐                │
│   Check/     │                │
│   Apply/     │                │
│   Validate/  │                │
│   Rollback   │                │
└──────┬───────┘                │
       │                        │
       ├────────────────────────┘
       │
       ▼
┌──────────────┐
│   Utils      │
│  (Logger,    │
│   Cache,     │
│   File,      │
│   SSH)       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Wazuh Files │
└──────────────┘
```

---

## Diagramme de flux de données

### Flux de configuration

```
┌──────────┐
│   User   │
└────┬─────┘
     │
     │ "python3 wazuh_configurator.py --module security --action apply"
     ▼
┌──────────────┐
│ CLI Parser   │
└──────┬───────┘
     │
     │ args: module="security", action="apply"
     ▼
┌──────────────┐
│ConfigManager │
│  get_instance│
└──────┬───────┘
     │
     │ Get SecurityConfigurator
     ▼
┌──────────────┐
│ Security     │
│ Configurator  │
│  .apply()    │
└──────┬───────┘
     │
     │ 1. Check current state
     ▼
┌──────────────┐
│  Check SSL   │
│  Check Ports │
│  Check FW    │
└──────┬───────┘
     │
     │ 2. Backup current config
     ▼
┌──────────────┐
│FileHandler   │
│ .backup_file()│
└──────┬───────┘
     │
     │ 3. Apply new config
     ▼
┌──────────────┐
│FileHandler   │
│ .write_file()│
└──────┬───────┘
     │
     │ 4. Validate new config
     ▼
┌──────────────┐
│  Validate    │
│  SSL, Ports, │
│  FW, PWD     │
└──────┬───────┘
     │
     │ 5. Return result
     ▼
┌──────────────┐
│ ConfigResult │
│  (success,   │
│   message,   │
│   details)   │
└──────┬───────┘
     │
     │ Log result
     ▼
┌──────────────┐
│   Logger     │
│  .info()     │
└──────┬───────┘
     │
     ▼
┌──────────┐
│   User   │
└──────────┘
```

### Flux avec cache

```
┌──────────────┐
│   Request    │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ @cached()    │
│  Decorator   │
└──────┬───────┘
       │
       │ Check cache
       ▼
┌──────────────┐
│   Cache      │
│  (TTL: 300s) │
└──────┬───────┘
       │
       ├─ Hit? ──Yes──▶ Return cached result
       │
       │ No
       ▼
┌──────────────┐
│  Execute     │
│  Function    │
└──────┬───────┘
       │
       │ Store in cache
       ▼
┌──────────────┐
│   Cache      │
│  (TTL: 300s) │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Return      │
│  Result      │
└──────────────┘
```

### Flux SSH distant

```
┌──────────────┐
│   Local      │
│   Machine    │
└──────┬───────┘
       │
       │ "python3 wazuh_configurator.py --remote-host 192.168.1.100"
       ▼
┌──────────────┐
│ConfigManager │
│ set_remote   │
└──────┬───────┘
       │
       │ SSH credentials
       ▼
┌──────────────┐
│  SSHClient   │
│  .connect()  │
└──────┬───────┘
       │
       │ SSH connection established
       ▼
┌──────────────┐
│  Remote      │
│  Machine     │
│  (192.168.1.100)│
└──────┬───────┘
       │
       │ Execute command
       ▼
┌──────────────┐
│ SSHClient    │
│ .execute_cmd()│
└──────┬───────┘
       │
       │ Command output
       ▼
┌──────────────┐
│  Local      │
│   Machine    │
└──────┬───────┘
       │
       │ Process result
       ▼
┌──────────────┐
│  Return     │
│  Result     │
└──────────────┘
```

---

## Diagramme de classes

### Classes principales

```
┌─────────────────────────────────────────────────────────────┐
│                     BaseConfigurator                         │
│                    (Abstract Class)                          │
├─────────────────────────────────────────────────────────────┤
│ - _wazuh_path: str                                          │
│ - _logger: WazuhLogger                                      │
│ - file_handler: FileHandler                                │
├─────────────────────────────────────────────────────────────┤
│ + __init__(wazuh_path: str)                                 │
│ + check() -> ConfigResult                    (abstract)     │
│ + apply() -> ConfigResult                    (abstract)     │
│ + validate() -> ConfigResult                  (abstract)     │
│ + rollback() -> ConfigResult                  (abstract)     │
│ + backup_config(file_path: str) -> bool                      │
│ + restore_config(file_path: str) -> bool                     │
└─────────────────────────────────────────────────────────────┘
                            △
                            │ implements
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────┴────────┐  ┌──────┴────────┐  ┌──────┴────────┐
│Security        │  │Performance    │  │Monitoring     │
│Configurator    │  │Configurator   │  │Configurator   │
└────────────────┘  └───────────────┘  └───────────────┘
        │
        │
┌───────┴────────┐
│SecurityModules │
│Configurator    │
└────────────────┘
        │
        │
┌───────┴────────┐
│Dashboard       │
│Configurator    │
└────────────────┘
```

### Classes utilitaires

```
┌─────────────────────────────────────────────────────────────┐
│                      ConfigManager                           │
│                      (Singleton)                              │
├─────────────────────────────────────────────────────────────┤
│ - _instance: ConfigManager                                   │
│ - _configurators: Dict[str, BaseConfigurator]               │
│ - _remote_config: RemoteConfig                              │
├─────────────────────────────────────────────────────────────┤
│ + get_instance() -> ConfigManager                           │
│ + register_configurator(name: str, configurator: ...)       │
│ + get_configurator(name: str) -> BaseConfigurator           │
│ + configure_all() -> Dict[str, ConfigResult]                │
│ + set_remote_config(...)                                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       WazuhLogger                             │
├─────────────────────────────────────────────────────────────┤
│ - _logger: logging.Logger                                   │
│ - _json_format: bool                                        │
├─────────────────────────────────────────────────────────────┤
│ + __init__(name: str, log_file: str, json_format: bool)     │
│ + info(message: str)                                        │
│ + warning(message: str)                                      │
│ + error(message: str)                                        │
│ + debug(message: str)                                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                        Cache                                  │
├─────────────────────────────────────────────────────────────┤
│ - _cache: Dict[str, Tuple[any, float]]                     │
│ - _lock: threading.Lock                                      │
├─────────────────────────────────────────────────────────────┤
│ + @cached(ttl: int)                                          │
│ + _get(key: str) -> Optional[any]                           │
│ + _set(key: str, value: any, ttl: int)                      │
│ + _clear()                                                   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      FileHandler                             │
├─────────────────────────────────────────────────────────────┤
│ + read_file(file_path: str) -> Optional[str]                │
│ + write_file(file_path: str, content: str) -> bool           │
│ + backup_file(file_path: str) -> bool                        │
│ + restore_file(file_path: str) -> bool                      │
│ + create_directory(path: str) -> bool                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                       SSHClient                              │
├─────────────────────────────────────────────────────────────┤
│ - _credentials: SSHCredentials                               │
│ - _client: paramiko.SSHClient                               │
├─────────────────────────────────────────────────────────────┤
│ + __init__(credentials: SSHCredentials)                     │
│ + connect() -> bool                                         │
│ + disconnect() -> bool                                      │
│ + execute_command(command: str) -> Tuple[str, str, int]    │
│ + upload_file(local_path: str, remote_path: str) -> bool    │
│ + download_file(remote_path: str, local_path: str) -> bool  │
└─────────────────────────────────────────────────────────────┘
```

---

## Design Patterns utilisés

### 1. Pattern Strategy

Le pattern Strategy permet de séparer les logiques de configuration et de faciliter l'ajout de nouveaux configurators.

**Avantages:**
- Facile d'ajouter de nouveaux configurators
- Chaque configurator est indépendant
- Code modulaire et maintenable

**Exemple:**
```python
# BaseConfigurator définit l'interface
class BaseConfigurator(ABC):
    @abstractmethod
    def check(self) -> ConfigResult:
        pass
    
    @abstractmethod
    def apply(self) -> ConfigResult:
        pass

# Chaque configurator implémente sa propre stratégie
class SecurityConfigurator(BaseConfigurator):
    def check(self) -> ConfigResult:
        # Implémentation spécifique
        pass
    
    def apply(self) -> ConfigResult:
        # Implémentation spécifique
        pass
```

### 2. Pattern Singleton

Le pattern Singleton assure qu'il n'y a qu'une seule instance du ConfigManager.

**Avantages:**
- Point d'accès global
- Partage d'état entre configurators
- Économie de ressources

**Exemple:**
```python
class ConfigManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
```

### 3. Pattern Template Method

Le pattern Template Method définit le squelette d'un algorithme dans la classe de base, laissant les sous-classes implémenter les étapes spécifiques.

**Avantages:**
- Réutilisation du code
- Structure commune
- Flexibilité des implémentations

**Exemple:**
```python
class BaseConfigurator:
    def apply(self) -> ConfigResult:
        # Étape commune
        self.backup_config()
        
        # Étape spécifique (implémentée par sous-classe)
        self._apply_specific_config()
        
        # Étape commune
        self.validate()
```

### 4. Pattern Decorator

Le pattern Decorator est utilisé pour le cache avec le décorateur `@cached`.

**Avantages:**
- Ajout de fonctionnalités sans modifier le code
- Séparation des préoccupations
- Réutilisation du code

**Exemple:**
```python
@cached(ttl=300)
def check_configuration():
    # Cette fonction est automatiquement mise en cache
    return expensive_operation()
```

---

## Architecture des modules

### Module Security

```
SecurityConfigurator
│
├── check()
│   ├── _check_ssl_config()
│   ├── _check_ports()
│   ├── _check_firewall()
│   └── _check_passwords()
│
├── apply()
│   ├── _apply_ssl_config()
│   ├── _apply_ports_config()
│   ├── _apply_firewall_config()
│   └── _apply_passwords_config()
│
├── validate()
│   ├── _validate_ssl_config()
│   ├── _validate_ports_config()
│   ├── _validate_firewall_config()
│   └── _validate_passwords_config()
│
└── rollback()
    └── restore from backup
```

### Module Performance

```
PerformanceConfigurator
│
├── check()
│   ├── _check_cache_config()
│   ├── _check_database_config()
│   ├── _check_threads_config()
│   └── _check_logging_config()
│
├── apply()
│   ├── _apply_cache_config()
│   ├── _apply_database_config()
│   ├── _apply_threads_config()
│   └── _apply_logging_config()
│
├── validate()
│   └── _validate_all_configs()
│
└── rollback()
    └── restore from backup
```

### Module Monitoring

```
MonitoringConfigurator
│
├── check()
│   ├── _check_service_monitoring()
│   ├── _check_log_level()
│   ├── _check_alerts_enabled()
│   └── _check_health_checks()
│
├── apply()
│   ├── _apply_monitoring_config()
│   └── _apply_alerts_config()
│
├── validate()
│   └── _validate_monitoring_config()
│
└── rollback()
    └── restore from backup
```

### Module Security Modules

```
SecurityModulesConfigurator
│
├── check()
│   ├── _check_vulnerability_detector()
│   ├── _check_cis_benchmarks()
│   ├── _check_fim()
│   └── _check_mitre_attack()
│
├── apply()
│   ├── _apply_vulnerability_detector()
│   ├── _apply_cis_benchmarks()
│   ├── _apply_fim()
│   └── _apply_mitre_attack()
│
├── validate()
│   ├── _validate_vulnerability_detector()
│   ├── _validate_cis_benchmarks()
│   ├── _validate_fim()
│   └── _validate_mitre_attack()
│
└── rollback()
    └── restore from backup
```

### Module Dashboard

```
DashboardConfigurator
│
├── check()
│   ├── _check_dashboard_connection()
│   ├── _check_visualizations()
│   └── _check_dashboards()
│
├── apply()
│   ├── _create_index_pattern()
│   ├── _create_visualizations()
│   └── _create_dashboard()
│
├── validate()
│   ├── _validate_index_pattern()
│   ├── _validate_visualizations()
│   └── _validate_dashboard()
│
└── rollback()
    ├── _delete_index_pattern()
    ├── _delete_visualizations()
    └── _delete_dashboard()
```

---

## Architecture du cache

### Implémentation du cache

```
┌─────────────────────────────────────────────────────────────┐
│                        Cache                                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _cache: Dict[str, Tuple[any, float]]              │    │
│  │                                                      │    │
│  │  {                                                   │    │
│  │    "func_name(arg1, arg2)": (result, expiry_time), │    │
│  │    "func_name(arg3, arg4)": (result, expiry_time), │    │
│  │    ...                                               │    │
│  │  }                                                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _lock: threading.Lock                               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Flux du cache

```
┌──────────────┐
│ Function     │
│ Call         │
└──────┬───────┘
       │
       │ @cached(ttl=300)
       ▼
┌──────────────┐
│ Generate Key │
│ (func_name,  │
│  args, kwargs)│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Check Cache  │
│ for Key      │
└──────┬───────┘
       │
       ├─ Hit? ──Yes──▶ Return cached result
       │
       │ No
       ▼
┌──────────────┐
│ Execute      │
│ Function     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Store in     │
│ Cache        │
│ (result,     │
│  expiry_time)│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Return       │
│ Result       │
└──────────────┘
```

### Thread-safety

Le cache utilise un `threading.Lock` pour assurer la thread-safety:

```python
@cached(ttl=300)
def check_configuration():
    # Le lock assure que seul un thread peut exécuter
    # cette fonction à la fois si elle n'est pas en cache
    return expensive_operation()
```

---

## Architecture du logging

### Implémentation du logger

```
┌─────────────────────────────────────────────────────────────┐
│                      WazuhLogger                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _logger: logging.Logger                             │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _json_format: bool                                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _log_file: str                                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Flux du logging

```
┌──────────────┐
│ Log Call     │
│ logger.info()│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Format Log   │
│ (JSON/Text)  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Add Metadata │
│ (timestamp,  │
│  level, etc.)│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Write to     │
│ File/Console │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Log Saved    │
└──────────────┘
```

### Format JSON

Le logger supporte le format JSON pour l'intégration avec des systèmes de log:

```json
{
  "timestamp": "2024-04-16T12:00:00Z",
  "level": "INFO",
  "logger": "SecurityConfigurator",
  "message": "Configuration appliquée avec succès",
  "details": {
    "ssl_enabled": true,
    "ports_open": [1514, 1515, 55000]
  }
}
```

---

## Architecture SSH

### Implémentation SSH

```
┌─────────────────────────────────────────────────────────────┐
│                       SSHClient                              │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _credentials: SSHCredentials                         │    │
│  │  - host: str                                          │    │
│  │  - username: str                                      │    │
│  │  - key_path: Optional[str]                            │    │
│  │  - password: Optional[str]                            │    │
│  │  - port: int                                          │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  _client: paramiko.SSHClient                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Flux SSH

```
┌──────────────┐
│ SSHClient    │
│ .connect()   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Load         │
│ Credentials  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Create SSH   │
│ Connection   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Authenticate │
│ (Key/Password)│
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Connection   │
│ Established  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Execute      │
│ Command      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Return       │
│ Output       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Disconnect   │
└──────────────┘
```

### Sécurité SSH

- **Support de clés SSH privées** (recommandé)
- **Support de mots de passe** (optionnel)
- **Port SSH personnalisable**
- **Timeout de connexion**
- **Gestion des erreurs** avec exceptions personnalisées

---

## Séparation des préoccupations

L'architecture du Wazuh Configurator suit le principe de séparation des préoccupations:

- **Core**: Logique de base et abstractions
- **Strategies**: Implémentations spécifiques
- **Utils**: Fonctionnalités réutilisables
- **Config**: Configuration centralisée

Cette séparation permet:
- Maintenance facile
- Testabilité
- Extensibilité
- Réutilisation du code

---

## Scalabilité

L'architecture est conçue pour être scalable:

1. **Ajout de nouveaux configurators**: Simple héritage de BaseConfigurator
2. **Cache distribué**: Peut être étendu avec Redis
3. **Multi-machine**: Support SSH natif
4. **Parallélisation**: Peut être ajoutée facilement
5. **Monitoring**: Logger structuré pour intégration

---

## Performance

L'architecture optimise les performances:

1. **Cache**: Réduit les opérations répétées
2. **Thread-safety**: Support multi-threading
3. **Lazy loading**: Chargement à la demande
4. **Timeouts**: Évite les blocages
5. **Optimisations SSH**: Pool de connexions réutilisables

---

## Sécurité

L'architecture intègre la sécurité:

1. **Exceptions personnalisées**: Gestion d'erreurs robuste
2. **SSH sécurisé**: Support de clés privées
3. **Validation**: Validation des configurations
4. **Rollback**: Restauration en cas d'erreur
5. **Audit trail**: Logger structuré pour traçabilité

---

## Support

Pour plus d'informations sur l'architecture:
- API Documentation: [API Documentation](../api/README.md)
- Usage Guide: [Usage Guide](../usage/README.md)
- Templates: [Configuration Templates](../templates/README.md)
