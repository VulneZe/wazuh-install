# Wazuh DevSec Generator v2.0 - Architecture Améliorée

## 🚀 Nouveautés de la v2.0

### Architecture Professionnelle
- **Design Patterns**: Factory, Strategy, Observer pour une architecture modulaire et extensible
- **Système de profils**: Gestion avancée des configurations par profils (dev, production, testing, custom)
- **Plugin System**: Intégrations extensible via plugins (VirusTotal, Suricata, Elasticsearch, TheHive, MISP)

### Interface Graphique Terminal (TUI)
- **Navigation intuitive**: Interface Rich-based pour naviguer dans les configurations
- **Gestion visuelle**: Tableaux, panneaux, et menus interactifs
- **Dashboard temps réel**: État du système et des intégrations

### Détection Automatique de Services
- **Scan intelligent**: Détection automatique des services installés (Apache, Nginx, MySQL, Docker, Jenkins, etc.)
- **Recommandations**: Suggestions d'intégrations basées sur les services détectés
- **Configuration adaptative**: Ajustement automatique des règles selon l'environnement

### Templates Dashboard Wazuh
- **Dashboards prêts à l'emploi**: Templates JSON pour Kibana/Grafana
- **Intégrations spécifiques**: Dashboards dédiés pour VirusTotal, Suricata, Elasticsearch
- **Scripts d'import**: Automatisation de l'import dans Kibana

## 📦 Installation

```bash
# Cloner le projet
git clone <repository>
cd wazuh-devsec-config-generator

# Installation avec environnement virtuel
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## 🎯 Utilisation

### Interface Graphique Terminal (Recommandé)

```bash
# Lancer l'interface TUI
wazuh-tui

# Ou avec l'ancien générateur
wazuh-generator
```

### Détection de Services

```bash
# Scanner les services installés
wazuh-scan

# Voir l'état du système
wazuh-tui --status
```

### Génération par Profil

```bash
# Générer avec détection automatique
wazuh-tui --profile dev

# Scanner seulement
wazuh-tui --scan

# Créer un exemple
wazuh-tui --sample
```

## 🏗️ Architecture Technique

### Structure des Packages

```
wazuh_devsec_config_generator/
├── core/                    # Architecture centrale
│   ├── config.py           # Gestion des profils et configurations
│   ├── factory.py          # Pattern Factory pour générateurs
│   ├── rules.py            # Strategy Pattern pour règles
│   ├── decoders.py         # Strategy Pattern pour décodeurs
│   ├── integrations.py     # Plugin system pour intégrations
│   ├── service_detector.py # Détection automatique de services
│   └── dashboard_generator.py # Templates dashboard
├── tui/                     # Interface Terminal
│   └── app.py              # Application TUI principale
├── templates/              # Templates Jinja2
├── generator.py            # Générateur original (v1)
└── generator_v2.py         # Générateur amélioré (v2)
```

### Design Patterns Implémentés

#### 1. Factory Pattern
```python
# Création de générateurs modulaires
factory = GeneratorFactory()
rule_generator = factory.create("rules")
decoder_generator = factory.create("decoders")
```

#### 2. Strategy Pattern
```python
# Stratégies de règles interchangeables
class GitRuleStrategy(RuleStrategy):
    def generate_rules(self, theme):
        # Implémentation spécifique Git
```

#### 3. Plugin System
```python
# Intégrations extensibles
class VirusTotalIntegration(BaseIntegration):
    def check_installation(self):
        # Détection automatique
```

## 🔗 Intégrations Supportées

### Sécurité
- **VirusTotal**: Analyse de fichiers et détection de malware
- **Suricata**: IDS/IPS pour détection d'intrusion
- **TheHive**: Plateforme de réponse à incident
- **MISP**: Threat intelligence sharing

### Infrastructure
- **Elasticsearch**: Stockage et analyse des logs
- **Kibana**: Visualisation et dashboards
- **Docker/Kubernetes**: Sécurité des conteneurs

### Développement
- **Git/GitLab**: Surveillance des repositories
- **Jenkins**: Sécurité des pipelines CI/CD
- **IDE Tools**: VSCode, IntelliJ monitoring

## 📊 Dashboards Générés

### Types de Dashboards

1. **Overview Dashboard**: Vue d'ensemble de la sécurité
2. **Integration Dashboards**: Spécifiques à chaque intégration
3. **Rule Dashboards**: Par thématique (Git, Docker, etc.)
4. **MITRE ATT&CK**: Cartographie des techniques

### Importation dans Kibana

```bash
# Script généré automatiquement
./output/wazuh-custom-devsec/import_dashboards.sh

# Import manuel
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
     -H "kbn-xsrf: true" \
     --form file="@dashboard.json"
```

## 🔍 Détection de Services

### Services Détectés

#### Web Servers
- Apache HTTP Server
- Nginx  
- Microsoft IIS

#### Bases de Données
- MySQL/MariaDB
- PostgreSQL
- MongoDB
- Redis

#### CI/CD
- Jenkins
- GitLab
- GitHub Actions

#### Conteneurs
- Docker
- Kubernetes
- Podman

#### Sécurité
- Suricata
- Wazuh Manager
- Elasticsearch
- Kibana

### Configuration Automatique

```python
# Exemple de détection
detector = ServiceDetector()
services = detector.scan_all_services()
recommendations = detector.get_recommended_integrations()
```

## 📝 Profils de Configuration

### Profils Intégrés

1. **Development**: Environnement de développement
   - Règles: git, ide, cicd, docker
   - Intégrations: VirusTotal

2. **Production**: Environnement de production
   - Règles: ransomware, insider, web, database, docker
   - Intégrations: Suricata, Elasticsearch

3. **Testing**: Test complet
   - Toutes les règles et intégrations activées

### Personnalisation

```python
# Création de profil personnalisé
custom_profile = WazuhProfile(
    name="custom-devsec",
    type=ProfileType.CUSTOM,
    description="Profil personnalisé pour notre entreprise",
    rules_enabled=["git", "docker", "web"],
    integrations=[IntegrationType.VIRUSTOTAL, IntegrationType.ELASTICSEARCH]
)
```

## 🚀 Déploiement

### Déploiement Automatisé

```bash
# Via l'interface TUI
wazuh-tui -> Option 5 (Déployer)

# Via script
python deploy.py

# Manuel
sudo rsync -av --chown=ossec:ossec output/wazuh-custom-devsec/etc/ /var/ossec/etc/
sudo /var/ossec/bin/ossec-makelists
sudo systemctl restart wazuh-manager
```

### Validation

```bash
# Test des règles générées
/var/ossec/bin/wazuh-logtest < tests/sample-logs/git-suspicious.txt

# Vérification des dashboards
curl http://localhost:5601/api/saved_objects/_find?type=dashboard
```

## 🔄 Migration v1 → v2

### Compatibilité
- Le générateur v1 reste disponible via `wazuh-generator`
- Les configurations existantes sont compatibles
- Migration progressive recommandée

### Étapes de Migration

1. **Installer la v2**: `pip install -e .`
2. **Lancer la TUI**: `wazuh-tui`
3. **Scanner les services**: Option 3 → "Tester les intégrations"
4. **Créer un profil**: Option 1 → "Créer un profil"
5. **Générer**: Option 2 → "Générer une configuration"

## 🧪 Tests et Validation

### Tests Unitaires
```bash
# Tests des composants core
python -m pytest tests/core/

# Tests de l'interface TUI
python -m pytest tests/tui/
```

### Tests d'Intégration
```bash
# Test de détection de services
wazuh-scan

# Test de génération complète
wazuh-tui --sample
```

## 📈 Roadmap Future

### v2.1
- Support de Grafana dashboards
- Intégration avec Ansible/Terraform
- Mode cluster multi-manager

### v2.2
- Interface web (FastAPI + React)
- Machine learning pour détection d'anomalies
- Support de cloud (AWS, Azure, GCP)

### v3.0
- Architecture microservices
- API REST complète
- Plugin marketplace

## 🤝 Contribuer

### Architecture Modulaire
Le système est conçu pour être facilement extensible:

1. **Nouvelles Règles**: Implémenter `RuleStrategy`
2. **Nouvelles Intégrations**: Hériter de `BaseIntegration`
3. **Nouveaux Dashboards**: Étendre `DashboardGenerator`

### Exemple d'Extension

```python
# Ajouter une nouvelle stratégie de règles
class KubernetesRuleStrategy(RuleStrategy):
    def generate_rules(self, theme):
        return [
            RuleDefinition(
                rule_id=300001,
                level=12,
                title="Kubernetes RBAC violation",
                description="Violation des politiques RBAC Kubernetes",
                mitre="T1548.003",
                regex=r"kubernetes.*rbac.*denied",
                group="kubernetes,devsec"
            )
        ]

# Enregistrer la stratégie
generator.register_strategy("kubernetes", KubernetesRuleStrategy())
```

---

**Wazuh DevSec Generator v2.0** - L'outil professionnel pour une sécurité DevSec moderne et intelligente.
