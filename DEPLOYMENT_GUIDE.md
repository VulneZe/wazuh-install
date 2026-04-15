# 📚 Wazuh DevSec Generator - Guide de Déploiement Complet

## 🎯 Vue d'Ensemble

Ce guide couvre le déploiement complet du générateur de configuration Wazuh DevSec, depuis l'installation jusqu'à la mise en production, avec un support particulier pour les environnements macOS et les simulations.

## 🏗️ Architecture de Déploiement

### Composants Principaux

```
wazuh-devsec-config-generator/
├── wazuh_devsec_config_generator/    # Core package
│   ├── core/                         # Architecture centrale
│   ├── tui/                          # Interface terminal
│   └── generator_v2.py              # Générateur principal
├── scripts/                          # Scripts de validation
│   ├── validate_config.py           # Validation configuration
│   ├── test_logs.py                 # Test des logs
│   └── deploy_simulation.py         # Simulation déploiement
├── output/                           # Configuration générée
└── docs/                            # Documentation
```

### Modes de Fonctionnement

1. **Mode Production** : Déploiement réel sur serveur Wazuh
2. **Mode Simulation** : Tests complets sans Wazuh installé
3. **Mode Validation** : Vérification de la configuration
4. **Mode TUI** : Interface graphique interactive

## 🚀 Installation

### Prérequis

```bash
# Python 3.9+
python3 --version

# Dépendances système (macOS)
brew install libxml2 libxslt
```

### Installation du Package

```bash
# Cloner le repository
git clone <repository-url>
cd wazuh-devsec-config-generator

# Créer environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer le package
pip install -e .

# Vérifier l'installation
wazuh-tui --help
```

## 🎮 Utilisation

### Interface Graphique (Recommandé)

```bash
# Lancer l'interface TUI
wazuh-tui

# Menu principal disponible :
# 1. Gérer les profils
# 2. Générer configuration  
# 3. Gérer intégrations
# 4. Voir configurations
# 5. Déployer configuration
# 6. Dashboard d'état
```

### Ligne de Commande

```bash
# Scanner les services installés
wazuh-tui --scan

# Générer configuration pour un profil
wazuh-tui --profile dev

# Voir l'état du système
wazuh-tui --status

# Simulation complète (macOS compatible)
wazuh-tui --simulate dev

# Validation de configuration
wazuh-tui --validate

# Test des logs
wazuh-tui --test-logs

# Simulation déploiement
wazuh-tui --deploy-sim
```

### Scripts Individuels

```bash
# Validation de configuration
python scripts/validate_config.py output/wazuh-custom-devsec

# Test des logs
python scripts/test_logs.py output/wazuh-custom-devsec

# Simulation déploiement
python scripts/deploy_simulation.py output/wazuh-custom-devsec
```

## 🎭 Mode Simulation (macOS Compatible)

Le mode simulation permet de tester complètement le projet sans installation Wazuh.

### Exécution Complète

```bash
# Lancer la simulation complète pour le profil "dev"
wazuh-tui --simulate dev
```

Cette commande exécute :
1. ✅ Génération de configuration
2. ✅ Détection des services locaux
3. ✅ Validation de tous les composants
4. ✅ Test des logs avec règles générées
5. ✅ Simulation de déploiement
6. ✅ Génération de rapports détaillés

### Résultats de Simulation

```
output/wazuh-custom-devsec/simulation/
├── metadata.json                    # Infos simulation
├── logs/                           # Logs simulés
├── configs/                        # Configs validées
├── validation/                     # Rapports validation
├── full_simulation_report.json     # Rapport complet
└── deployment_simulation.json      # Simulation déploiement
```

## 🔍 Validation de Configuration

### Validation Automatique

```bash
# Valider toute la configuration
wazuh-tui --validate

# Ou via script direct
python scripts/validate_config.py output/wazuh-custom-devsec
```

### Composants Validés

1. **Règles XML** : Structure et syntaxe
2. **Décodeurs XML** : Format et éléments requis
3. **Listes CDB** : Format et compilation
4. **Active Response** : Scripts et commandes
5. **Configuration** : Fragments ossec.conf
6. **Dashboards** : Structure JSON

### Rapports de Validation

```json
{
  "timestamp": "2026-03-19T12:00:00",
  "summary": {
    "total": 6,
    "passed": 6,
    "failed": 0,
    "warnings": 0
  },
  "validations": {
    "rules": {
      "status": "passed",
      "data": {
        "files_found": 8,
        "files_valid": 8,
        "rules_count": 42
      }
    }
  }
}
```

## 🧪 Test des Logs

### Test avec Logs Échantillons

```bash
# Tester tous les logs échantillons
wazuh-tui --test-logs

# Test manuel
python scripts/test_logs.py output/wazuh-custom-devsec --logs-dir output/wazuh-custom-devsec/tests/sample-logs
```

### Logs Testés

- `git-suspicious.txt` → Règle 101001
- `vscode-curl.txt` → Règle 102001
- `docker-privileged.txt` → Règle 104001
- `ransomware-encrypt.txt` → Règle 105001
- + 16 autres logs

### Résultats de Test

```
🧪 Log Testing Summary:
┌──────────────┬─────────┬─────────────┬────────┐
│ Log File     │ Expected│ Matched     │ Status │
├──────────────┼─────────┼─────────────┼────────┤
│ git-suspicious│ 101001  │ 101001      │ ✅ PASS│
│ vscode-curl  │ 102001  │ 102001      │ ✅ PASS│
│ docker-priv  │ 104001  │ 104001      │ ✅ PASS│
└──────────────┴─────────┴─────────────┴────────┘

📊 Pass Rate: 95.0%
```

## 🚀 Déploiement en Production

### Prérequis Wazuh

```bash
# Installation Wazuh Manager (Ubuntu/Debian)
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt-get update
apt-get install wazuh-manager

# Installation Wazuh Agent
apt-get install wazuh-agent
```

### Déploiement Automatisé

```bash
# Option 1: Via TUI
wazuh-tui
# → Menu 5 (Déployer configuration)

# Option 2: Via script original
python deploy.py

# Option 3: Manuel
sudo rsync -av --chown=ossec:ossec output/wazuh-custom-devsec/etc/ /var/ossec/etc/
sudo /var/ossec/bin/ossec-makelists
sudo systemctl restart wazuh-manager
```

### Validation Post-Déploiement

```bash
# Vérifier que Wazuh utilise les nouvelles règles
sudo /var/ossec/bin/wazuh-logtest < output/wazuh-custom-devsec/tests/sample-logs/git-suspicious.txt

# Vérifier l'état des services
sudo systemctl status wazuh-manager
sudo /var/ossec/bin/wazuh-control status

# Consulter les logs
sudo tail -f /var/ossec/logs/ossec.log
```

### Importation des Dashboards

```bash
# Script généré automatiquement
./output/wazuh-custom-devsec/import_dashboards.sh

# Import manuel dans Kibana
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
     -H "kbn-xsrf: true" \
     --form file=@"output/wazuh-custom-devsec/dashboards/Development_overview.json" \
     --form overwrite=true
```

## 📊 Configuration des Profils

### Profils Intégrés

#### 1. Development
- **Règles** : Git, IDE, CI/CD, Docker
- **Intégrations** : VirusTotal
- **Utile pour** : Environnements de développement

#### 2. Production  
- **Règles** : Ransomware, Insider, Web, Database
- **Intégrations** : Suricata, Elasticsearch
- **Utile pour** : Environnements de production

#### 3. Testing
- **Règles** : Toutes les catégories
- **Intégrations** : Toutes disponibles
- **Utile pour** : Tests complets

### Création de Profil Personnalisé

```bash
# Via TUI
wazuh-tui
# → Menu 1 (Gérer profils) → Créer profil

# Configuration manuelle
python -c "
from wazuh_devsec_config_generator.core.config import WazuhProfile, ProfileType, IntegrationType

custom_profile = WazuhProfile(
    name='enterprise-devsec',
    type=ProfileType.CUSTOM,
    description='Profil personnalisé entreprise',
    rules_enabled=['git', 'docker', 'web', 'database'],
    integrations=[IntegrationType.VIRUSTOTAL, IntegrationType.ELASTICSEARCH]
)

from wazuh_devsec_config_generator.core.config import ConfigManager
config_manager = ConfigManager()
config_manager.add_profile(custom_profile)
print('Profil créé avec succès!')
"
```

## 🔧 Configuration des Intégrations

### VirusTotal

```bash
# Configuration API
export VIRUSTOTAL_API_KEY="your_api_key_here"

# Test de l'intégration
python -c "
from wazuh_devsec_config_generator.core.integrations import VirusTotalIntegration
vt = VirusTotalIntegration(Path('output'))
status = vt.check_installation()
print(f'Status: {status}')
"
```

### Suricata

```bash
# Installation Suricata
apt-get install suricata

# Configuration
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.backup
# Éditer la configuration selon vos besoins

# Test
suricata --version
```

### Elasticsearch

```bash
# Installation Elasticsearch
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
apt-get update && apt-get install elasticsearch

# Configuration
# /etc/elasticsearch/elasticsearch.yml
```

## 🐛 Dépannage

### Problèmes Communs

#### 1. Erreur d'Installation
```bash
# Problème : Module non trouvé
Solution : Vérifier l'environnement virtuel
source venv/bin/activate
pip install -e .
```

#### 2. Permissions Wazuh
```bash
# Problème : Permission denied
Solution : Corriger les permissions
sudo chown -R ossec:ossec /var/ossec/
sudo chmod 750 /var/ossec/etc/
```

#### 3. XML Malformé
```bash
# Problème : Erreur de syntaxe XML
Solution : Valider avec xmllint
xmllint --noout output/wazuh-custom-devsec/etc/rules/*.xml
```

#### 4. Logs Non Traités
```bash
# Problème : Les logs ne génèrent pas d'alertes
Solution : Vérifier avec wazuh-logtest
sudo /var/ossec/bin/wazuh-logtest -f /var/log/auth.log
```

### Mode Debug

```bash
# Activer le mode debug
export WAZUH_DEBUG=1
wazuh-tui --profile dev

# Logs détaillés
tail -f /var/ossec/logs/ossec.log | grep DEBUG
```

### Validation Complète

```bash
# Exécuter toutes les validations
wazuh-tui --simulate dev
wazuh-tui --validate
wazuh-tui --test-logs
wazuh-tui --deploy-sim
```

## 📈 Monitoring et Maintenance

### Monitoring Wazuh

```bash
# État des services
sudo systemctl status wazuh-manager wazuh-agent

# Performance
sudo /var/ossec/bin/wazuh-control info

# Logs d'erreurs
sudo grep -i error /var/ossec/logs/ossec.log
```

### Mise à Jour des Configurations

```bash
# Régénérer avec nouveau profil
wazuh-tui --profile production

# Déployer
python deploy.py

# Redémarrer
sudo systemctl restart wazuh-manager
```

### Backup des Configurations

```bash
# Backup automatique
sudo cp -r /var/ossec/etc/ /var/ossec/etc.backup.$(date +%Y%m%d)

# Backup des dashboards
curl -X GET "http://localhost:5601/api/saved_objects/_export" \
     -H "kbn-xsrf: true" \
     > dashboards_backup.json
```

## 🎯 Check-list de Déploiement

### Avant Déploiement

- [ ] Python 3.9+ installé
- [ ] Environnement virtuel créé
- [ ] Package Wazuh Generator installé
- [ ] Services détectés et analysés
- [ ] Profil configuré
- [ ] Configuration générée

### Validation

- [ ] Configuration validée (`wazuh-tui --validate`)
- [ ] Logs testés (`wazuh-tui --test-logs`)
- [ ] Simulation déploiement (`wazuh-tui --deploy-sim`)
- [ ] Aucune erreur critique

### Déploiement Production

- [ ] Wazuh Manager installé
- [ ] Backup configuration existante
- [ ] Configuration déployée
- [ ] Services redémarrés
- [ ] Dashboards importés
- [ ] Tests post-déploiement validés

### Post-Déploiement

- [ ] Monitoring activé
- [ ] Alerts configurées
- [ ] Documentation mise à jour
- [ ] Équipe formée
- [ ] Plan de maintenance établi

## 📞 Support

### Ressources

- **Documentation** : `/docs/`
- **Exemples** : `/examples/`
- **Tests** : `/tests/`
- **Scripts** : `/scripts/`

### Aide

```bash
# Aide intégrée
wazuh-tui --help

# Documentation des commandes
man wazuh-tui

# Exemples d'utilisation
wazuh-tui --sample
```

---

**Ce guide couvre l'ensemble du processus de déploiement, de l'installation à la production, avec un support particulier pour les environnements de développement comme macOS.**
