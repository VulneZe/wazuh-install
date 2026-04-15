# Installation Simple et Propre

## Installation Rapide

### Option 1: Installation depuis GitHub (recommandée)

```bash
# Cloner le dépôt
git clone https://github.com/VulneZe/wazuh-install.git
cd wazuh-install

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate

# Installer en mode développement
pip install -e .
```

### Option 2: Installation directe

```bash
# Installation directe depuis le dépôt
pip install git+https://github.com/VulneZe/wazuh-install.git
```

## Utilisation en Ligne de Commande

Une fois installé, vous avez accès à plusieurs commandes :

### Génération de Configuration

```bash
# Générer avec le profil par défaut
wazuh-generator generate

# Générer avec un profil spécifique
wazuh-generator generate --profile production

# Mode simulation
wazuh-generator generate --profile development --simulate

# Spécifier le répertoire de sortie
wazuh-generator generate --profile production --output /opt/wazuh-config
```

### Vérification de Configuration

```bash
# Vérifier la configuration générée
wazuh-generator verify

# Vérifier un répertoire spécifique
wazuh-generator verify --output /path/to/config
```

### Analyse de Règles

```bash
# Analyser la qualité des règles
wazuh-generator analyze

# Mode verbeux pour plus de détails
wazuh-generator analyze --verbose
```

### Vérification Intelligente

```bash
# Analyse complète de l'environnement
wazuh-generator smart

# Mode verbeux
wazuh-generator smart --verbose
```

### Déploiement

```bash
# Simuler le déploiement
wazuh-generator deploy --profile production

# Déploiement avec répertoire personnalisé
wazuh-generator deploy --profile development --output /tmp/wazuh-test
```

### Gestion des Profils

```bash
# Lister les profils disponibles
wazuh-generator list-profiles
```

### Test de Règles

```bash
# Tester une règle spécifique
wazuh-generator test-rule --profile development --rule 100001 --log /var/log/auth.log
```

## Options Globales

Toutes les commandes supportent ces options :

```bash
--verbose, -v    # Mode verbeux
--config, -c     # Fichier de configuration personnalisé
--help, -h       # Aide
--version         # Version
```

## Exemples d'Utilisation

### Scénario 1: Développement Rapide

```bash
# 1. Générer la configuration de développement
wazuh-generator generate --profile development --simulate

# 2. Vérifier la configuration
wazuh-generator verify

# 3. Analyser la qualité
wazuh-generator analyze --verbose
```

### Scénario 2: Production

```bash
# 1. Analyse de l'environnement
wazuh-generator smart

# 2. Générer la configuration de production
wazuh-generator generate --profile production --output /opt/wazuh-config

# 3. Simuler le déploiement
wazuh-generator deploy --profile production --output /opt/wazuh-config
```

### Scénario 3: Test et Validation

```bash
# 1. Générer avec le profil de test
wazuh-generator generate --profile testing

# 2. Tester une règle spécifique
wazuh-generator test-rule --profile testing --rule 100001 --log test.log

# 3. Vérifier la configuration
wazuh-generator verify --verbose
```

## Structure des Fichiers Générés

```
output/
├── etc/
│   ├── rules/                  # Règles de sécurité
│   ├── decoders/               # Décodeurs de logs
│   ├── lists/cdb/              # Listes CDB
│   └── ossec.conf             # Configuration principale
├── dashboards/                # Dashboards Kibana
├── scripts/                   # Scripts Active Response
└── tests/                     # Fichiers de test
```

## Dépannage

### Erreurs Communes

**ModuleNotFoundError: No module named 'wazuh_devsec_config_generator'**
```bash
# Réinstaller en mode développement
pip install -e .
```

**Permission denied lors de l'installation**
```bash
# Utiliser l'environnement virtuel
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Configuration non trouvée**
```bash
# Vérifier le répertoire de sortie
wazuh-generator list-profiles
wazuh-generator generate --profile development
```

### Mode Debug

Pour activer le mode debug :
```bash
wazuh-generator --verbose generate --profile development
```

### Logs

Les logs sont générés dans :
- `logs/wazuh-generator.log` (si le répertoire logs existe)
- Console en mode verbeux

---

**Installation simple et utilisation en ligne de commande !**
