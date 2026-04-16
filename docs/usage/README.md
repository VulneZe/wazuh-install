# Guide d'utilisation

## Table des matières

- [Installation](#installation)
- [Configuration de base](#configuration-de-base)
- [Guide Security Configurator](#guide-security-configurator)
- [Guide Performance Configurator](#guide-performance-configurator)
- [Guide Monitoring Configurator](#guide-monitoring-configurator)
- [Guide Security Modules Configurator](#guide-security-modules-configurator)
- [Guide Dashboard Configurator](#guide-dashboard-configurator)
- [Configuration distante via SSH](#configuration-distante-via-ssh)
- [Dépannage](#dépannage)

---

## Installation

### Prérequis

- Python 3.8+
- Accès root ou sudo
- Wazuh installé (optionnel pour vérification uniquement)

### Installation des dépendances

```bash
# Créer un environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### Vérification de l'installation

```bash
python3 wazuh_configurator.py --help
```

---

## Configuration de base

### Premier lancement

```bash
# Lancer le configurator sans argument pour voir l'aide
python3 wazuh_configurator.py --help
```

### Options principales

- `--module`: Module à configurer (security, performance, monitoring, security_modules, dashboard)
- `--action`: Action à effectuer (check, apply, validate, rollback)
- `--wazuh-path`: Chemin d'installation Wazuh (défaut: /var/ossec)
- `--remote-host`: Adresse de la machine distante (optionnel)
- `--ssh-user`: Utilisateur SSH (optionnel)
- `--ssh-key`: Chemin de la clé SSH (optionnel)
- `--ssh-password`: Mot de passe SSH (optionnel)
- `--ssh-port`: Port SSH (défaut: 22)
- `--log-level`: Niveau de log (INFO, WARNING, ERROR, DEBUG)
- `--json-format`: Format JSON pour les logs

---

## Guide Security Configurator

Le Security Configurator configure la sécurité Wazuh: SSL, ports, firewall, mots de passe.

### Vérifier la configuration actuelle

```bash
python3 wazuh_configurator.py --module security --action check
```

**Sortie attendue:**
```
[*] Vérification de la configuration de sécurité...
[*] Vérification SSL/TLS...
[+] SSL/TLS: Configuré
[*] Vérification des ports...
[+] Port 1514: Ouvert
[+] Port 1515: Ouvert
[+] Port 55000: Ouvert
[*] Vérification du firewall...
[+] Firewall: Configuré (UFW)
[*] Vérification des mots de passe...
[+] Mots de passe par défaut: Modifiés

[+] Configuration de sécurité: OK
```

### Appliquer la configuration de sécurité

```bash
python3 wazuh_configurator.py --module security --action apply
```

**Ce que cela fait:**
- Configure SSL/TLS pour les communications sécurisées
- Configure les ports Wazuh (1514, 1515, 55000)
- Configure le firewall (UFW) avec les règles appropriées
- Modifie les mots de passe par défaut

### Valider la configuration

```bash
python3 wazuh_configurator.py --module security --action validate
```

### Annuler les changements (Rollback)

```bash
python3 wazuh_configurator.py --module security --action rollback
```

**Note:** Le rollback restaure les fichiers de configuration depuis les sauvegardes automatiques.

### Configuration personnalisée

Vous pouvez spécifier des ports personnalisés:

```bash
python3 wazuh_configurator.py --module security --action apply --custom-ports 1514:1515:55000
```

---

## Guide Performance Configurator

Le Performance Configurator optimise les performances Wazuh: cache, base de données, threads.

### Vérifier la configuration actuelle

```bash
python3 wazuh_configurator.py --module performance --action check
```

**Sortie attendue:**
```
[*] Vérification de la configuration des performances...
[*] Vérification du cache...
[+] Cache: Configuré
[*] Vérification de la base de données...
[+] Base de données: Optimisée
[*] Vérification des threads...
[+] Threads: Optimisés
[*] Vérification de la journalisation...
[+] Journalisation: Configurée

[+] Configuration des performances: OK
```

### Appliquer les optimisations de performance

```bash
python3 wazuh_configurator.py --module performance --action apply
```

**Ce que cela fait:**
- Configure le cache avec des paramètres optimaux
- Optimise la configuration de la base de données
- Ajuste le nombre de threads pour votre système
- Configure la journalisation pour minimiser l'impact sur les performances

### Valider la configuration

```bash
python3 wazuh_configurator.py --module performance --action validate
```

### Annuler les changements (Rollback)

```bash
python3 wazuh_configurator.py --module performance --action rollback
```

---

## Guide Monitoring Configurator

Le Monitoring Configurator configure le monitoring et les alertes Wazuh.

### Vérifier la configuration actuelle

```bash
python3 wazuh_configurator.py --module monitoring --action check
```

**Sortie attendue:**
```
[*] Vérification de la configuration du monitoring...
[*] Vérification du service de monitoring...
[+] Service monitoring: Actif
[*] Vérification du niveau de log...
[+] Niveau de log: INFO
[*] Vérification des alertes...
[+] Alertes: Activées
[*] Vérification des health checks...
[+] Health checks: Configurés

[+] Configuration du monitoring: OK
```

### Appliquer la configuration de monitoring

```bash
python3 wazuh_configurator.py --module monitoring --action apply
```

**Ce que cela fait:**
- Active les alertes pour les événements de sécurité
- Configure les health checks pour surveiller l'état du système
- Configure le niveau de log approprié
- Configure les notifications

### Valider la configuration

```bash
python3 wazuh_configurator.py --module monitoring --action validate
```

### Annuler les changements (Rollback)

```bash
python3 wazuh_configurator.py --module monitoring --action rollback
```

---

## Guide Security Modules Configurator

Le Security Modules Configurator configure les modules de sécurité avancés: Vulnerability Detector, CIS Benchmarks, FIM, MITRE ATT&CK.

### Vérifier la configuration actuelle

```bash
python3 wazuh_configurator.py --module security_modules --action check
```

**Sortie attendue:**
```
[*] Vérification de la configuration des modules de sécurité...
============================================================
[*] Vérification Vulnerability Detector...
[+] Vulnerability Detector: Activé
[*] Vérification CIS Benchmarks...
[+] CIS Benchmarks: Activé
[*] Vérification File Integrity Monitoring (FIM)...
[+] FIM: Activé
[*] Vérification MITRE ATT&CK...
[+] MITRE ATT&CK: Activé
============================================================

[+] Configuration des modules de sécurité: OK
```

### Appliquer la configuration des modules de sécurité

```bash
python3 wazuh_configurator.py --module security_modules --action apply
```

**Ce que cela fait:**
- Configure le Vulnerability Detector pour détecter les CVE
- Configure les CIS Benchmarks pour la conformité
- Configure le FIM pour surveiller l'intégrité des fichiers
- Configure MITRE ATT&CK pour la détection de menaces avancées

### Valider la configuration

```bash
python3 wazuh_configurator.py --module security_modules --action validate
```

### Annuler les changements (Rollback)

```bash
python3 wazuh_configurator.py --module security_modules --action rollback
```

### Configuration par module

Vous pouvez configurer des modules spécifiques en modifiant le fichier de configuration:

```bash
# Éditer wazuh_configurator/config/modules_config.yaml
python3 wazuh_configurator.py --module security_modules --action apply
```

---

## Guide Dashboard Configurator

Le Dashboard Configurator configure les dashboards Wazuh via API OpenSearch Dashboards.

### Vérifier la configuration actuelle

```bash
python3 wazuh_configurator.py --module dashboard --action check
```

**Sortie attendue:**
```
[*] Vérification de la configuration des dashboards...
============================================================
[*] Vérification de la connexion au dashboard...
[+] Connexion au dashboard: OK
[*] Vérification des visualisations...
[+] Visualisations existantes: 5
[*] Vérification des dashboards...
[+] Dashboards existants: 1
============================================================

[+] Configuration des dashboards: OK
```

### Appliquer la configuration des dashboards

```bash
python3 wazuh_configurator.py --module dashboard --action apply
```

**Ce que cela fait:**
- Crée l'index pattern wazuh-alerts-*
- Crée les visualisations SOC (alertes par niveau, par source, etc.)
- Crée le dashboard SOC complet

### Valider la configuration

```bash
python3 wazuh_configurator.py --module dashboard --action validate
```

### Annuler les changements (Rollback)

```bash
python3 wazuh_configurator.py --module dashboard --action rollback
```

### Configuration personnalisée du dashboard

Vous pouvez spécifier l'URL et les credentials du dashboard:

```bash
python3 wazuh_configurator.py \
  --module dashboard \
  --action apply \
  --dashboard-url https://192.168.1.100:5601 \
  --dashboard-username admin \
  --dashboard-password your_password
```

---

## Configuration distante via SSH

Le Wazuh Configurator supporte la configuration de machines distantes via SSH.

### Configuration avec clé SSH

```bash
python3 wazuh_configurator.py \
  --module security \
  --action check \
  --remote-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa
```

### Configuration avec mot de passe

```bash
python3 wazuh_configurator.py \
  --module security \
  --action apply \
  --remote-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-password your_password
```

### Configuration avec port SSH personnalisé

```bash
python3 wazuh_configurator.py \
  --module security \
  --action check \
  --remote-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --ssh-port 2222
```

### Configuration de chemin Wazuh personnalisé

```bash
python3 wazuh_configurator.py \
  --module security \
  --action check \
  --remote-host 192.168.1.100 \
  --ssh-user admin \
  --ssh-key ~/.ssh/id_rsa \
  --wazuh-path /opt/wazuh
```

### Configuration de plusieurs machines

Vous pouvez créer un script pour configurer plusieurs machines:

```bash
#!/bin/bash
MACHINES=("192.168.1.100" "192.168.1.101" "192.168.1.102")

for machine in "${MACHINES[@]}"; do
    echo "Configuration de $machine..."
    python3 wazuh_configurator.py \
        --module security \
        --action apply \
        --remote-host "$machine" \
        --ssh-user admin \
        --ssh-key ~/.ssh/id_rsa
done
```

---

## Dépannage

### Erreur: "Wazuh non détecté sur ce système"

**Cause:** Wazuh n'est pas installé sur la machine.

**Solution:** 
- Vérifiez que Wazuh est installé: `systemctl status wazuh-server`
- Si Wazuh n'est pas installé, utilisez le Smart Installer: `python3 wazuh_smart_installer.py install`

### Erreur: "Permission denied"

**Cause:** L'utilisateur n'a pas les permissions nécessaires.

**Solution:** 
- Exécutez le configurator avec sudo: `sudo python3 wazuh_configurator.py ...`
- Ou assurez-vous que l'utilisateur a les permissions appropriées.

### Erreur: "SSHConnectionError"

**Cause:** Impossible de se connecter à la machine distante.

**Solution:**
- Vérifiez que la machine distante est accessible: `ping 192.168.1.100`
- Vérifiez que le port SSH est ouvert: `nmap -p 22 192.168.1.100`
- Vérifiez les credentials SSH
- Vérifiez que la clé SSH a les permissions correctes: `chmod 600 ~/.ssh/id_rsa`

### Erreur: "Dashboard non accessible"

**Cause:** Le dashboard Wazuh n'est pas accessible.

**Solution:**
- Vérifiez que le dashboard est en cours d'exécution: `systemctl status wazuh-dashboard`
- Vérifiez que le port 5601 est ouvert: `nmap -p 5601 localhost`
- Vérifiez l'URL du dashboard: `--dashboard-url https://localhost:5601`
- Vérifiez les credentials du dashboard

### Erreur: "Configuration déjà appliquée"

**Cause:** La configuration a déjà été appliquée.

**Solution:**
- Utilisez `--action validate` pour vérifier que la configuration est correcte
- Si vous voulez réappliquer, utilisez d'abord `--action rollback` puis `--action apply`

### Logs détaillés

Pour obtenir des logs détaillés, utilisez l'option `--log-level DEBUG`:

```bash
python3 wazuh_configurator.py --module security --action check --log-level DEBUG
```

### Logs au format JSON

Pour des logs au format JSON (utile pour l'intégration avec des systèmes de log):

```bash
python3 wazuh_configurator.py --module security --action check --json-format
```

### Vérifier les fichiers de log

Les logs sont sauvegardés dans `wazuh_configurator.log`:

```bash
tail -f wazuh_configurator.log
```

---

## Meilleures pratiques

1. **Toujours vérifier avant d'appliquer:**
   ```bash
   python3 wazuh_configurator.py --module security --action check
   python3 wazuh_configurator.py --module security --action apply
   ```

2. **Valider après l'application:**
   ```bash
   python3 wazuh_configurator.py --module security --action validate
   ```

3. **Utiliser le rollback en cas d'erreur:**
   ```bash
   python3 wazuh_configurator.py --module security --action rollback
   ```

4. **Tester sur un environnement de développement avant la production**

5. **Garder une sauvegarde des configurations avant modifications**

6. **Utiliser le cache pour optimiser les vérifications répétées** (activé par défaut)

7. **Utiliser le logger structuré pour le monitoring** (activé par défaut)

---

## Support

Pour plus d'informations ou pour signaler un problème:
- GitHub: https://github.com/VulneZe/wazuh-install
- Documentation: https://github.com/VulneZe/wazuh-install/tree/main/docs
