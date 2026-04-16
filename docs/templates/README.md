# Templates de configuration

## Table des matières

- [Templates Security](#templates-security)
- [Templates Performance](#templates-performance)
- [Templates Monitoring](#templates-monitoring)
- [Templates Security Modules](#templates-security-modules)
- [Templates Dashboard](#templates-dashboard)
- [Templates Multi-environment](#templates-multi-environment)

---

## Templates Security

### Template Sécurité Standard

Configuration de sécurité standard pour environnement de production.

**Fichier:** `security_standard.yaml`

```yaml
security:
  ssl:
    enabled: true
    certificate_path: "/var/ossec/etc/sslmanager/certs/manager.cert"
    key_path: "/var/ossec/etc/sslmanager/certs/manager.key"
    ca_path: "/var/ossec/etc/sslmanager/certs/rootCA.pem"
  
  ports:
    events_port: 1514
    secure_port: 1515
    api_port: 55000
  
  firewall:
    enabled: true
    tool: "ufw"
    allowed_ports:
      - 1514/tcp
      - 1515/tcp
      - 55000/tcp
  
  passwords:
    change_defaults: true
    admin_password: "your_secure_password"
    api_password: "your_api_password"
  
  api:
    authentication:
      enabled: true
      method: "jwt"
      token_timeout: 3600
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module security --action apply --config-file docs/templates/security_standard.yaml
```

---

### Template Sécurité Développement

Configuration de sécurité pour environnement de développement (moins restrictive).

**Fichier:** `security_dev.yaml`

```yaml
security:
  ssl:
    enabled: false
  
  ports:
    events_port: 1514
    secure_port: 1515
    api_port: 55000
  
  firewall:
    enabled: false
  
  passwords:
    change_defaults: false
  
  api:
    authentication:
      enabled: false
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module security --action apply --config-file docs/templates/security_dev.yaml
```

---

### Template Sécurité Haute Disponibilité

Configuration de sécurité pour cluster haute disponibilité.

**Fichier:** `security_ha.yaml`

```yaml
security:
  ssl:
    enabled: true
    certificate_path: "/var/ossec/etc/sslmanager/certs/manager.cert"
    key_path: "/var/ossec/etc/sslmanager/certs/manager.key"
    ca_path: "/var/ossec/etc/sslmanager/certs/rootCA.pem"
    verify_peer: true
  
  ports:
    events_port: 1514
    secure_port: 1515
    api_port: 55000
  
  firewall:
    enabled: true
    tool: "ufw"
    allowed_ports:
      - 1514/tcp
      - 1515/tcp
      - 55000/tcp
      - 9200/tcp  # Indexer
      - 9300/tcp  # Indexer
  
  passwords:
    change_defaults: true
    admin_password: "your_secure_password"
    api_password: "your_api_password"
  
  api:
    authentication:
      enabled: true
      method: "jwt"
      token_timeout: 1800
  
  cluster:
    enabled: true
    nodes:
      - host: "192.168.1.100"
        port: 1514
      - host: "192.168.1.101"
        port: 1514
      - host: "192.168.1.102"
        port: 1514
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module security --action apply --config-file docs/templates/security_ha.yaml
```

---

## Templates Performance

### Template Performance Standard

Configuration de performance standard pour environnement de production.

**Fichier:** `performance_standard.yaml`

```yaml
performance:
  cache:
    enabled: true
    size: "512M"
    ttl: 300
  
  database:
    optimized: true
    connection_pool: 50
    query_timeout: 30
  
  threads:
    analysis_threads: 4
    rule_loader_threads: 2
    decoder_threads: 2
  
  logging:
    level: "INFO"
    max_size: "100M"
    max_files: 10
  
  memory:
    max_memory: "2G"
    buffer_size: "16M"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module performance --action apply --config-file docs/templates/performance_standard.yaml
```

---

### Template Performance Haute Charge

Configuration de performance pour environnement à haute charge.

**Fichier:** `performance_high_load.yaml`

```yaml
performance:
  cache:
    enabled: true
    size: "2G"
    ttl: 600
  
  database:
    optimized: true
    connection_pool: 100
    query_timeout: 60
  
  threads:
    analysis_threads: 8
    rule_loader_threads: 4
    decoder_threads: 4
  
  logging:
    level: "WARNING"
    max_size: "500M"
    max_files: 20
  
  memory:
    max_memory: "8G"
    buffer_size: "64M"
  
  queue:
    event_queue_size: 100000
    alert_queue_size: 50000
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module performance --action apply --config-file docs/templates/performance_high_load.yaml
```

---

### Template Performance Faible Ressource

Configuration de performance pour environnement à faible ressource.

**Fichier:** `performance_low_resource.yaml`

```yaml
performance:
  cache:
    enabled: true
    size: "128M"
    ttl: 300
  
  database:
    optimized: true
    connection_pool: 10
    query_timeout: 30
  
  threads:
    analysis_threads: 2
    rule_loader_threads: 1
    decoder_threads: 1
  
  logging:
    level: "ERROR"
    max_size: "50M"
    max_files: 5
  
  memory:
    max_memory: "512M"
    buffer_size: "8M"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module performance --action apply --config-file docs/templates/performance_low_resource.yaml
```

---

## Templates Monitoring

### Template Monitoring Standard

Configuration de monitoring standard pour environnement de production.

**Fichier:** `monitoring_standard.yaml`

```yaml
monitoring:
  alerts:
    enabled: true
    email_alerts: true
    email_recipients:
      - "security@company.com"
      - "ops@company.com"
    severity_levels:
      - "critical"
      - "high"
      - "medium"
  
  health_checks:
    enabled: true
    interval: 60
    timeout: 30
    checks:
      - "disk_space"
      - "memory"
      - "cpu"
      - "services"
  
  logging:
    level: "INFO"
    format: "json"
    output: "file"
    file_path: "/var/ossec/logs/wazuh.log"
  
  notifications:
    slack:
      enabled: false
      webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    email:
      enabled: true
      smtp_server: "smtp.company.com"
      smtp_port: 587
      smtp_user: "alerts@company.com"
      smtp_password: "your_password"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module monitoring --action apply --config-file docs/templates/monitoring_standard.yaml
```

---

### Template Monitoring Développement

Configuration de monitoring pour environnement de développement.

**Fichier:** `monitoring_dev.yaml`

```yaml
monitoring:
  alerts:
    enabled: true
    email_alerts: false
    severity_levels:
      - "critical"
      - "high"
  
  health_checks:
    enabled: true
    interval: 300
    timeout: 60
    checks:
      - "services"
  
  logging:
    level: "DEBUG"
    format: "text"
    output: "file"
  
  notifications:
    slack:
      enabled: false
    email:
      enabled: false
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module monitoring --action apply --config-file docs/templates/monitoring_dev.yaml
```

---

## Templates Security Modules

### Template Security Modules Standard

Configuration des modules de sécurité standard pour environnement de production.

**Fichier:** `security_modules_standard.yaml`

```yaml
security_modules:
  vulnerability_detector:
    enabled: true
    update_interval: 3600
    providers:
      - "Red Hat"
      - "Debian"
      - "Ubuntu"
      - "NVD"
    cve_feeds:
      enabled: true
  
  cis_benchmarks:
    enabled: true
    benchmarks:
      - "ubuntu_20.04"
      - "debian_10"
    severity: "high"
  
  fim:
    enabled: true
    directories:
      - path: "/etc"
        attributes: "check_sum,scheck_size,check_mtime"
      - path: "/usr/bin"
        attributes: "check_sum"
      - path: "/var/www"
        attributes: "check_sum,check_mtime"
    alert_on_new_files: true
    realtime: true
  
  mitre_attack:
    enabled: true
    techniques:
      - "T1003"
      - "T1055"
      - "T1059"
      - "T1083"
      - "T1106"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module security_modules --action apply --config-file docs/templates/security_modules_standard.yaml
```

---

### Template Security Modules Minimal

Configuration minimale des modules de sécurité pour environnement de développement.

**Fichier:** `security_modules_minimal.yaml`

```yaml
security_modules:
  vulnerability_detector:
    enabled: false
  
  cis_benchmarks:
    enabled: false
  
  fim:
    enabled: true
    directories:
      - path: "/etc"
        attributes: "check_sum"
    alert_on_new_files: false
    realtime: false
  
  mitre_attack:
    enabled: false
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module security_modules --action apply --config-file docs/templates/security_modules_minimal.yaml
```

---

## Templates Dashboard

### Template Dashboard Standard

Configuration standard du dashboard Wazuh.

**Fichier:** `dashboard_standard.yaml`

```yaml
dashboard:
  url: "https://localhost:5601"
  username: "admin"
  password: "your_password"
  
  index_pattern:
    name: "wazuh-alerts-*"
    time_field: "@timestamp"
  
  visualizations:
    - name: "Alerts by Level"
      type: "pie"
    - name: "Alerts by Source"
      type: "bar"
    - name: "Alerts Timeline"
      type: "line"
    - name: "Top Sources"
      type: "table"
    - name: "Alerts by Rule"
      type: "bar"
  
  dashboard:
    name: "Wazuh SOC Dashboard"
    description: "Security Operations Center Dashboard"
    panels:
      - "Alerts by Level"
      - "Alerts by Source"
      - "Alerts Timeline"
      - "Top Sources"
      - "Alerts by Rule"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module dashboard --action apply --config-file docs/templates/dashboard_standard.yaml
```

---

### Template Dashboard Avancé

Configuration avancée du dashboard avec plus de visualisations.

**Fichier:** `dashboard_advanced.yaml`

```yaml
dashboard:
  url: "https://localhost:5601"
  username: "admin"
  password: "your_password"
  
  index_pattern:
    name: "wazuh-alerts-*"
    time_field: "@timestamp"
  
  visualizations:
    - name: "Alerts by Level"
      type: "pie"
    - name: "Alerts by Source"
      type: "bar"
    - name: "Alerts Timeline"
      type: "line"
    - name: "Top Sources"
      type: "table"
    - name: "Alerts by Rule"
      type: "bar"
    - name: "Alerts by GeoLocation"
      type: "map"
    - name: "Agent Status"
      type: "pie"
    - name: "Vulnerabilities"
      type: "bar"
  
  dashboard:
    name: "Wazuh Advanced SOC Dashboard"
    description: "Advanced Security Operations Center Dashboard"
    panels:
      - "Alerts by Level"
      - "Alerts by Source"
      - "Alerts Timeline"
      - "Top Sources"
      - "Alerts by Rule"
      - "Alerts by GeoLocation"
      - "Agent Status"
      - "Vulnerabilities"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --module dashboard --action apply --config-file docs/templates/dashboard_advanced.yaml
```

---

## Templates Multi-environment

### Template Production Complet

Configuration complète pour environnement de production.

**Fichier:** `production_complete.yaml`

```yaml
security:
  ssl:
    enabled: true
    certificate_path: "/var/ossec/etc/sslmanager/certs/manager.cert"
    key_path: "/var/ossec/etc/sslmanager/certs/manager.key"
    ca_path: "/var/ossec/etc/sslmanager/certs/rootCA.pem"
  
  ports:
    events_port: 1514
    secure_port: 1515
    api_port: 55000
  
  firewall:
    enabled: true
    tool: "ufw"
    allowed_ports:
      - 1514/tcp
      - 1515/tcp
      - 55000/tcp
  
  passwords:
    change_defaults: true
    admin_password: "your_secure_password"
    api_password: "your_api_password"

performance:
  cache:
    enabled: true
    size: "512M"
    ttl: 300
  
  database:
    optimized: true
    connection_pool: 50
    query_timeout: 30
  
  threads:
    analysis_threads: 4
    rule_loader_threads: 2
    decoder_threads: 2
  
  logging:
    level: "INFO"
    max_size: "100M"
    max_files: 10

monitoring:
  alerts:
    enabled: true
    email_alerts: true
    email_recipients:
      - "security@company.com"
    severity_levels:
      - "critical"
      - "high"
      - "medium"
  
  health_checks:
    enabled: true
    interval: 60
    timeout: 30
    checks:
      - "disk_space"
      - "memory"
      - "cpu"
      - "services"

security_modules:
  vulnerability_detector:
    enabled: true
    update_interval: 3600
    providers:
      - "Red Hat"
      - "Debian"
      - "Ubuntu"
      - "NVD"
  
  cis_benchmarks:
    enabled: true
    benchmarks:
      - "ubuntu_20.04"
      - "debian_10"
    severity: "high"
  
  fim:
    enabled: true
    directories:
      - path: "/etc"
        attributes: "check_sum,scheck_size,check_mtime"
      - path: "/usr/bin"
        attributes: "check_sum"
      - path: "/var/www"
        attributes: "check_sum,check_mtime"
    alert_on_new_files: true
    realtime: true
  
  mitre_attack:
    enabled: true
    techniques:
      - "T1003"
      - "T1055"
      - "T1059"
      - "T1083"
      - "T1106"

dashboard:
  url: "https://localhost:5601"
  username: "admin"
  password: "your_password"
  
  index_pattern:
    name: "wazuh-alerts-*"
    time_field: "@timestamp"
  
  visualizations:
    - name: "Alerts by Level"
      type: "pie"
    - name: "Alerts by Source"
      type: "bar"
    - name: "Alerts Timeline"
      type: "line"
    - name: "Top Sources"
      type: "table"
    - name: "Alerts by Rule"
      type: "bar"
  
  dashboard:
    name: "Wazuh SOC Dashboard"
    description: "Security Operations Center Dashboard"
    panels:
      - "Alerts by Level"
      - "Alerts by Source"
      - "Alerts Timeline"
      - "Top Sources"
      - "Alerts by Rule"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --config-file docs/templates/production_complete.yaml
```

---

### Template Développement Complet

Configuration complète pour environnement de développement.

**Fichier:** `development_complete.yaml`

```yaml
security:
  ssl:
    enabled: false
  
  ports:
    events_port: 1514
    secure_port: 1515
    api_port: 55000
  
  firewall:
    enabled: false
  
  passwords:
    change_defaults: false

performance:
  cache:
    enabled: true
    size: "128M"
    ttl: 300
  
  database:
    optimized: true
    connection_pool: 10
    query_timeout: 30
  
  threads:
    analysis_threads: 2
    rule_loader_threads: 1
    decoder_threads: 1
  
  logging:
    level: "DEBUG"
    max_size: "50M"
    max_files: 5

monitoring:
  alerts:
    enabled: true
    email_alerts: false
    severity_levels:
      - "critical"
      - "high"
  
  health_checks:
    enabled: true
    interval: 300
    timeout: 60
    checks:
      - "services"

security_modules:
  vulnerability_detector:
    enabled: false
  
  cis_benchmarks:
    enabled: false
  
  fim:
    enabled: true
    directories:
      - path: "/etc"
        attributes: "check_sum"
    alert_on_new_files: false
    realtime: false
  
  mitre_attack:
    enabled: false

dashboard:
  url: "https://localhost:5601"
  username: "admin"
  password: "admin"
  
  index_pattern:
    name: "wazuh-alerts-*"
    time_field: "@timestamp"
  
  visualizations:
    - name: "Alerts by Level"
      type: "pie"
    - name: "Alerts by Source"
      type: "bar"
  
  dashboard:
    name: "Wazuh Dev Dashboard"
    description: "Development Dashboard"
    panels:
      - "Alerts by Level"
      - "Alerts by Source"
```

**Utilisation:**
```bash
python3 wazuh_configurator.py --config-file docs/templates/development_complete.yaml
```

---

## Personnalisation des Templates

Vous pouvez personnaliser les templates en fonction de vos besoins:

1. **Copier un template existant**
2. **Modifier les paramètres**
3. **Sauvegarder sous un nouveau nom**
4. **Utiliser le template personnalisé**

**Exemple:**
```bash
cp docs/templates/security_standard.yaml docs/templates/security_custom.yaml
# Éditer security_custom.yaml
python3 wazuh_configurator.py --module security --action apply --config-file docs/templates/security_custom.yaml
```

---

## Variables d'environnement

Vous pouvez utiliser des variables d'environnement dans les templates:

```yaml
security:
  passwords:
    admin_password: "${WAZUH_ADMIN_PASSWORD}"
    api_password: "${WAZUH_API_PASSWORD}"
```

**Utilisation:**
```bash
export WAZUH_ADMIN_PASSWORD="your_password"
export WAZUH_API_PASSWORD="your_api_password"
python3 wazuh_configurator.py --module security --action apply --config-file docs/templates/security_standard.yaml
```

---

## Validation des Templates

Avant d'appliquer un template, vous pouvez le valider:

```bash
python3 wazuh_configurator.py --module security --action validate --config-file docs/templates/security_standard.yaml
```

---

## Support

Pour plus d'informations sur les templates:
- Documentation API: [API Documentation](../api/README.md)
- Guide d'utilisation: [Usage Guide](../usage/README.md)
