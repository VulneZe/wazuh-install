# wazuh-devsec-config-generator

Générateur Python professionnel qui configure **ENTIÈREMENT** Wazuh (4.x/5.x) pour une entreprise de dev/édition logiciel.

**Structure de sortie (la plus facile à déployer sur Wazuh) :**
```
output/wazuh-custom-devsec/
├── etc/
│   ├── rules/                  ← tous les .xml customs + local_rules.xml
│   ├── decoders/               ← decoders + sibling
│   ├── lists/cdb/              ← .txt prêts pour ossec-makelists
│   ├── ossec.conf.d/           ← fragments à merger (recommandé)
│   ├── active-response/
│   │   ├── bin/                ← scripts Python AR
│   │   └── commands/           ← <command> XML
│   └── custom_lists.conf       ← à inclure dans ossec.conf
└── tests/sample-logs/          ← 20 logs de test + résultats attendus
```

## Installation & lancement

```bash
git clone <votre-repo>
cd wazuh-devsec-config-generator
pip install -e .
wazuh-generator
```

## Déploiement (30 secondes sur le manager)

```bash
sudo rsync -av --chown=ossec:ossec output/wazuh-custom-devsec/etc/ /var/ossec/etc/
sudo /var/ossec/bin/ossec-makelists
sudo systemctl restart wazuh-manager
/var/ossec/bin/wazuh-logtest < tests/sample-logs/git-suspicious.txt
```

Tout est prêt à la production : 40+ règles personnalisées (ID 100000-119999), whitelists CDB, low FP (<5%), MITRE ATT&CK, Linux + Windows, FIM renforcé, etc.
