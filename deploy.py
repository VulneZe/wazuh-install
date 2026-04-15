#!/usr/bin/env python3
import subprocess
from pathlib import Path

def deploy():
    output = Path("output/wazuh-custom-devsec")
    if not output.exists():
        print("❌ Lance d'abord : wazuh-generator")
        return

    print("🚀 Déploiement sur Wazuh manager...")
    cmd = [
        "sudo", "rsync", "-av", "--chown=ossec:ossec",
        f"{output}/etc/", "/var/ossec/etc/"
    ]
    subprocess.run(cmd, check=True)
    subprocess.run(["sudo", "/var/ossec/bin/ossec-makelists"], check=True)
    subprocess.run(["sudo", "systemctl", "restart", "wazuh-manager"], check=True)
    print("✅ Déploiement terminé ! Testez avec wazuh-logtest")

if __name__ == "__main__":
    deploy()
