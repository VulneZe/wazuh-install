from pathlib import Path
from typing import List

def create_cdb_list(name: str, items: List[str], output_dir: Path) -> None:
    """Crée un fichier .txt prêt pour ossec-makelists (format Wazuh CDB)"""
    file = output_dir / f"{name}.txt"
    content = "\n".join(items) + "\n"
    file.write_text(content, encoding="utf-8")
    print(f"   ✅ Liste CDB générée : {name}.txt ({len(items)} entrées)")
