"""
File Handler - Utility for file operations
"""

import os
import shutil
from typing import Optional


class FileHandler:
    """Handle file operations safely"""
    
    @staticmethod
    def read_file(file_path: str) -> Optional[str]:
        """Read file content safely"""
        try:
            with open(file_path, 'r') as f:
                return f.read()
        except Exception as e:
            print(f"[-] Error reading {file_path}: {e}")
            return None
    
    @staticmethod
    def write_file(file_path: str, content: str) -> bool:
        """Write content to file safely"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"[-] Error writing {file_path}: {e}")
            return False
    
    @staticmethod
    def backup_file(file_path: str) -> Optional[str]:
        """Backup a file"""
        try:
            backup_path = f"{file_path}.backup"
            shutil.copy2(file_path, backup_path)
            return backup_path
        except Exception as e:
            print(f"[-] Error backing up {file_path}: {e}")
            return None
    
    @staticmethod
    def restore_file(backup_path: str, original_path: str) -> bool:
        """Restore file from backup"""
        try:
            shutil.copy2(backup_path, original_path)
            return True
        except Exception as e:
            print(f"[-] Error restoring {original_path}: {e}")
            return False
    
    @staticmethod
    def file_exists(file_path: str) -> bool:
        """Check if file exists"""
        return os.path.exists(file_path)
    
    @staticmethod
    def create_directory(directory_path: str) -> bool:
        """Create directory if it doesn't exist"""
        try:
            os.makedirs(directory_path, exist_ok=True)
            return True
        except Exception as e:
            print(f"[-] Error creating directory {directory_path}: {e}")
            return False
