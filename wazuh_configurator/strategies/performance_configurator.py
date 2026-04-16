"""
Performance Configurator - Performance optimization configuration strategy
Implements memory and storage optimization
"""

import os
import subprocess
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.cache import cached


class PerformanceConfigurator(BaseConfigurator):
    """Performance configuration strategy"""
    
    PERFORMANCE_CHECKS = {
        "jvm_memory": "JVM memory optimized",
        "log_rotation": "Log rotation configured",
        "disk_cleanup": "Disk cleanup configured",
        "connection_pool": "Connection pool optimized"
    }
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        super().__init__(wazuh_path)
        self.paths = WazuhPaths()
        self.system_memory = self._get_system_memory()
        self.performance_config = {}
    
    @cached(ttl=300)
    def check(self) -> ConfigResult:
        """Check current performance configuration"""
        print("[*] Verification configuration performance...")
        
        results = {}
        warnings = []
        
        # Check JVM memory configuration
        jvm_result = self._check_jvm_memory()
        results["jvm_memory"] = jvm_result
        
        if not jvm_result:
            warnings.append("JVM memory non optimisee")
        
        # Check log rotation
        log_result = self._check_log_rotation()
        results["log_rotation"] = log_result
        
        if not log_result:
            warnings.append("Rotation logs non configuree")
        
        # Check disk cleanup
        cleanup_result = self._check_disk_cleanup()
        results["disk_cleanup"] = cleanup_result
        
        if not cleanup_result:
            warnings.append("Nettoyage disque non configure")
        
        # Check connection pool
        pool_result = self._check_connection_pool()
        results["connection_pool"] = pool_result
        
        if not pool_result:
            warnings.append("Pool connexions non optimise")
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Performance: {success_count}/{total_count} verifications OK",
            details=results,
            warnings=warnings
        )
    
    def apply(self) -> ConfigResult:
        """Apply performance configuration"""
        print("[*] Application configuration performance...")
        
        results = {}
        
        # Apply JVM memory configuration
        jvm_result = self._apply_jvm_memory()
        results["jvm_memory"] = jvm_result
        
        # Apply log rotation
        log_result = self._apply_log_rotation()
        results["log_rotation"] = log_result
        
        # Apply disk cleanup
        cleanup_result = self._apply_disk_cleanup()
        results["disk_cleanup"] = cleanup_result
        
        # Apply connection pool
        pool_result = self._apply_connection_pool()
        results["connection_pool"] = pool_result
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Performance: {success_count}/{total_count} configurations appliquees",
            details=results
        )
    
    def validate(self) -> ConfigResult:
        """Validate performance configuration"""
        print("[*] Validation configuration performance...")
        return self.check()
    
    def rollback(self) -> ConfigResult:
        """Rollback performance configuration"""
        print("[*] Rollback configuration performance...")
        
        success = True
        for config_file in self.config_files.keys():
            if not self.restore_config(config_file):
                success = False
        
        return ConfigResult(
            success=success,
            message="Rollback performance termine",
            details={"rollback": success}
        )
    
    def _get_system_memory(self) -> int:
        """Get total system memory in GB"""
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r") as f:
                    meminfo = f.read()
                match = re.search(r"MemTotal:\s+(\d+)", meminfo)
                if match:
                    mem_kb = int(match.group(1))
                    return mem_kb // (1024 * 1024)  # Convert to GB
        except (OSError, IOError, ValueError):
            pass
        return 4  # Default to 4GB
    
    @cached(ttl=300)
    def _check_jvm_memory(self) -> bool:
        """Check if JVM memory is properly configured"""
        # Check Wazuh indexer JVM config
        if os.path.exists(self.paths.jvm_config):
            content = self.read_config_file(self.paths.jvm_config)
            # Check if heap size is configured (should be 50-70% of available memory)
            return "-Xms" in content and "-Xmx" in content
        
        return False
    
    @cached(ttl=300)
    def _check_log_rotation(self) -> bool:
        """Check if log rotation is configured"""
        # Check Wazuh manager log rotation
        if os.path.exists(self.paths.logrotate_config):
            content = self.read_config_file(self.paths.logrotate_config)
            return "rotate" in content and "size" in content
        
        return False
    
    @cached(ttl=300)
    def _check_disk_cleanup(self) -> bool:
        """Check if disk cleanup is configured"""
        # Check if cleanup cron job exists
        cleanup_script = os.path.join(self.paths.cron_daily, "wazuh-cleanup")
        return os.path.exists(cleanup_script)
    
    @cached(ttl=300)
    def _check_connection_pool(self) -> bool:
        """Check if connection pool is optimized"""
        # Check indexer configuration
        if os.path.exists(self.paths.indexer_config):
            content = self.read_config_file(self.paths.indexer_config)
            return "thread_pool" in content or "max_connections" in content
        
        return False
    
    def _apply_jvm_memory(self) -> bool:
        """Apply JVM memory configuration"""
        print("[*] Configuration JVM memory...")
        
        # Calculate optimal heap size (50-70% of available memory)
        heap_size = int(self.system_memory * 0.6)
        heap_min = int(self.system_memory * 0.4)
        
        if os.path.exists(self.paths.jvm_config):
            self.backup_config(self.paths.jvm_config)
            
            content = self.read_config_file(self.paths.jvm_config)
            # Add or replace heap size settings
            new_content = f"-Xms{heap_min}g\n-Xmx{heap_size}g\n"
            
            # Remove existing heap settings
            lines = content.split('\n')
            filtered_lines = [line for line in lines if not line.startswith('-Xms') and not line.startswith('-Xmx')]
            
            # Add new heap settings at the beginning
            filtered_lines.insert(0, new_content.strip())
            
            final_content = '\n'.join(filtered_lines)
            self.write_config_file(self.paths.jvm_config, final_content)
            self.config_files[self.paths.jvm_config] = True
            
            print(f"[+] JVM memory configure: {heap_min}GB min, {heap_size}GB max")
            return True
        
        print("[-] Fichier JVM config non trouve")
        return False
    
    def _apply_log_rotation(self) -> bool:
        """Apply log rotation configuration"""
        print("[*] Configuration rotation logs...")
        
        if os.path.exists(self.paths.logrotate_config):
            # Check if it has proper configuration
            content = self.read_config_file(self.paths.logrotate_config)
            if "rotate" in content and "size" in content:
                print("[+] Rotation logs deja configuree")
                return True
            else:
                self.backup_config(self.paths.logrotate_config)
        
        # Create new logrotate config
        logrotate_content = f"""
{self.paths.wazuh_logs}/*.log {{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    size 100M
}}
"""
        self.write_config_file(self.paths.logrotate_config, logrotate_content)
        self.config_files[self.paths.logrotate_config] = True
        print("[+] Rotation logs configuree")
        return True
    
    def _apply_disk_cleanup(self) -> bool:
        """Apply disk cleanup configuration"""
        print("[*] Configuration nettoyage disque...")
        
        cleanup_script = os.path.join(self.paths.cron_daily, "wazuh-cleanup")
        cleanup_content = f"""#!/bin/bash
# Wazuh disk cleanup script
# Remove logs older than 30 days
find {self.paths.wazuh_logs}/ -name "*.log" -mtime +30 -delete
find {self.paths.alerts_logs}/ -name "*.json" -mtime +30 -delete
find {self.paths.archives_logs}/ -name "*.log.gz" -mtime +90 -delete
"""
        
        self.write_config_file(cleanup_script, cleanup_content)
        os.chmod(cleanup_script, 0o755)
        self.config_files[cleanup_script] = True
        
        print("[+] Nettoyage disque configure (cron daily)")
        return True
    
    def _apply_connection_pool(self) -> bool:
        """Apply connection pool configuration"""
        print("[*] Configuration pool connexions...")
        
        if os.path.exists(self.paths.indexer_config):
            content = self.read_config_file(self.paths.indexer_config)
            if not content:
                print("[-] Impossible de lire le fichier config indexer")
                return False
                
            self.backup_config(self.paths.indexer_config)
            
            # Add connection pool settings
            pool_config = """
# Connection pool settings
thread_pool:
  search:
    size: 20
    queue_size: 1000
  write:
    size: 10
    queue_size: 500
"""
            
            if "thread_pool" not in content:
                content += pool_config
            
            self.write_config_file(self.paths.indexer_config, content)
            self.config_files[self.paths.indexer_config] = True
            print("[+] Pool connexions configure")
            return True
        
        print("[-] Fichier config indexer non trouve")
        return False
