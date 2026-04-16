"""
Monitoring Configurator - Monitoring configuration strategy
Implements alerts and logging configuration
"""

from typing import Dict, Optional
import os
import subprocess
from ..core.base_configurator import BaseConfigurator, ConfigResult


class MonitoringConfigurator(BaseConfigurator):
    """Monitoring configuration strategy"""
    
    MONITORING_CHECKS = {
        "service_monitoring": "Service monitoring configured",
        "log_level": "Log level optimized",
        "alerts_enabled": "Alerts enabled",
        "health_checks": "Health checks configured"
    }
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        super().__init__(wazuh_path)
        self.monitoring_config = {}
    
    def check(self) -> ConfigResult:
        """Check current monitoring configuration"""
        print("[*] Verification configuration monitoring...")
        
        results = {}
        warnings = []
        
        # Check service monitoring
        service_result = self._check_service_monitoring()
        results["service_monitoring"] = service_result
        
        if not service_result:
            warnings.append("Monitoring services non configure")
        
        # Check log level
        log_result = self._check_log_level()
        results["log_level"] = log_result
        
        if not log_result:
            warnings.append("Niveau logs non optimise")
        
        # Check alerts
        alerts_result = self._check_alerts_enabled()
        results["alerts_enabled"] = alerts_result
        
        if not alerts_result:
            warnings.append("Alertes non activees")
        
        # Check health checks
        health_result = self._check_health_checks()
        results["health_checks"] = health_result
        
        if not health_result:
            warnings.append("Health checks non configurees")
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Monitoring: {success_count}/{total_count} verifications OK",
            details=results,
            warnings=warnings
        )
    
    def apply(self) -> ConfigResult:
        """Apply monitoring configuration"""
        print("[*] Application configuration monitoring...")
        
        results = {}
        
        # Apply service monitoring
        service_result = self._apply_service_monitoring()
        results["service_monitoring"] = service_result
        
        # Apply log level
        log_result = self._apply_log_level()
        results["log_level"] = log_result
        
        # Apply alerts
        alerts_result = self._apply_alerts_enabled()
        results["alerts_enabled"] = alerts_result
        
        # Apply health checks
        health_result = self._apply_health_checks()
        results["health_checks"] = health_result
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Monitoring: {success_count}/{total_count} configurations appliquees",
            details=results
        )
    
    def validate(self) -> ConfigResult:
        """Validate monitoring configuration"""
        print("[*] Validation configuration monitoring...")
        return self.check()
    
    def rollback(self) -> ConfigResult:
        """Rollback monitoring configuration"""
        print("[*] Rollback configuration monitoring...")
        
        success = True
        for config_file in self.config_files.keys():
            if not self.restore_config(config_file):
                success = False
        
        return ConfigResult(
            success=success,
            message="Rollback monitoring termine",
            details={"rollback": success}
        )
    
    def _check_service_monitoring(self) -> bool:
        """Check if service monitoring is configured"""
        # Check if monitoring services are configured
        monit_config = "/etc/monit/monitrc"
        if os.path.exists(monit_config):
            content = self.read_config_file(monit_config)
            if content:
                return "wazuh" in content.lower()
        
        # Check systemd monitoring
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service"],
                capture_output=True, text=True, check=False,
                timeout=30
            )
            return "wazuh" in result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        except Exception:
            return False
    
    def _check_log_level(self) -> bool:
        """Check if log level is optimized"""
        # Check Wazuh manager log configuration
        local_options = "/var/ossec/etc/local_internal_options.conf"
        if os.path.exists(local_options):
            content = self.read_config_file(local_options)
            # Check if log level is set to INFO (not DEBUG for production)
            return "log.level" in content and "debug" not in content.lower()
        
        return False
    
    def _check_alerts_enabled(self) -> bool:
        """Check if alerts are enabled"""
        # Check Wazuh alerts configuration
        ossec_config = "/var/ossec/etc/ossec.conf"
        if os.path.exists(ossec_config):
            content = self.read_config_file(ossec_config)
            return "<alerts>" in content and "</alerts>" in content
        
        return False
    
    def _check_health_checks(self) -> bool:
        """Check if health checks are configured"""
        # Check if health check script exists
        health_check = "/usr/local/bin/wazuh-health-check"
        return os.path.exists(health_check)
    
    def _apply_service_monitoring(self) -> bool:
        """Apply service monitoring configuration"""
        print("[*] Configuration monitoring services...")
        
        # Create simple systemd monitoring
        monitor_script = "/usr/local/bin/wazuh-monitor"
        monitor_content = """#!/bin/bash
# Wazuh service monitoring script
SERVICES="wazuh-indexer wazuh-manager wazuh-dashboard"

for service in $SERVICES; do
    if ! systemctl is-active --quiet $service; then
        echo "[!] Service $service is down"
        systemctl restart $service
        echo "[+] Service $service restarted"
    fi
done
"""
        
        self.write_config_file(monitor_script, monitor_content)
        os.chmod(monitor_script, 0o755)
        self.config_files[monitor_script] = True
        
        # Add to cron for monitoring every 5 minutes
        cron_line = "*/5 * * * * /usr/local/bin/wazuh-monitor"
        try:
            subprocess.run(
                ["crontab", "-l"],
                capture_output=True, text=True, check=False,
                timeout=30
            )
            # Append to existing crontab
            subprocess.run(
                ["bash", "-c", f"(crontab -l 2>/dev/null; echo '{cron_line}') | crontab -"],
                check=True, timeout=30
            )
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            # Create new crontab
            subprocess.run(
                ["bash", "-c", f"echo '{cron_line}' | crontab -"],
                check=True, timeout=30
            )
        
        print("[+] Monitoring services configure (cron 5min)")
        return True
    
    def _apply_log_level(self) -> bool:
        """Apply log level configuration"""
        print("[*] Configuration niveau logs...")
        
        local_options = "/var/ossec/etc/local_internal_options.conf"
        if os.path.exists(local_options):
            self.backup_config(local_options)
        
        # Set log level to INFO (not DEBUG for production)
        log_config = """
# Log level configuration
log.level=info
"""
        
        self.write_config_file(local_options, log_config)
        self.config_files[local_options] = True
        
        print("[+] Niveau logs configure (INFO)")
        return True
    
    def _apply_alerts_enabled(self) -> ConfigResult:
        """Apply alerts configuration"""
        print("[*] Configuration alertes...")
        
        ossec_config = "/var/ossec/etc/ossec.conf"
        if os.path.exists(ossec_config):
            content = self.read_config_file(ossec_config)
            
            # Check if alerts section exists
            if "<alerts>" not in content:
                print("[-] Section alerts non trouvee dans ossec.conf")
                return ConfigResult(
                    success=False,
                    message="Configuration alertes necessite modification manuelle"
                )
        
        print("[+] Alertes deja configurees")
        return ConfigResult(
            success=True,
            message="Alertes deja activees"
        )
    
    def _apply_health_checks(self) -> bool:
        """Apply health checks configuration"""
        print("[*] Configuration health checks...")
        
        health_check_script = "/usr/local/bin/wazuh-health-check"
        health_content = """#!/bin/bash
# Wazuh health check script

# Check if all Wazuh services are running
SERVICES=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
ALL_OK=true

for service in "${SERVICES[@]}"; do
    if systemctl is-active --quiet $service; then
        echo "[+] $service: OK"
    else
        echo "[-] $service: FAILED"
        ALL_OK=false
    fi
done

# Check disk space
DISK_USAGE=$(df /var/ossec | tail -1 | awk '{print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "[!] Disk usage high: ${DISK_USAGE}%"
    ALL_OK=false
fi

# Check memory
MEM_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
if [ $(echo "$MEM_USAGE > 90" | bc -l) -eq 1 ]; then
    echo "[!] Memory usage high: ${MEM_USAGE}%"
    ALL_OK=false
fi

if $ALL_OK; then
    echo "[+] All health checks passed"
    exit 0
else
    echo "[-] Some health checks failed"
    exit 1
fi
"""
        
        self.write_config_file(health_check_script, health_content)
        os.chmod(health_check_script, 0o755)
        self.config_files[health_check_script] = True
        
        print("[+] Health checks configurees")
        return True
