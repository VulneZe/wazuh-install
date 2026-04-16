"""
Monitoring Configurator - Monitoring configuration strategy
"""

import os
import subprocess
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.logger import WazuhLogger
from ..utils.cache import cached


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
        self.paths = WazuhPaths()
        self.monitoring_config = {}
        self._logger = WazuhLogger(__name__, use_json=False)
    
    @cached(ttl=300)
    def check(self) -> ConfigResult:
        """Check current monitoring configuration"""
        self._logger.info("Verification configuration monitoring...")
        
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
        self._logger.info("Application configuration monitoring...")
        
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
        """Validate applied monitoring configuration"""
        self._logger.info("Validation configuration monitoring...")
        return self.check()
    
    def rollback(self) -> ConfigResult:
        """Rollback monitoring configuration"""
        self._logger.info("Rollback configuration monitoring...")
        
        success = True
        for config_file in self.config_files.keys():
            if not self.restore_config(config_file):
                success = False
        
        return ConfigResult(
            success=success,
            message="Rollback monitoring termine",
            details={"rollback": success}
        )
    
    @cached(ttl=300)
    def _check_service_monitoring(self) -> bool:
        """Check if service monitoring is configured"""
        # Check if monitoring services are configured
        # Note: monit_config is not in WazuhPaths as it's optional
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
    
    @cached(ttl=300)
    def _check_log_level(self) -> bool:
        """Check if log level is optimized"""
        # Check Wazuh manager log configuration
        if os.path.exists(self.paths.local_options):
            content = self.read_config_file(self.paths.local_options)
            # Check if log level is set to INFO (not DEBUG for production)
            return "log.level" in content and "debug" not in content.lower()
        
        return False
    
    @cached(ttl=300)
    def _check_alerts_enabled(self) -> bool:
        """Check if alerts are enabled"""
        # Check Wazuh alerts configuration
        if os.path.exists(self.paths.ossec_conf):
            content = self.read_config_file(self.paths.ossec_conf)
            return "<alerts>" in content and "</alerts>" in content
        
        return False
    
    @cached(ttl=300)
    def _check_health_checks(self) -> bool:
        """Check if health checks are configured"""
        # Check if health check script exists
        health_check = "/usr/local/bin/wazuh-health-check"
        return os.path.exists(health_check)
    
    def _apply_service_monitoring(self) -> bool:
        """Apply service monitoring configuration"""
        self._logger.info("Configuration monitoring services...")
        
        # Create simple systemd monitoring
        monitor_script = "/usr/local/bin/wazuh-monitor"
        monitor_content = """#!/bin/bash
# Wazuh service monitoring script
# Checks if Wazuh services are running

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
        
        self._logger.info("Monitoring services configure (cron 5min)")
        return True
    
    def _apply_log_level(self) -> bool:
        """Apply log level configuration"""
        self._logger.info("Configuration niveau logs...")
        
        if os.path.exists(self.paths.local_options):
            self.backup_config(self.paths.local_options)
        
        # Set log level to INFO (not DEBUG for production)
        log_config = """
# Log level configuration
log.level=info
"""
        
        self.write_config_file(self.paths.local_options, log_config)
        self.config_files[self.paths.local_options] = True
        
        self._logger.info("Niveau logs configure (INFO)")
        return True
    
    def _apply_alerts_enabled(self) -> bool:
        """Apply alerts configuration"""
        self._logger.info("Configuration alertes...")
        
        if os.path.exists(self.paths.ossec_conf):
            content = self.read_config_file(self.paths.ossec_conf)
            
            # Check if alerts section exists
            if "<alerts>" not in content:
                self._logger.error("Section alerts non trouvee dans ossec.conf")
                return ConfigResult(
                    success=False,
                    message="Configuration alertes necessite modification manuelle"
                )
            
            # Enable critical alerts
            content = content.replace("<alerts>", '<alerts>\n    <use_alerts>yes</use_alerts>')
            self.write_config_file(self.paths.ossec_conf, content)
            self.config_files[self.paths.ossec_conf] = True
        
        self._logger.info("Alertes deja configurees")
        return ConfigResult(
            success=True,
            message="Alertes deja activees"
        )
    
    def _apply_health_checks(self) -> bool:
        """Apply health checks configuration"""
        self._logger.info("Configuration health checks...")
        
        health_check_script = os.path.join(self.paths.usr_local_bin, "wazuh-health-check")
        health_check_content = f"""#!/bin/bash
# Wazuh Health Check Script
# Checks if Wazuh services are running

# Check Wazuh Manager
if systemctl is-active --quiet wazuh-manager; then
    echo "Wazuh Manager: OK"
else
    echo "Wazuh Manager: FAILED"
    exit 1
fi

# Check Wazuh Indexer
if systemctl is-active --quiet wazuh-indexer; then
    echo "Wazuh Indexer: OK"
else
    echo "Wazuh Indexer: FAILED"
    exit 1
fi

# Check disk usage
DISK_USAGE=$(df {self.paths.wazuh_path} | tail -1 | awk '{{print $5}}' | sed 's/%//')
if [ $DISK_USAGE -gt 80 ]; then
    echo "Disk usage: WARNING ($DISK_USAGE%)"
fi

echo "Health check completed"
exit 0
"""
        
        self.write_config_file(health_check_script, health_check_content)
        os.chmod(health_check_script, 0o755)
        self.config_files[health_check_script] = True
        
        self._logger.info("Health checks configurees")
        return True
