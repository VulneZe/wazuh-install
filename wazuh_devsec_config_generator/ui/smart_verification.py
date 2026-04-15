"""
Smart Verification System - Intelligent Environment Detection
Advanced system verification with detailed OS and service analysis
"""

import os
import sys
import platform
import subprocess
import psutil
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .terminal import EnhancedTerminalUI, UIConfig, UIStyle


class ServiceStatus(str, Enum):
    """Service status enumeration"""
    RUNNING = "running"
    STOPPED = "stopped"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


class OSType(str, Enum):
    """Operating system types"""
    MACOS = "macos"
    LINUX = "linux"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


@dataclass
class SystemInfo:
    """System information structure"""
    os_type: OSType
    os_version: str
    architecture: str
    hostname: str
    cpu_count: int
    memory_total: str
    disk_space: str
    python_version: str


@dataclass
class ServiceInfo:
    """Service information structure"""
    name: str
    status: ServiceStatus
    version: Optional[str]
    pid: Optional[int]
    memory_usage: Optional[str]
    config_path: Optional[str]


class SmartVerification:
    """Intelligent verification system"""
    
    def __init__(self, ui: EnhancedTerminalUI):
        self.ui = ui
        self.system_info = self._get_system_info()
        self.wazuh_paths = self._get_wazuh_paths()
        
    def run_comprehensive_verification(self) -> Dict[str, Any]:
        """Run comprehensive intelligent verification"""
        self.ui.show_loading("Analyse intelligente de l'environnement...", 2.0)
        
        verification_results = {
            "system": self._analyze_system(),
            "wazuh": self._analyze_wazuh(),
            "services": self._analyze_services(),
            "security": self._analyze_security(),
            "network": self._analyze_network(),
            "recommendations": []
        }
        
        # Generate intelligent recommendations
        verification_results["recommendations"] = self._generate_recommendations(verification_results)
        
        return verification_results
    
    def _get_system_info(self) -> SystemInfo:
        """Get detailed system information"""
        try:
            # OS Information
            system = platform.system().lower()
            if system == "darwin":
                os_type = OSType.MACOS
            elif system == "linux":
                os_type = OSType.LINUX
            elif system == "windows":
                os_type = OSType.WINDOWS
            else:
                os_type = OSType.UNKNOWN
            
            # Memory and disk
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return SystemInfo(
                os_type=os_type,
                os_version=platform.mac_ver()[0] if os_type == OSType.MACOS else platform.release(),
                architecture=platform.machine(),
                hostname=platform.node(),
                cpu_count=psutil.cpu_count(),
                memory_total=self._format_bytes(memory.total),
                disk_space=self._format_bytes(disk.free),
                python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
            )
        except Exception as e:
            self.ui.show_warning(f"Erreur lors de la détection système: {e}")
            return SystemInfo(
                os_type=OSType.UNKNOWN,
                os_version="Inconnue",
                architecture="Inconnue",
                hostname="Inconnu",
                cpu_count=0,
                memory_total="Inconnue",
                disk_space="Inconnue",
                python_version=f"{sys.version_info.major}.{sys.version_info.minor}"
            )
    
    def _get_wazuh_paths(self) -> Dict[str, List[str]]:
        """Get Wazuh paths based on OS"""
        if self.system_info.os_type == OSType.MACOS:
            return {
                "manager": ["/Library/Application Support/Wazuh"],
                "agent": ["/Library/Application Support/Wazuh"],
                "config": ["/Library/Application Support/Wazuh/etc"]
            }
        elif self.system_info.os_type == OSType.LINUX:
            return {
                "manager": ["/var/ossec"],
                "agent": ["/var/ossec"],
                "config": ["/var/ossec/etc"]
            }
        elif self.system_info.os_type == OSType.WINDOWS:
            return {
                "manager": ["C:\\Program Files (x86)\\ossec-agent"],
                "agent": ["C:\\Program Files (x86)\\ossec-agent"],
                "config": ["C:\\Program Files (x86)\\ossec-agent\\etc"]
            }
        else:
            return {"manager": [], "agent": [], "config": []}
    
    def _analyze_system(self) -> Dict[str, Any]:
        """Analyze system environment"""
        analysis = {
            "os_info": {
                "type": self.system_info.os_type.value,
                "version": self.system_info.os_version,
                "architecture": self.system_info.architecture,
                "hostname": self.system_info.hostname
            },
            "hardware": {
                "cpu_cores": self.system_info.cpu_count,
                "memory_total": self.system_info.memory_total,
                "disk_free": self.system_info.disk_space
            },
            "python": {
                "version": self.system_info.python_version,
                "executable": sys.executable,
                "pip_version": self._get_pip_version()
            },
            "virtual_env": self._check_virtual_env()
        }
        
        return analysis
    
    def _analyze_wazuh(self) -> Dict[str, Any]:
        """Analyze Wazuh installation"""
        wazuh_status = {
            "installed": False,
            "components": {},
            "paths_found": [],
            "version": None,
            "manager_status": ServiceStatus.NOT_INSTALLED,
            "agents": []
        }
        
        # Check all possible paths
        for component_type, paths in self.wazuh_paths.items():
            for path in paths:
                if Path(path).exists():
                    wazuh_status["installed"] = True
                    wazuh_status["paths_found"].append(path)
                    
                    # Analyze component
                    component_info = self._analyze_wazuh_component(path, component_type)
                    wazuh_status["components"][component_type] = component_info
        
        # Check Wazuh processes
        wazuh_processes = self._find_wazuh_processes()
        if wazuh_processes:
            wazuh_status["manager_status"] = ServiceStatus.RUNNING
            wazuh_status["processes"] = wazuh_processes
        
        # Try to detect version
        if wazuh_status["installed"]:
            wazuh_status["version"] = self._detect_wazuh_version(wazuh_status["paths_found"])
        
        # Check agents
        wazuh_status["agents"] = self._check_wazuh_agents(wazuh_status["paths_found"])
        
        return wazuh_status
    
    def _analyze_services(self) -> Dict[str, ServiceInfo]:
        """Analyze security-related services"""
        services = {}
        
        # Common security services to check
        security_services = {
            "docker": ["docker", "containerd"],
            "nginx": ["nginx"],
            "apache": ["apache2", "httpd"],
            "mysql": ["mysqld", "mysql"],
            "postgresql": ["postgres"],
            "redis": ["redis-server"],
            "elasticsearch": ["elasticsearch"],
            "suricata": ["suricata"],
            "fail2ban": ["fail2ban-server"]
        }
        
        for service_name, process_names in security_services.items():
            service_info = self._check_service(service_name, process_names)
            services[service_name] = service_info
        
        return services
    
    def _analyze_security(self) -> Dict[str, Any]:
        """Analyze security configuration"""
        security_analysis = {
            "firewall": self._check_firewall(),
            "antivirus": self._check_antivirus(),
            "permissions": self._check_permissions(),
            "open_ports": self._check_open_ports(),
            "security_tools": self._check_security_tools()
        }
        
        return security_analysis
    
    def _analyze_network(self) -> Dict[str, Any]:
        """Analyze network configuration"""
        network_analysis = {
            "interfaces": self._get_network_interfaces(),
            "dns_servers": self._get_dns_servers(),
            "internet_connectivity": self._check_internet(),
            "localhost_services": self._check_localhost_services()
        }
        
        return network_analysis
    
    def _analyze_wazuh_component(self, path: str, component_type: str) -> Dict[str, Any]:
        """Analyze specific Wazuh component"""
        component_info = {
            "path": path,
            "exists": True,
            "config_files": [],
            "log_files": [],
            "size": self._get_directory_size(path)
        }
        
        # Check config files
        config_path = Path(path) / "etc"
        if config_path.exists():
            component_info["config_files"] = [f.name for f in config_path.glob("*.conf")]
            component_info["config_files"].extend([f.name for f in config_path.glob("*.xml")])
        
        # Check log files
        logs_path = Path(path) / "logs"
        if logs_path.exists():
            component_info["log_files"] = [f.name for f in logs_path.glob("*.log")]
        
        return component_info
    
    def _find_wazuh_processes(self) -> List[Dict[str, Any]]:
        """Find running Wazuh processes"""
        wazuh_processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if any(keyword in cmdline.lower() for keyword in ['ossec', 'wazuh']):
                        wazuh_processes.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name'],
                            "cmdline": cmdline,
                            "memory": self._format_bytes(proc.memory_info().rss),
                            "cpu_percent": proc.cpu_percent()
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.ui.show_warning(f"Erreur lors de la recherche des processus Wazuh: {e}")
        
        return wazuh_processes
    
    def _detect_wazuh_version(self, paths: List[str]) -> Optional[str]:
        """Try to detect Wazuh version"""
        for path in paths:
            version_file = Path(path) / "etc" / "ossec.conf"
            if version_file.exists():
                try:
                    with open(version_file, 'r') as f:
                        content = f.read()
                        # Look for version info
                        if "4.8" in content:
                            return "4.8.x"
                        elif "4.7" in content:
                            return "4.7.x"
                        elif "4.6" in content:
                            return "4.6.x"
                except:
                    pass
        
        return None
    
    def _check_wazuh_agents(self, paths: List[str]) -> List[Dict[str, Any]]:
        """Check Wazuh agents"""
        agents = []
        
        for path in paths:
            client_keys = Path(path) / "etc" / "client.keys"
            if client_keys.exists():
                try:
                    with open(client_keys, 'r') as f:
                        lines = f.readlines()
                        for line in lines:
                            if line.strip() and not line.startswith('#'):
                                parts = line.strip().split(' ')
                                if len(parts) >= 4:
                                    agents.append({
                                        "id": parts[0],
                                        "name": parts[1],
                                        "ip": parts[2],
                                        "key": parts[3][:8] + "..."  # Show only first 8 chars
                                    })
                except:
                    pass
        
        return agents
    
    def _check_service(self, service_name: str, process_names: List[str]) -> ServiceInfo:
        """Check if a service is running"""
        running = False
        pid = None
        memory_usage = None
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    if any(name in cmdline.lower() for name in process_names):
                        running = True
                        pid = proc.info['pid']
                        memory_usage = self._format_bytes(proc.memory_info().rss)
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        
        status = ServiceStatus.RUNNING if running else ServiceStatus.STOPPED
        
        return ServiceInfo(
            name=service_name,
            status=status,
            version=None,
            pid=pid,
            memory_usage=memory_usage,
            config_path=None
        )
    
    def _check_firewall(self) -> Dict[str, Any]:
        """Check firewall status"""
        firewall_status = {
            "enabled": False,
            "type": "unknown",
            "details": ""
        }
        
        try:
            if self.system_info.os_type == OSType.MACOS:
                # Check macOS firewall
                result = subprocess.run(
                    ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    firewall_status["enabled"] = result.stdout.strip() != "0"
                    firewall_status["type"] = "macos_application_firewall"
                    firewall_status["details"] = f"State: {result.stdout.strip()}"
            
            elif self.system_info.os_type == OSType.LINUX:
                # Check UFW (Ubuntu/Debian)
                result = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    firewall_status["enabled"] = "active" in result.stdout.lower()
                    firewall_status["type"] = "ufw"
                    firewall_status["details"] = result.stdout.strip()
                
        except Exception as e:
            firewall_status["details"] = f"Erreur: {e}"
        
        return firewall_status
    
    def _check_antivirus(self) -> Dict[str, Any]:
        """Check antivirus status"""
        av_status = {
            "installed": False,
            "name": None,
            "real_time_protection": False,
            "details": ""
        }
        
        try:
            if self.system_info.os_type == OSType.MACOS:
                # Check for common macOS AV
                av_tools = [
                    "/Applications/XProtect.app",
                    "/Applications/Sophos Endpoint.app",
                    "/Applications/Avast.app",
                    "/Applications/ClamXav.app"
                ]
                
                for av_tool in av_tools:
                    if Path(av_tool).exists():
                        av_status["installed"] = True
                        av_status["name"] = Path(av_tool).name
                        break
            
            elif self.system_info.os_type == OSType.LINUX:
                # Check for common Linux AV
                av_tools = ["clamav", "clamd", "freshclam"]
                for tool in av_tools:
                    result = subprocess.run(["which", tool], capture_output=True, text=True)
                    if result.returncode == 0:
                        av_status["installed"] = True
                        av_status["name"] = tool
                        break
        
        except Exception as e:
            av_status["details"] = f"Erreur: {e}"
        
        return av_status
    
    def _check_permissions(self) -> Dict[str, Any]:
        """Check file permissions"""
        permissions = {
            "current_user": os.getlogin(),
            "current_uid": os.getuid(),
            "sudo_access": False,
            "writable_paths": []
        }
        
        # Check sudo access
        try:
            result = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=3)
            permissions["sudo_access"] = result.returncode == 0
        except:
            pass
        
        # Check writable paths
        writable_paths = ["/tmp", os.path.expanduser("~")]
        for path in writable_paths:
            if os.access(path, os.W_OK):
                permissions["writable_paths"].append(path)
        
        return permissions
    
    def _check_open_ports(self) -> List[Dict[str, Any]]:
        """Check open ports"""
        open_ports = []
        
        try:
            # Get network connections
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    open_ports.append({
                        "port": conn.laddr.port,
                        "address": conn.laddr.ip,
                        "pid": conn.pid,
                        "process_name": self._get_process_name(conn.pid) if conn.pid else "Unknown"
                    })
        except Exception as e:
            self.ui.show_warning(f"Erreur lors de la vérification des ports: {e}")
        
        return open_ports[:10]  # Limit to first 10 ports
    
    def _check_security_tools(self) -> Dict[str, bool]:
        """Check for security tools"""
        tools = {
            "nmap": False,
            "wireshark": False,
            "tcpdump": False,
            "netcat": False,
            "john": False,
            "hashcat": False,
            "metasploit": False,
            "burp": False
        }
        
        for tool in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=3)
                tools[tool] = result.returncode == 0
            except:
                pass
        
        return tools
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Get network interfaces"""
        interfaces = []
        
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    "name": interface,
                    "addresses": []
                }
                
                for addr in addrs:
                    if addr.family.name in ['AF_INET', 'AF_INET6']:
                        interface_info["addresses"].append({
                            "family": addr.family.name,
                            "address": addr.address,
                            "netmask": addr.netmask
                        })
                
                interfaces.append(interface_info)
        except Exception as e:
            self.ui.show_warning(f"Erreur lors de la détection des interfaces: {e}")
        
        return interfaces
    
    def _get_dns_servers(self) -> List[str]:
        """Get DNS servers"""
        dns_servers = []
        
        try:
            if self.system_info.os_type == OSType.MACOS:
                # macOS DNS configuration
                result = subprocess.run(
                    ["scutil", "--dns"],
                    capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line and ':' in line:
                        dns_servers.append(line.split(':')[1].strip())
            
            elif self.system_info.os_type == OSType.LINUX:
                # Linux DNS configuration
                resolv_conf = Path("/etc/resolv.conf")
                if resolv_conf.exists():
                    with open(resolv_conf) as f:
                        for line in f:
                            if line.startswith('nameserver'):
                                dns_servers.append(line.split()[1])
        except Exception as e:
            self.ui.show_warning(f"Erreur lors de la détection DNS: {e}")
        
        return dns_servers
    
    def _check_internet(self) -> bool:
        """Check internet connectivity"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            return True
        except:
            return False
    
    def _check_localhost_services(self) -> List[Dict[str, Any]]:
        """Check services running on localhost"""
        localhost_services = []
        
        common_ports = {
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            9200: "Elasticsearch",
            5601: "Kibana"
        }
        
        for port, service_name in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                if result == 0:
                    localhost_services.append({
                        "port": port,
                        "service": service_name,
                        "status": "running"
                    })
                sock.close()
            except:
                pass
        
        return localhost_services
    
    def _generate_recommendations(self, verification_results: Dict[str, Any]) -> List[str]:
        """Generate intelligent recommendations based on verification"""
        recommendations = []
        
        # Wazuh recommendations
        wazuh = verification_results["wazuh"]
        if not wazuh["installed"]:
            recommendations.append("🔧 Installer Wazuh pour la surveillance de sécurité")
            recommendations.append("📚 Consulter la documentation officielle: https://documentation.wazuh.com")
        elif wazuh["manager_status"] == ServiceStatus.STOPPED:
            recommendations.append("🚀 Démarrer le service Wazuh Manager")
        
        # Security recommendations
        security = verification_results["security"]
        if not security["firewall"]["enabled"]:
            recommendations.append("🔥 Activer le pare-feu pour améliorer la sécurité")
        
        if not security["antivirus"]["installed"]:
            recommendations.append("🛡️ Installer un antivirus pour une protection complète")
        
        # System recommendations
        system = verification_results["system"]
        if not system["virtual_env"]["active"]:
            recommendations.append("🐍 Utiliser un environnement virtuel Python")
        
        # Services recommendations
        services = verification_results["services"]
        running_services = [name for name, info in services.items() if info.status == ServiceStatus.RUNNING]
        if not running_services:
            recommendations.append("📦 Aucun service de sécurité détecté - envisager d'en installer")
        
        # Network recommendations
        network = verification_results["network"]
        if not network["internet_connectivity"]:
            recommendations.append("🌐 Vérifier la connexion Internet")
        
        return recommendations
    
    # Helper methods
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    
    def _get_pip_version(self) -> str:
        """Get pip version"""
        try:
            result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.split()[1]
        except:
            pass
        return "Unknown"
    
    def _check_virtual_env(self) -> Dict[str, Any]:
        """Check virtual environment status"""
        return {
            "active": hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix),
            "path": sys.prefix,
            "base_prefix": getattr(sys, 'base_prefix', None)
        }
    
    def _get_directory_size(self, path: str) -> str:
        """Get directory size"""
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    total_size += os.path.getsize(filepath)
            return self._format_bytes(total_size)
        except:
            return "Unknown"
    
    def _get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            return psutil.Process(pid).name()
        except:
            return "Unknown"
    
    def display_verification_results(self, results: Dict[str, Any]) -> None:
        """Display comprehensive verification results"""
        self.ui.show_header("📊 Vérification Intelligente Complète")
        
        # System Information
        self._display_system_info(results["system"])
        
        # Wazuh Status
        self._display_wazuh_status(results["wazuh"])
        
        # Services Status
        self._display_services_status(results["services"])
        
        # Security Analysis
        self._display_security_analysis(results["security"])
        
        # Network Analysis
        self._display_network_analysis(results["network"])
        
        # Recommendations
        self._display_recommendations(results["recommendations"])
    
    def _display_system_info(self, system: Dict[str, Any]) -> None:
        """Display system information"""
        self.ui.show_separator("🖥️  Informations Système")
        
        os_info = system["os_info"]
        hardware = system["hardware"]
        python_info = system["python"]
        
        system_data = [
            {"Propriété": "Système d'exploitation", "Valeur": f"{os_info['type']} {os_info['version']}"},
            {"Propriété": "Architecture", "Valeur": os_info['architecture']},
            {"Propriété": "Nom d'hôte", "Valeur": os_info['hostname']},
            {"Propriété": "CPU", "Valeur": f"{hardware['cpu_cores']} cœurs"},
            {"Propriété": "Mémoire totale", "Valeur": hardware['memory_total']},
            {"Propriété": "Espace disque libre", "Valeur": hardware['disk_free']},
            {"Propriété": "Python", "Valeur": python_info['version']},
            {"Propriété": "Environnement virtuel", "Valeur": "✅ Actif" if system['virtual_env']['active'] else "❌ Inactif"}
        ]
        
        self.ui.show_table("Configuration Système", system_data, ["Propriété", "Valeur"])
    
    def _display_wazuh_status(self, wazuh: Dict[str, Any]) -> None:
        """Display Wazuh status"""
        self.ui.show_separator("🛡️  État Wazuh")
        
        if wazuh["installed"]:
            wazuh_data = [
                {"Composant": "Installation", "État": "✅ Installé"},
                {"Composant": "Version détectée", "État": wazuh.get("version", "Inconnue")},
                {"Composant": "Manager", "État": f"✅ {wazuh['manager_status'].value}" if wazuh['manager_status'] != ServiceStatus.NOT_INSTALLED else "❌ Non installé"},
                {"Composant": "Agents", "État": f"{len(wazuh['agents'])} agent(s)"},
                {"Composant": "Processus", "État": f"{len(wazuh.get('processes', []))} processus"},
                {"Composant": "Chemins", "État": f"{len(wazuh['paths_found'])} trouvé(s)"}
            ]
            
            self.ui.show_table("État Wazuh", wazuh_data, ["Composant", "État"])
            
            # Show agents if any
            if wazuh["agents"]:
                agents_data = []
                for agent in wazuh["agents"]:
                    agents_data.append({
                        "ID": agent["id"],
                        "Nom": agent["name"],
                        "IP": agent["ip"],
                        "Clé": agent["key"]
                    })
                self.ui.show_table("Agents Wazuh", agents_data, ["ID", "Nom", "IP", "Clé"])
        else:
            self.ui.show_warning("❌ Wazuh n'est pas installé sur ce système")
            self.ui.show_info("📚 Documentation: https://documentation.wazuh.com")
    
    def _display_services_status(self, services: Dict[str, ServiceInfo]) -> None:
        """Display services status"""
        self.ui.show_separator("🔧 Services de Sécurité")
        
        services_data = []
        for name, info in services.items():
            status_icon = "✅" if info.status == ServiceStatus.RUNNING else "❌"
            memory_info = f" ({info.memory_usage})" if info.memory_usage else ""
            services_data.append({
                "Service": name.title(),
                "État": f"{status_icon} {info.status.value}",
                "PID": str(info.pid) if info.pid else "N/A",
                "Mémoire": info.memory_usage or "N/A"
            })
        
        self.ui.show_table("Services détectés", services_data, ["Service", "État", "PID", "Mémoire"])
    
    def _display_security_analysis(self, security: Dict[str, Any]) -> None:
        """Display security analysis"""
        self.ui.show_separator("🔒 Analyse de Sécurité")
        
        # Firewall
        firewall = security["firewall"]
        firewall_icon = "✅" if firewall["enabled"] else "❌"
        self.ui.show_info(f"Pare-feu: {firewall_icon} {firewall['type']} - {firewall['details']}")
        
        # Antivirus
        av = security["antivirus"]
        av_icon = "✅" if av["installed"] else "❌"
        av_name = av["name"] if av["name"] else "Non installé"
        self.ui.show_info(f"Antivirus: {av_icon} {av_name}")
        
        # Permissions
        perms = security["permissions"]
        sudo_icon = "✅" if perms["sudo_access"] else "❌"
        self.ui.show_info(f"Accès sudo: {sudo_icon} {perms['current_user']}")
        
        # Open ports
        ports = security["open_ports"]
        if ports:
            ports_data = []
            for port in ports[:5]:  # Show first 5
                ports_data.append({
                    "Port": port["port"],
                    "Adresse": port["address"],
                    "Processus": port["process_name"]
                })
            self.ui.show_table("Ports ouverts", ports_data, ["Port", "Adresse", "Processus"])
        
        # Security tools
        tools = security["security_tools"]
        installed_tools = [name for name, installed in tools.items() if installed]
        if installed_tools:
            self.ui.show_info(f"🔧 Outils de sécurité installés: {', '.join(installed_tools)}")
    
    def _display_network_analysis(self, network: Dict[str, Any]) -> None:
        """Display network analysis"""
        self.ui.show_separator("🌐 Analyse Réseau")
        
        # Internet connectivity
        internet_icon = "✅" if network["internet_connectivity"] else "❌"
        self.ui.show_info(f"Connectivité Internet: {internet_icon}")
        
        # DNS servers
        dns = network["dns_servers"]
        if dns:
            self.ui.show_info(f"Serveurs DNS: {', '.join(dns[:3])}")
        
        # Network interfaces
        interfaces = network["interfaces"]
        if interfaces:
            interface_data = []
            for interface in interfaces[:3]:  # Show first 3
                for addr in interface["addresses"]:
                    interface_data.append({
                        "Interface": interface["name"],
                        "Adresse": addr["address"],
                        "Type": addr["family"]
                    })
            self.ui.show_table("Interfaces réseau", interface_data, ["Interface", "Adresse", "Type"])
        
        # Localhost services
        localhost = network["localhost_services"]
        if localhost:
            services_data = []
            for service in localhost:
                services_data.append({
                    "Port": service["port"],
                    "Service": service["service"],
                    "État": service["status"]
                })
            self.ui.show_table("Services locaux", services_data, ["Port", "Service", "État"])
    
    def _display_recommendations(self, recommendations: List[str]) -> None:
        """Display recommendations"""
        self.ui.show_separator("💡 Recommandations Intelligentes")
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                self.ui.show_info(f"{i}. {rec}")
        else:
            self.ui.show_success("✅ Tout semble correctement configuré !")
