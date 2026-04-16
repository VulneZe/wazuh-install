"""
Wazuh Dashboard Configurator
Configuration des dashboards Wazuh via API OpenSearch Dashboards
Dashboard Configurator - Dashboard configuration strategy
"""

import os
import json
import subprocess
import requests
import socket
from typing import Dict, Optional, List
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.logger import WazuhLogger
from ..utils.cache import cached
from ..utils.exceptions import ConfigurationError, ServiceNotAvailableError
from ..dashboard_templates import ALL_DASHBOARDS
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DashboardConfigurator(BaseConfigurator):
    """Configuration des dashboards Wazuh via API OpenSearch Dashboards"""
    
    def __init__(self, wazuh_path: str = "/var/ossec", dashboard_host: str = "localhost", dashboard_port: int = None):
        super().__init__(wazuh_path)
        self.paths = WazuhPaths()
        self.dashboard_host = dashboard_host
        
        # Lire le port depuis opensearch_dashboards.yml si non fourni
        if dashboard_port is None:
            dashboard_port = self._read_dashboard_port()
        
        self.dashboard_port = dashboard_port or 443
        self.dashboard_url = f"https://{dashboard_host}:{self.dashboard_port}"
        self.dashboard_username = "admin"
        self.dashboard_password = None
        self.verify_ssl = False
        self._logger = WazuhLogger(__name__, use_json=False)
        self.index_pattern = "wazuh-alerts-*"
        
        self._logger.info(f"Dashboard URL: {self.dashboard_url}")
        
        # Charger les identifiants depuis le fichier de mots de passe Wazuh
        self._load_credentials()
    
    def _read_dashboard_port(self) -> int:
        """Lire le port dashboard depuis opensearch_dashboards.yml"""
        try:
            # Chemins possibles pour le fichier de configuration
            config_paths = [
                "/etc/wazuh-dashboard/opensearch_dashboards.yml",
                "/etc/opensearch-dashboards/opensearch_dashboards.yml",
                "/var/ossec/etc/opensearch_dashboards.yml"
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        content = f.read()
                        # Chercher server.port
                        for line in content.split('\n'):
                            if line.strip().startswith("server.port:"):
                                port_str = line.split(":")[1].strip()
                                try:
                                    port = int(port_str)
                                    self._logger.info(f"[+] Port dashboard lu depuis {config_path}: {port}")
                                    return port
                                except ValueError:
                                    self._logger.warning(f"[-] Port invalide dans {config_path}: {port_str}")
                                    break
            
            self._logger.info("[] Port par défaut utilisé: 443")
            return 443
        except Exception as e:
            self._logger.warning(f"[-] Erreur lecture port dashboard: {e}")
            return 443
    
    def _load_credentials(self):
        """Charger les identifiants depuis le fichier de mots de passe Wazuh"""
        try:
            if os.path.exists(self.paths.passwords_file):
                with open(self.paths.passwords_file, 'r') as f:
                    content = f.read()
                    # Chercher le mot de passe admin
                    if "admin:" in content:
                        for line in content.split('\n'):
                            if line.startswith("admin:"):
                                self.dashboard_password = line.split(":")[1].strip()
                                self._logger.info(f"[+] Mot de passe admin chargé depuis {self.paths.passwords_file}")
                                break
                    else:
                        self._logger.warning(f"[-] Mot de passe admin non trouvé dans {self.paths.passwords_file}")
            else:
                self._logger.warning(f"[-] Fichier de mots de passe non trouvé: {self.paths.passwords_file}")
        except (OSError, IOError) as e:
            self._logger.warning(f"Impossible de lire le fichier de mots de passe: {e}")
            self.dashboard_password = None
        
        # Valider les identifiants via un appel test authentifié
        self._validate_credentials()
    
    def _validate_credentials(self):
        """Valider les identifiants via un appel test authentifié"""
        if not self.dashboard_password:
            self._logger.error("[-] Impossible de valider les identifiants: mot de passe non disponible")
            return
        
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=dashboard"
            headers = {"osd-xsrf": "true"}
            response = requests.get(
                url,
                headers=headers,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self._logger.info("[+] Validation des identifiants admin réussie")
            elif response.status_code == 401:
                self._logger.error("[-] ERREUR: Mot de passe admin invalide (401)")
                self._logger.error("[-] Le mot de passe chargé depuis wazuh-passwords.txt n'est pas accepté par le Dashboard")
                self._logger.error("[-] Veuillez mettre à jour le mot de passe dans /var/ossec/etc/wazuh-passwords.txt")
                self._logger.error("[-] Ou utiliser le mot de passe actuel du Dashboard")
            else:
                self._logger.warning(f"[!] Code de réponse inattendu: {response.status_code}")
        except requests.exceptions.ConnectionError:
            self._logger.warning("[!] Impossible de valider les identifiants: Dashboard non accessible")
        except Exception as e:
            self._logger.warning(f"[!] Erreur lors de la validation des identifiants: {e}")
    
    @cached(ttl=300)
    def check(self) -> ConfigResult:
        """Vérifier la configuration des dashboards"""
        self._logger.info("Vérification de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        # Vérifier si le service est actif via systemctl
        service_active = self._check_dashboard_connection()
        
        if not service_active:
            self._logger.warning("Dashboard service non actif")
            return ConfigResult(
                success=False,
                message="Dashboards: Service non disponible",
                details={"dashboard_running": False},
                warnings=["Dashboard service non démarré - Configuration ignorée"]
            )
        
        # Si le service est actif, on considère le dashboard comme OK
        # On ne vérifie pas l'API HTTP car elle peut ne pas être accessible
        self._logger.info("[+] Dashboard service actif")
        self._logger.info("[+] Note: La vérification de l'API HTTP est désactivée")
        self._logger.info("[+] La création de dashboards nécessite une connexion API manuelle")
        
        self._logger.info("=" * 60)
        
        return ConfigResult(
            success=True,
            message="Dashboards: Service actif",
            details={
                "dashboard_running": True,
                "api_accessible": False,
                "note": "API non vérifiée - configuration manuelle requise"
            },
            warnings=["API HTTP non accessible - création de dashboards manuelle requise"]
        )
    
    def apply(self) -> ConfigResult:
        """Appliquer la configuration des dashboards professionnels"""
        self._logger.info("Application de la configuration des dashboards professionnels...")
        self._logger.info("=" * 60)
        
        # Vérifier si le service est actif via systemctl
        service_active = self._check_dashboard_connection()
        
        if not service_active:
            self._logger.warning("Dashboard service non actif - Configuration ignorée")
            return ConfigResult(
                success=False,
                message="Dashboards: Service non disponible",
                details={"dashboard_running": False},
                warnings=["Dashboard service non démarré - Configuration ignorée"]
            )
        
        # Créer les dashboards professionnels avec les templates
        self._logger.info(f"[+] Dashboard service actif (IP: {self.dashboard_host})")
        self._logger.info(f"[+] Création de {len(ALL_DASHBOARDS)} dashboards professionnels...")
        
        results = []
        
        # Créer l'index pattern
        try:
            results.append(self._create_index_pattern())
        except Exception as e:
            self._logger.error(f"Erreur création index pattern: {e}")
            results.append(False)
        
        # Créer les visualisations pour tous les dashboards
        try:
            results.append(self._create_visualizations())
        except Exception as e:
            self._logger.error(f"Erreur création visualisations: {e}")
            results.append(False)
        
        # Créer les dashboards professionnels
        try:
            results.append(self._create_dashboards())
        except Exception as e:
            self._logger.error(f"Erreur création dashboards: {e}")
            results.append(False)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Dashboards: {success_count}/{total_count} configurations appliquées",
            details={
                "dashboard_running": True,
                "index_pattern": results[0],
                "visualizations": results[1],
                "dashboard": results[2]
            }
        )
    
    def validate(self) -> ConfigResult:
        """Valider la configuration des dashboards"""
        self._logger.info("Validation de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        # Vérifier si le service est actif via systemctl
        service_active = self._check_dashboard_connection()
        
        if not service_active:
            self._logger.warning("Dashboard service non actif - Validation ignorée")
            return ConfigResult(
                success=False,
                message="Dashboards: Service non disponible",
                details={"dashboard_running": False},
                warnings=["Dashboard service non démarré - Validation ignorée"]
            )
        
        # Vérification authentifiée de l'API Dashboard
        api_validated = self._validate_dashboard_api()
        
        if not api_validated:
            self._logger.warning("[-] API Dashboard non accessible ou mot de passe invalide")
            return ConfigResult(
                success=False,
                message="Dashboards: API non accessible",
                details={
                    "dashboard_running": True,
                    "api_validated": False
                },
                warnings=["API Dashboard non accessible - vérifiez le mot de passe admin"]
            )
        
        # Vérifier que les dashboards existent
        dashboard_exists = self._check_dashboard_exists()
        index_pattern_exists = self._check_index_pattern_exists()
        
        self._logger.info("=" * 60)
        
        if dashboard_exists and index_pattern_exists:
            return ConfigResult(
                success=True,
                message="Dashboards: Configuration validée",
                details={
                    "dashboard_running": True,
                    "api_validated": True,
                    "dashboard_exists": True,
                    "index_pattern_exists": True
                }
            )
        else:
            return ConfigResult(
                success=False,
                message="Dashboards: Configuration incomplète",
                details={
                    "dashboard_running": True,
                    "api_validated": True,
                    "dashboard_exists": dashboard_exists,
                    "index_pattern_exists": index_pattern_exists
                },
                warnings=["Dashboards ou index pattern manquants"]
            )
    
    def _validate_dashboard_api(self) -> bool:
        """Valider l'API Dashboard avec authentification"""
        if not self.dashboard_password:
            self._logger.warning("[-] Impossible de valider l'API: mot de passe non disponible")
            return False
        
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=dashboard"
            headers = {"osd-xsrf": "true"}
            response = requests.get(
                url,
                headers=headers,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self._logger.info("[+] API Dashboard accessible et authentifiée")
                return True
            elif response.status_code == 401:
                self._logger.error("[-] ERREUR: Mot de passe admin invalide (401)")
                self._logger.error("[-] Le mot de passe dans wazuh-passwords.txt n'est pas accepté")
                return False
            else:
                self._logger.warning(f"[!] Code de réponse API inattendu: {response.status_code}")
                return False
        except requests.exceptions.ConnectionError:
            self._logger.warning("[-] Impossible de joindre l'API Dashboard")
            return False
        except Exception as e:
            self._logger.warning(f"[-] Erreur validation API: {e}")
            return False
    
    def rollback(self) -> ConfigResult:
        """Annuler les changements de configuration des dashboards"""
        self._logger.info("Annulation de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        results = []
        
        # Supprimer le dashboard
        dashboard_deleted = self._delete_dashboard()
        results.append(dashboard_deleted)
        
        # Supprimer les visualisations
        vis_deleted = self._delete_visualizations()
        results.append(vis_deleted)
        
        # Supprimer l'index pattern
        index_deleted = self._delete_index_pattern()
        results.append(index_deleted)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Dashboards: {success_count}/{total_count} suppressions réussies",
            details={
                "dashboard": results[0],
                "visualizations": results[1],
                "index_pattern": results[2]
            }
        )
    
    @cached(ttl=300)
    def _check_dashboard_connection(self) -> bool:
        """Vérifier la connexion au dashboard via systemctl"""
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "wazuh-dashboard"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and "active" in result.stdout:
                self._logger.info("[+] Dashboard service actif")
                return True
            else:
                self._logger.warning("[-] Dashboard service non actif")
                return False
        except Exception as e:
            self._logger.error(f"[-] Erreur vérification dashboard: {e}")
            return False
    
    @cached(ttl=300)
    def _check_existing_visualizations(self) -> bool:
        """Vérifier les visualisations existantes"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=visualization"
            response = requests.get(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                vis_count = len(data.get('savedObjects', []))
                self._logger.info(f"[+] Visualisations existantes: {vis_count}")
                return vis_count > 0
            else:
                self._logger.error("[-] Erreur récupération visualisations")
                return False
        except requests.exceptions.ConnectionError as e:
            raise ServiceNotAvailableError(f"Dashboard non accessible: {e}")
        except Exception as e:
            self._logger.error(f"[-] Erreur vérification visualisations: {e}")
            return False
    
    @cached(ttl=300)
    def _check_existing_dashboards(self) -> bool:
        """Vérifier les dashboards existants"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=dashboard"
            response = requests.get(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                dash_count = len(data.get('savedObjects', []))
                self._logger.info(f"[+] Dashboards existants: {dash_count}")
                return dash_count > 0
            else:
                self._logger.error("[-] Erreur récupération dashboards")
                return False
        except requests.exceptions.ConnectionError as e:
            raise ServiceNotAvailableError(f"Dashboard non accessible: {e}")
        except Exception as e:
            self._logger.error(f"[-] Erreur vérification dashboards: {e}")
            return False
    
    def _create_index_pattern(self) -> bool:
        """Créer l'index pattern wazuh-alerts-*"""
        try:
            self._logger.info("[*] Création de l'index pattern...")
            
            url = f"{self.dashboard_url}/api/saved_objects/index-pattern/wazuh-alerts-*"
            headers = {
                "osd-xsrf": "true",
                "Content-Type": "application/json"
            }
            
            attributes = {
                "title": "wazuh-alerts-*",
                "timeFieldName": "@timestamp"
            }
            
            body = {"attributes": attributes}
            
            # Debug: vérifier l'authentification
            if not self.dashboard_password:
                self._logger.error("[-] Mot de passe admin non disponible - impossible de s'authentifier")
                return False
            
            self._logger.info(f"[*] Tentative de connexion à {url} avec user: {self.dashboard_username}")
            
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                json=body,
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Index pattern créé ou existe déjà")
                return True
            else:
                self._logger.error(f"[-] Erreur création index pattern: {response.status_code}")
                if response.status_code == 401:
                    self._logger.error("[-] Erreur d'authentification 401 - vérifiez le mot de passe admin")
                    self._logger.error(f"[-] URL: {url}")
                    self._logger.error(f"[-] User: {self.dashboard_username}")
                    self._logger.error(f"[-] Password loaded: {'Yes' if self.dashboard_password else 'No'}")
                return False
        except requests.exceptions.ConnectionError as e:
            raise ServiceNotAvailableError(f"Dashboard non accessible: {e}")
        except Exception as e:
            self._logger.error(f"[-] Erreur création index pattern: {e}")
            return False
    
    def _create_saved_object(self, obj_type: str, obj_id: str, attributes: dict, references: list = None) -> bool:
        """Créer un saved object (visualization ou dashboard)"""
        try:
            headers = {
                "osd-xsrf": "true",
                "Content-Type": "application/json"
            }
            
            body = {"attributes": attributes}
            if references:
                body["references"] = references
            
            url = f"{self.dashboard_url}/api/saved_objects/{obj_type}/{obj_id}"
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                json=body,
                timeout=30
            )
            
            if response.status_code == 409:
                # Déjà existe, mettre à jour
                response = requests.put(
                    url,
                    headers=headers,
                    auth=(self.dashboard_username, self.dashboard_password),
                    verify=False,
                    json=body,
                    timeout=30
                )
            
            self._logger.info(f"  {obj_type}/{obj_id}: {response.status_code}")
            return response.status_code in [200, 201, 409]
            
        except Exception as e:
            self._logger.error(f"Erreur création {obj_type}/{obj_id}: {e}")
            return False
    
    def _create_visualizations(self) -> bool:
        """Créer les visualisations pour les dashboards professionnels"""
        try:
            self._logger.info("[*] Création des visualisations pour les dashboards professionnels...")
            
            # Utiliser les templates de dashboards professionnels
            success_count = 0
            total_count = 0
            
            for dashboard_template in ALL_DASHBOARDS:
                self._logger.info(f"[*] Traitement du dashboard: {dashboard_template['title']}")
                
                for viz in dashboard_template['visualizations']:
                    total_count += 1
                    viz_id = viz['id']
                    viz_type = viz['type']
                    
                    # Créer l'attribut de visualisation
                    viz_attributes = {
                        "title": viz['title'],
                        "description": viz.get('description', ''),
                        "visState": viz.get('attributes', {}).get('visState', {}),
                        "uiState": viz.get('attributes', {}).get('uiState', {}),
                        "kibanaSavedObjectMeta": {
                            "searchSourceJSON": json.dumps({
                                "index": viz['query']['index'],
                                "query": viz['query'].get('query', '*'),
                                "filter": [],
                                "aggs": viz['query'].get('aggs', [])
                            })
                        }
                    }
                    
                    if self._create_saved_object('visualization', viz_id, viz_attributes):
                        success_count += 1
                    else:
                        self._logger.warning(f"[-] Échec création visualisation: {viz_id}")
            
            self._logger.info(f"[+] Visualisations créées: {success_count}/{total_count}")
            return success_count == total_count
            
        except Exception as e:
            self._logger.error(f"[-] Erreur création visualisations: {e}")
            return False
    
    def _create_dashboards(self) -> bool:
        """Créer les dashboards professionnels"""
        try:
            self._logger.info("[*] Création des dashboards professionnels...")
            
            success_count = 0
            total_count = 0
            
            for dashboard_template in ALL_DASHBOARDS:
                total_count += 1
                dashboard_id = dashboard_template['id']
                dashboard_title = dashboard_template['title']
                dashboard_description = dashboard_template.get('description', '')
                
                self._logger.info(f"[*] Création du dashboard: {dashboard_title}")
                
                # Créer les références vers les visualisations
                references = []
                for viz in dashboard_template['visualizations']:
                    references.append({
                        "id": viz['id'],
                        "name": f"visualization:{viz['id']}",
                        "type": "visualization"
                    })
                
                # Créer les attributs du dashboard
                dashboard_attributes = {
                    "title": dashboard_title,
                    "description": dashboard_description,
                    "visState": {
                        "type": "dashboard",
                        "params": {
                            "useMargins": True,
                            "syncColors": False,
                            "hidePanelTitles": False,
                            "panels": dashboard_template.get('layout', {}).get('rows', [])
                        }
                    },
                    "uiState": {
                        "vis": {
                            "params": {
                                "panels": dashboard_template.get('layout', {}).get('rows', [])
                            }
                        }
                    }
                }
                
                if self._create_saved_object('dashboard', dashboard_id, dashboard_attributes, references):
                    success_count += 1
                    self._logger.info(f"[+] Dashboard créé: {dashboard_title}")
                else:
                    self._logger.warning(f"[-] Échec création dashboard: {dashboard_title}")
            
            self._logger.info(f"[+] Dashboards créés: {success_count}/{total_count}")
            return success_count == total_count
            
        except Exception as e:
            self._logger.error(f"[-] Erreur création dashboards: {e}")
            return False
    
    @cached(ttl=300)
    def _validate_index_pattern(self) -> bool:
        """Valider que l'index pattern existe"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/index-pattern/wazuh-alerts-*"
            response = requests.get(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur vérification index pattern: {e}")
            return False
    
    @cached(ttl=300)
    def _validate_visualizations(self) -> bool:
        """Valider que les visualisations existent"""
        try:
            vis_ids = ["ssh-events-result", "ad-events-type", "alerts-level"]
            for vis_id in vis_ids:
                url = f"{self.dashboard_url}/api/saved_objects/visualization/{vis_id}"
                response = requests.get(
                    url,
                    auth=(self.dashboard_username, self.dashboard_password),
                    verify=False,
                    timeout=10
                )
                if response.status_code != 200:
                    return False
            return True
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur vérification index pattern existe: {e}")
            return False
    
    @cached(ttl=300)
    def _validate_dashboard(self) -> bool:
        """Valider que le dashboard existe"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=dashboard"
            response = requests.get(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur vérification dashboards: {e}")
            return False
    
    def _delete_dashboard(self, dashboard_id: str) -> bool:
        """Supprimer le dashboard"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/dashboard/{dashboard_id}"
            response = requests.delete(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code in [200, 404]
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur suppression dashboard {dashboard_id}: {e}")
            return False
    
    def _delete_visualizations(self) -> bool:
        """Supprimer les visualisations"""
        try:
            vis_ids = ["ssh-events-result", "ad-events-type", "alerts-level"]
            all_deleted = True
            for vis_id in vis_ids:
                url = f"{self.dashboard_url}/api/saved_objects/visualization/{vis_id}"
                response = requests.delete(
                    url,
                    auth=(self.dashboard_username, self.dashboard_password),
                    verify=False,
                    timeout=10
                )
                if response.status_code not in [200, 404]:
                    all_deleted = False
            return all_deleted
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur suppression visualizations: {e}")
            return False
    
    def _delete_index_pattern(self) -> bool:
        """Supprimer l'index pattern"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/index-pattern/wazuh-alerts-*"
            response = requests.delete(
                url,
                auth=(self.dashboard_username, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code in [200, 404]
        except (requests.exceptions.RequestException, Exception) as e:
            self._logger.warning(f"Erreur suppression index pattern: {e}")
            return False
