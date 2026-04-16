"""
Wazuh Dashboard Configurator
Configuration des dashboards Wazuh via API OpenSearch Dashboards
Dashboard Configurator - Dashboard configuration strategy
"""

import os
import json
import requests
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.logger import WazuhLogger
from ..utils.cache import cached

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DashboardConfigurator(BaseConfigurator):
    """Configuration des dashboards Wazuh via API OpenSearch Dashboards"""
    
    def __init__(self, wazuh_path: str = "/var/ossec"):
        super().__init__(wazuh_path)
        self.paths = WazuhPaths()
        self.dashboard_url = "https://localhost:5601"
        self.dashboard_username = "admin"
        self.dashboard_password = None
        self.verify_ssl = False
        self._logger = WazuhLogger(__name__, use_json=False)
        self.index_pattern = "wazuh-alerts-*"
        
        # Charger les identifiants depuis le fichier de mots de passe Wazuh
        self._load_credentials()
    
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
                                break
        except:
            pass
    
    @cached(ttl=300)
    def check(self) -> ConfigResult:
        """Vérifier la configuration des dashboards"""
        self._logger.info("Vérification de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        # Vérifier la connexion au dashboard
        try:
            connection_ok = self._check_dashboard_connection()
        except Exception as e:
            error_msg = str(e)
            if "Connection refused" in error_msg or "Max retries exceeded" in error_msg:
                self._logger.warning("Dashboard non accessible (service probablement non démarré)")
                return ConfigResult(
                    success=False,
                    message="Dashboards: Service non disponible",
                    details={"dashboard_running": False},
                    warnings=["Dashboard service non démarré - Configuration ignorée"]
                )
            connection_ok = False
        
        # Vérifier les visualisations existantes
        try:
            visualizations_ok = self._check_visualizations()
        except Exception as e:
            self._logger.error(f"Erreur vérification visualisations: {e}")
            visualizations_ok = False
        
        # Vérifier les dashboards existants
        try:
            dashboards_ok = self._check_dashboards()
        except Exception as e:
            self._logger.error(f"Erreur vérification dashboards: {e}")
            dashboards_ok = False
        
        self._logger.info("=" * 60)
        
        success = connection_ok and visualizations_ok and dashboards_ok
        
        return ConfigResult(
            success=success,
            message=f"Dashboards: {'OK' if success else 'Configuration incomplète'}",
            details={
                "dashboard_running": connection_ok,
                "visualizations": visualizations_ok,
                "dashboards": dashboards_ok
            }
        )
    
    def apply(self) -> ConfigResult:
        """Appliquer la configuration des dashboards"""
        self._logger.info("Application de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        # Vérifier d'abord si le dashboard est accessible
        try:
            connection_ok = self._check_dashboard_connection()
            if not connection_ok:
                self._logger.warning("Dashboard non accessible - Configuration ignorée")
                return ConfigResult(
                    success=False,
                    message="Dashboards: Service non disponible",
                    details={"dashboard_running": False},
                    warnings=["Dashboard service non démarré - Configuration ignorée"]
                )
        except Exception as e:
            error_msg = str(e)
            if "Connection refused" in error_msg or "Max retries exceeded" in error_msg:
                self._logger.warning("Dashboard non accessible (service probablement non démarré)")
                return ConfigResult(
                    success=False,
                    message="Dashboards: Service non disponible",
                    details={"dashboard_running": False},
                    warnings=["Dashboard service non démarré - Configuration ignorée"]
                )
        
        results = []
        
        # Créer l'index pattern
        try:
            results.append(self._create_index_pattern())
        except Exception as e:
            self._logger.error(f"Erreur création index pattern: {e}")
            results.append(False)
        
        # Créer les visualisations
        try:
            results.append(self._create_visualizations())
        except Exception as e:
            self._logger.error(f"Erreur création visualisations: {e}")
            results.append(False)
        
        # Créer le dashboard
        try:
            results.append(self._create_dashboard())
        except Exception as e:
            self._logger.error(f"Erreur création dashboard: {e}")
            results.append(False)
        
        self._logger.info("=" * 60)
        
        success_count = sum(1 for r in results if r)
        total_count = len(results)
        
        return ConfigResult(
            success=success_count == total_count,
            message=f"Dashboards: {success_count}/{total_count} configurations appliquées",
            details={
                "index_pattern": results[0],
                "visualizations": results[1],
                "dashboard": results[2]
            }
        )
    
    def validate(self) -> ConfigResult:
        """Valider la configuration des dashboards"""
        self._logger.info("Validation de la configuration des dashboards...")
        self._logger.info("=" * 60)
        
        # Vérifier que l'index pattern existe
        index_ok = self._validate_index_pattern()
        
        # Vérifier que les visualisations existent
        vis_ok = self._validate_visualizations()
        
        # Vérifier que le dashboard existe
        dashboard_ok = self._validate_dashboard()
        
        self._logger.info("=" * 60)
        
        success = index_ok and vis_ok and dashboard_ok
        
        return ConfigResult(
            success=success,
            message=f"Dashboards: {'Validé' if success else 'Validation échouée'}",
            details={
                "index_pattern": index_ok,
                "visualizations": vis_ok,
                "dashboard": dashboard_ok
            }
        )
    
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
        """Vérifier la connexion au dashboard"""
        try:
            url = f"{self.dashboard_url}/api/status"
            response = requests.get(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self._logger.info("[+] Connexion au dashboard: OK")
                return True
            else:
                self._logger.error(f"[-] Connexion au dashboard: Échec (status {response.status_code})")
                return False
        except Exception as e:
            self._logger.error(f"[-] Erreur connexion dashboard: {e}")
            return False
    
    @cached(ttl=300)
    def _check_existing_visualizations(self) -> bool:
        """Vérifier les visualisations existantes"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/_find?type=visualization"
            response = requests.get(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
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
                auth=(self.dashboard_user, self.dashboard_password),
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
            
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                json=body,
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Index pattern créé ou existe déjà")
                return True
            else:
                self._logger.error(f"[-] Erreur création index pattern: {response.status_code}")
                return False
        except Exception as e:
            self._logger.error(f"[-] Erreur création index pattern: {e}")
            return False
    
    def _create_visualizations(self) -> bool:
        """Créer les visualisations pour le dashboard SOC"""
        try:
            self._logger.info("[*] Création des visualisations...")
            
            headers = {
                "osd-xsrf": "true",
                "Content-Type": "application/json"
            }
            
            # Visualisation 1: SSH Events par résultat (Pie Chart)
            vis_ssh_pie = {
                "title": "SSH - Événements par résultat",
                "type": "pie",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {}
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "data.ssh.result",
                            "size": 10,
                            "order": "desc",
                            "orderBy": "_count"
                        }
                    }
                ]
            }
            
            # Créer la visualisation SSH
            url = f"{self.dashboard_url}/api/saved_objects/visualization/ssh-events-result"
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                json={"attributes": vis_ssh_pie},
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Visualisation SSH créée")
            else:
                self._logger.error(f"[-] Erreur création visualisation SSH: {response.status_code}")
                return False
            
            # Visualisation 2: AD Events par type (Pie Chart)
            vis_ad_pie = {
                "title": "AD - Événements par type",
                "type": "pie",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {}
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "data.win.eventdata.id",
                            "size": 10,
                            "order": "desc",
                            "orderBy": "_count"
                        }
                    }
                ]
            }
            
            # Créer la visualisation AD
            url = f"{self.dashboard_url}/api/saved_objects/visualization/ad-events-type"
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                json={"attributes": vis_ad_pie},
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Visualisation AD créée")
            else:
                self._logger.error(f"[-] Erreur création visualisation AD: {response.status_code}")
                return False
            
            # Visualisation 3: Alertes par niveau (Bar Chart)
            vis_level_bar = {
                "title": "Alertes par niveau",
                "type": "histogram",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {}
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "rule.level",
                            "size": 15,
                            "order": "desc",
                            "orderBy": "_count"
                        }
                    }
                ]
            }
            
            # Créer la visualisation niveau
            url = f"{self.dashboard_url}/api/saved_objects/visualization/alerts-level"
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                json={"attributes": vis_level_bar},
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Visualisation alertes niveau créée")
            else:
                self._logger.error(f"[-] Erreur création visualisation niveau: {response.status_code}")
                return False
            
            self._logger.info("[+] Toutes les visualisations créées")
            return True
            
        except Exception as e:
            self._logger.error(f"[-] Erreur création visualisations: {e}")
            return False
    
    def _create_dashboard(self) -> bool:
        """Créer le dashboard SOC"""
        try:
            self._logger.info("[*] Création du dashboard SOC...")
            
            headers = {
                "osd-xsrf": "true",
                "Content-Type": "application/json"
            }
            
            dashboard_config = {
                "title": "SOC - AD & SSH Dashboard",
                "type": "dashboard",
                "panelsJSON": json.dumps([
                    {
                        "id": "ssh-events-result",
                        "type": "pie",
                        "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
                        "panelIndex": 1,
                        "title": "SSH - Événements par résultat"
                    },
                    {
                        "id": "ad-events-type",
                        "type": "pie",
                        "gridData": {"x": 24, "y": 0, "w": 24, "h": 15},
                        "panelIndex": 2,
                        "title": "AD - Événements par type"
                    },
                    {
                        "id": "alerts-level",
                        "type": "histogram",
                        "gridData": {"x": 0, "y": 15, "w": 48, "h": 15},
                        "panelIndex": 3,
                        "title": "Alertes par niveau"
                    }
                ]),
                "optionsJSON": json.dumps({
                    "useMargins": True,
                    "syncColors": False,
                    "hidePanelTitles": False
                }),
                "version": 1
            }
            
            # Références aux visualisations
            references = [
                {"id": "ssh-events-result", "name": "ssh-events-result", "type": "visualization"},
                {"id": "ad-events-type", "name": "ad-events-type", "type": "visualization"},
                {"id": "alerts-level", "name": "alerts-level", "type": "visualization"}
            ]
            
            url = f"{self.dashboard_url}/api/saved_objects/dashboard/soc-ad-ssh"
            body = {
                "attributes": dashboard_config,
                "references": references
            }
            
            response = requests.post(
                url,
                headers=headers,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                json=body,
                timeout=30
            )
            
            if response.status_code in [200, 409]:
                self._logger.info("[+] Dashboard SOC créé")
                return True
            else:
                self._logger.error(f"[-] Erreur création dashboard: {response.status_code}")
                return False
                
        except Exception as e:
            self._logger.error(f"[-] Erreur création dashboard: {e}")
            return False
    
    @cached(ttl=300)
    def _validate_index_pattern(self) -> bool:
        """Valider que l'index pattern existe"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/index-pattern/wazuh-alerts-*"
            response = requests.get(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except:
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
                    auth=(self.dashboard_user, self.dashboard_password),
                    verify=False,
                    timeout=10
                )
                if response.status_code != 200:
                    return False
            return True
        except:
            return False
    
    @cached(ttl=300)
    def _validate_dashboard(self) -> bool:
        """Valider que le dashboard existe"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/dashboard/soc-ad-ssh"
            response = requests.get(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code == 200
        except:
            return False
    
    def _delete_dashboard(self) -> bool:
        """Supprimer le dashboard"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/dashboard/soc-ad-ssh"
            response = requests.delete(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code in [200, 404]
        except:
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
                    auth=(self.dashboard_user, self.dashboard_password),
                    verify=False,
                    timeout=10
                )
                if response.status_code not in [200, 404]:
                    all_deleted = False
            return all_deleted
        except:
            return False
    
    def _delete_index_pattern(self) -> bool:
        """Supprimer l'index pattern"""
        try:
            url = f"{self.dashboard_url}/api/saved_objects/index-pattern/wazuh-alerts-*"
            response = requests.delete(
                url,
                auth=(self.dashboard_user, self.dashboard_password),
                verify=False,
                timeout=10
            )
            return response.status_code in [200, 404]
        except:
            return False
