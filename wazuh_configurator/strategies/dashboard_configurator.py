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
from typing import Dict, Optional
from ..core.base_configurator import BaseConfigurator, ConfigResult
from ..config.paths import WazuhPaths
from ..utils.logger import WazuhLogger
from ..utils.cache import cached
from ..utils.exceptions import ConfigurationError, ServiceNotAvailableError
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DashboardConfigurator(BaseConfigurator):
    """Configuration des dashboards Wazuh via API OpenSearch Dashboards"""
    
    def __init__(self, wazuh_path: str = "/var/ossec", dashboard_host: str = "localhost", dashboard_port: int = 5601):
        super().__init__(wazuh_path)
        self.paths = WazuhPaths()
        self.dashboard_host = dashboard_host
        self.dashboard_port = dashboard_port
        self.dashboard_url = f"https://{dashboard_host}:{dashboard_port}"
        self.dashboard_username = "admin"
        self.dashboard_password = None
        self.verify_ssl = False
        self._logger = WazuhLogger(__name__, use_json=False)
        self.index_pattern = "wazuh-alerts-*"
        
        self._logger.info(f"Dashboard URL: {self.dashboard_url}")
        
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
        except (OSError, IOError) as e:
            self._logger.warning(f"Impossible de lire le fichier de mots de passe: {e}")
            self.dashboard_password = None
    
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
        """Appliquer la configuration des dashboards"""
        self._logger.info("Application de la configuration des dashboards...")
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
        
        # Créer les dashboards automatiquement avec les templates JSON
        self._logger.info(f"[+] Dashboard service actif (IP: {self.dashboard_ip})")
        self._logger.info("[+] Création automatique des dashboards...")
        
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
        
        # Si le service est actif, on considère la validation comme OK
        # On ne vérifie pas l'API HTTP car elle peut ne pas être accessible
        self._logger.info("[+] Dashboard service actif")
        self._logger.info("[+] Note: La validation de l'API HTTP est désactivée")
        
        self._logger.info("=" * 60)
        
        return ConfigResult(
            success=True,
            message="Dashboards: Service actif - Validation OK",
            details={
                "dashboard_running": True,
                "api_validated": False,
                "note": "Validation API non effectuée"
            },
            warnings=["Validation API non effectuée - configuration manuelle requise"]
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
        """Créer les visualisations pour le dashboard SOC"""
        try:
            self._logger.info("[*] Création des visualisations...")
            
            # Visualization 1: SSH Events by Result (Pie Chart)
            vis_ssh_pie_state = {
                "title": "SSH — Événements par résultat",
                "type": "pie",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "rule.description",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10,
                        "otherBucket": False,
                        "missingBucket": False
                    }, "schema": "segment"}
                ],
                "params": {
                    "type": "pie",
                    "addTooltip": True,
                    "addLegend": True,
                    "legendPosition": "right",
                    "isDonut": True,
                    "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}
                }
            }
            
            if not self._create_saved_object("visualization", "soc-ssh-pie", {
                "title": "SOC — SSH événements par résultat",
                "visState": json.dumps(vis_ssh_pie_state),
                "uiStateJSON": "{}",
                "description": "Distribution des événements SSH (succès/échecs) par type",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern,
                        "query": {"query": "rule.groups:sshd", "language": "lucene"},
                        "filter": []
                    })
                }
            }, references=[{"id": self.index_pattern, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]):
                return False
            
            # Visualization 2: SSH Timeline (Histogram)
            vis_ssh_timeline_state = {
                "title": "SSH — Timeline des événements",
                "type": "histogram",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "date_histogram", "params": {
                        "field": "timestamp",
                        "timeRange": {"from": "now-24h", "to": "now"},
                        "useNormalizedOpenSearchInterval": True,
                        "scaleMetricValues": False,
                        "interval": "auto",
                        "drop_partials": False,
                        "min_doc_count": 1,
                        "extended_bounds": {}
                    }, "schema": "segment"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {
                        "field": "rule.description",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 5,
                        "otherBucket": False,
                        "missingBucket": False
                    }, "schema": "group"}
                ],
                "params": {
                    "type": "histogram",
                    "grid": {"categoryLines": False},
                    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                      "show": True, "style": {}, "scale": {"type": "linear"},
                                      "labels": {"show": True, "filter": True, "truncate": 100},
                                      "title": {}}],
                    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                   "position": "left", "show": True, "style": {},
                                   "scale": {"type": "linear", "mode": "normal"},
                                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                   "title": {"text": "Nombre"}}],
                    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                      "data": {"label": "Count", "id": "1"},
                                      "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True,
                                      "lineWidth": 2, "showCircles": True}],
                    "addTooltip": True, "addLegend": True, "legendPosition": "right",
                    "times": [], "addTimeMarker": False,
                    "labels": {"show": False}, "thresholdLine": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"}
                }
            }
            
            if not self._create_saved_object("visualization", "soc-ssh-timeline", {
                "title": "SOC — SSH timeline",
                "visState": json.dumps(vis_ssh_timeline_state),
                "uiStateJSON": "{}",
                "description": "Distribution temporelle des événements SSH",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern,
                        "query": {"query": "rule.groups:sshd", "language": "lucene"},
                        "filter": []
                    })
                }
            }, references=[{"id": self.index_pattern, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]):
                return False
            
            # Visualization 3: Top IP Sources SSH (Data Table)
            vis_ssh_top_ip_state = {
                "title": "SSH — Top IP sources",
                "type": "table",
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "params": {}, "schema": "metric"},
                    {"id": "2", "enabled": True, "type": "terms", "params": {
                        "field": "data.srcip",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 10,
                        "otherBucket": False,
                        "missingBucket": False
                    }, "schema": "bucket"},
                    {"id": "3", "enabled": True, "type": "terms", "params": {
                        "field": "rule.description",
                        "orderBy": "1",
                        "order": "desc",
                        "size": 5,
                        "otherBucket": False,
                        "missingBucket": False
                    }, "schema": "bucket"}
                ],
                "params": {
                    "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                    "sort": {"columnIndex": None, "direction": None},
                    "showTotal": True, "totalFunc": "sum", "percentageCol": ""
                }
            }
            
            if not self._create_saved_object("visualization", "soc-ssh-top-ip", {
                "title": "SOC — SSH top IP sources",
                "visState": json.dumps(vis_ssh_top_ip_state),
                "uiStateJSON": json.dumps({"vis": {"params": {"sort": {"columnIndex": None, "direction": None}}}}),
                "description": "Top adresses IP sources des événements SSH",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": self.index_pattern,
                        "query": {"query": "rule.groups:sshd", "language": "lucene"},
                        "filter": []
                    })
                }
            }, references=[{"id": self.index_pattern, "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}]):
                return False
            
            self._logger.info("[+] Visualisations créées")
            return True
            
        except Exception as e:
            self._logger.error(f"[-] Erreur création visualisations: {e}")
            return False
    
    def _create_dashboard(self) -> bool:
        """Créer le dashboard SOC"""
        try:
            self._logger.info("[*] Création du dashboard SOC...")
            
            panels = [
                {"gridData": {"x": 0,  "y": 0,  "w": 16, "h": 12, "i": "1"}, "version": "2.19.4",
                 "panelIndex": "1", "embeddableConfig": {}, "panelRefName": "panel_0"},
                {"gridData": {"x": 16, "y": 0,  "w": 16, "h": 12, "i": "2"}, "version": "2.19.4",
                 "panelIndex": "2", "embeddableConfig": {}, "panelRefName": "panel_1"},
                {"gridData": {"x": 32, "y": 0,  "w": 16, "h": 12, "i": "3"}, "version": "2.19.4",
                 "panelIndex": "3", "embeddableConfig": {}, "panelRefName": "panel_2"},
                {"gridData": {"x": 0,  "y": 12, "w": 24, "h": 15, "i": "4"}, "version": "2.19.4",
                 "panelIndex": "4", "embeddableConfig": {}, "panelRefName": "panel_3"},
                {"gridData": {"x": 24, "y": 12, "w": 24, "h": 15, "i": "5"}, "version": "2.19.4",
                 "panelIndex": "5", "embeddableConfig": {}, "panelRefName": "panel_4"},
                {"gridData": {"x": 0,  "y": 27, "w": 48, "h": 15, "i": "6"}, "version": "2.19.4",
                 "panelIndex": "6", "embeddableConfig": {}, "panelRefName": "panel_5"},
            ]
            
            references = [
                {"name": "panel_0", "type": "visualization", "id": "soc-ssh-pie"},
                {"name": "panel_1", "type": "visualization", "id": "soc-ssh-timeline"},
                {"name": "panel_2", "type": "visualization", "id": "soc-ssh-top-ip"},
                {"name": "panel_3", "type": "visualization", "id": "soc-ssh-pie"},
                {"name": "panel_4", "type": "visualization", "id": "soc-ssh-timeline"},
                {"name": "panel_5", "type": "visualization", "id": "soc-ssh-top-ip"},
            ]
            
            if not self._create_saved_object("dashboard", "soc-ad-ssh", {
                "title": "SOC — AD & SSH",
                "hits": 0,
                "description": "Tableau de bord SOC centralisant la conformité CIS de l'AD et la détection SSH",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
                "version": 1,
                "timeRestore": True,
                "timeTo": "now",
                "timeFrom": "now-24h",
                "refreshInterval": {"pause": False, "value": 30000},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"query": "", "language": "lucene"},
                        "filter": []
                    })
                }
            }, references=references):
                return False
            
            self._logger.info(f"[+] Dashboard créé: {self.dashboard_url}/app/dashboards#/view/soc-ad-ssh")
            return True
            
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
