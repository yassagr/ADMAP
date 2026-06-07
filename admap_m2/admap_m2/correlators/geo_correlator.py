"""
Module   : admap_m2.correlators.geo_correlator
Version  : 1.0.0
Dépend   : [admap_m2.correlators.base, geoip2 (optionnel)]
"""
from __future__ import annotations

from admap_m2.correlators.base import BaseCorrelator
from admap_m2.models.alert import C2Alert
from admap_m2.models.flow import NetworkFlow

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False


class GeoCorrelator(BaseCorrelator):
    """
    Enrichissement géographique des IPs (optionnel).
    Ne génère pas de nouvelles alertes — rôle informatif uniquement.
    """

    @property
    def correlator_name(self) -> str:
        return "geo_correlator"

    def __init__(self, settings) -> None:
        super().__init__(settings)
        self.reader = None
        if GEOIP_AVAILABLE and self._settings.GEOIP_DB_PATH:
            try:
                self.reader = geoip2.database.Reader(self._settings.GEOIP_DB_PATH)
                self._logger.info("geoip_db_loaded", path=self._settings.GEOIP_DB_PATH)
            except Exception as e:
                self._logger.warning("geoip_db_load_failed", error=str(e))

    def get_country(self, ip: str) -> str:
        """
        Retourne le code pays ISO d'une IP.

        Args:
            ip: Adresse IP à géolocaliser.

        Returns:
            Code ISO à 2 lettres ou "Unknown".
        """
        if not self.reader:
            return "Unknown"
        try:
            response = self.reader.country(ip)
            return response.country.iso_code or "Unknown"
        except Exception:
            return "Unknown"

    def correlate(self, flows: list[NetworkFlow], alerts: list[C2Alert]) -> list[C2Alert]:
        """
        Enrichissement géo — ne retourne aucune nouvelle alerte.
        C2Alert est frozen=True et ne peut pas être muté.

        Args:
            flows: Flux réseau.
            alerts: Alertes existantes.

        Returns:
            Liste vide (aucune nouvelle alerte créée).
        """
        return []
