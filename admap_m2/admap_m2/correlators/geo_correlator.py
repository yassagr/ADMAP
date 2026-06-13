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
    import geoip2.database  # type: ignore[import-not-found]
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
        Enrichissement géo informatif — journalise le pays source et
        destination de chaque alerte si une base GeoIP est chargée.

        Ne retourne JAMAIS de nouvelle alerte : C2Alert est frozen=True
        et ne peut pas être muté. L'enrichissement est uniquement
        journalisé via structlog (exploitable par le SIEM/dashboard en
        aval, qui peut recouper alert_id ↔ pays dans les logs).

        Args:
            flows: Flux réseau (non utilisés directement — signature
                imposée par BaseCorrelator).
            alerts: Alertes existantes à enrichir (lecture seule).

        Returns:
            Liste vide (aucune nouvelle alerte créée).
        """
        if not self.reader:
            return []

        for alert in alerts:
            self._logger.info(
                "geo_enrichment",
                alert_id=str(alert.id),
                alert_type=alert.alert_type.value,
                src_ip=alert.src_ip,
                src_country=self.get_country(alert.src_ip),
                dst_ip=alert.dst_ip,
                dst_country=self.get_country(alert.dst_ip),
            )

        return []
