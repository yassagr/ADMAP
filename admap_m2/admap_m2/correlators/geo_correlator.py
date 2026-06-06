"""
Module   : admap_m2.correlators.geo_correlator
Version  : 1.0.0
Dépend   : [admap_m2.correlators.base]
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
    Enrichissement géographique des IPs (Optionnel).
    """

    @property
    def correlator_name(self) -> str:
        return "geo_correlator"

    def __init__(self, settings):
        super().__init__(settings)
        self.reader = None
        if GEOIP_AVAILABLE and self._settings.GEOIP_DB_PATH:
            try:
                self.reader = geoip2.database.Reader(self._settings.GEOIP_DB_PATH)
            except Exception as e:
                self._logger.warning("geoip_db_load_failed", error=str(e))

    def _get_country(self, ip: str) -> str:
        if not self.reader:
            return "Unknown"
        try:
            response = self.reader.country(ip)
            return response.country.iso_code or "Unknown"
        except Exception:
            return "Unknown"

    def correlate(self, flows: list[NetworkFlow], alerts: list[C2Alert]) -> list[C2Alert]:
        if not self.reader:
            return []

        # Enrich the alerts directly
        for alert in alerts:
            src_country = self._get_country(alert.src_ip)
            dst_country = self._get_country(alert.dst_ip)
            
            # Since Pydantic model is frozen, we must copy to modify or use __setattr__ if we bypass
            # However, metadata is a mutable dict, so we can modify it directly
            alert.metadata["src_country"] = src_country
            alert.metadata["dst_country"] = dst_country

        return []
