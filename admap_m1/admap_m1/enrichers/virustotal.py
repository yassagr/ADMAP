"""
Module   : admap_m1.enrichers.virustotal
Version  : 3.0.0
Dépend   : [httpx, asyncio, admap_m1.enrichers.base, admap_m1.core.config]

Enrichisseur VirusTotal asynchrone avec gestion stricte des quotas,
backoff exponentiel et cache local.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import httpx

from admap_m1.core.config import get_settings
from admap_m1.core.exceptions import VTAPIKeyError, VTRateLimitError
from admap_m1.enrichers.base import BaseEnricher
from admap_m1.models.ioc import IOC, IOCType, VTResult


class VirusTotalEnricher(BaseEnricher):
    """Service d'enrichissement asynchrone utilisant l'API VirusTotal v3."""

    # Correspondance IOCType -> Endpoint API VT v3
    ENDPOINTS = {
        IOCType.IPV4: "ip_addresses",
        IOCType.IPV6: "ip_addresses",
        IOCType.DOMAIN: "domains",
        IOCType.URL: "urls",
        IOCType.HASH_MD5: "files",
        IOCType.HASH_SHA1: "files",
        IOCType.HASH_SHA256: "files",
    }

    def __init__(self, api_key: str | None = None) -> None:
        super().__init__()
        self.settings = get_settings()
        self.api_key = api_key or self.settings.VT_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.max_retries = self.settings.VT_MAX_RETRIES
        self.timeout = self.settings.VT_TIMEOUT_SECONDS
        
        # Limites selon le type de compte
        self.concurrency_limit = 100 if self.settings.VT_IS_PREMIUM else 4
        self.semaphore = asyncio.Semaphore(self.concurrency_limit)
        
        # Cache local rudimentaire (en production, utiliser Redis)
        self._cache: dict[str, VTResult] = {}
        self._load_cache()

    @property
    def enricher_name(self) -> str:
        return "virustotal"

    async def enrich_bulk(self, iocs: list[IOC]) -> None:
        """Enrichit la liste d'IOCs de manière concurrente."""
        if not self.api_key:
            self._logger.warning("vt_api_key_missing_skipping_enrichment")
            return

        # Filtrer et limiter les requêtes par type selon la spec (VT_MAX_PER_TYPE)
        to_enrich: list[IOC] = []
        counts: dict[IOCType, int] = defaultdict(int)

        for ioc in iocs:
            if ioc.type not in self.ENDPOINTS:
                continue
            if counts[ioc.type] >= self.settings.VT_MAX_PER_TYPE:
                continue
            to_enrich.append(ioc)
            counts[ioc.type] += 1

        if not to_enrich:
            return

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        async with httpx.AsyncClient(headers=headers, timeout=self.timeout) as client:
            tasks = [self._enrich_single(client, ioc) for ioc in to_enrich]
            await asyncio.gather(*tasks, return_exceptions=True)

        self._save_cache()

    async def _enrich_single(self, client: httpx.AsyncClient, ioc: IOC) -> None:
        """Traite un seul IOC avec retries et gestion de cache."""
        # 1. Vérifier le cache
        cache_key = f"{ioc.type.value}:{ioc.value}"
        if cache_key in self._cache:
            object.__setattr__(ioc, "vt_result", self._cache[cache_key])
            self._logger.debug("vt_cache_hit", ioc=ioc.value)
            return

        # 2. Construire l'URL
        endpoint = self.ENDPOINTS[ioc.type]
        if ioc.type == IOCType.URL:
            # L'API v3 demande un base64url sans padding pour les URLs
            b64_url = base64.urlsafe_b64encode(ioc.value.encode()).decode().strip("=")
            identifier = b64_url
        else:
            identifier = ioc.value

        url = f"{self.base_url}/{endpoint}/{identifier}"

        # 3. Requête avec retry
        for attempt in range(self.max_retries):
            try:
                async with self.semaphore:
                    response = await client.get(url)

                if response.status_code == 200:
                    vt_res = self._parse_response(response.json(), ioc)
                    object.__setattr__(ioc, "vt_result", vt_res)
                    self._cache[cache_key] = vt_res
                    return

                elif response.status_code == 404:
                    # Non trouvé sur VT
                    vt_res = VTResult(
                        value=ioc.value,
                        ioc_type=ioc.type.value,
                        found=False,
                        verdict="UNKNOWN"
                    )
                    object.__setattr__(ioc, "vt_result", vt_res)
                    self._cache[cache_key] = vt_res
                    return

                elif response.status_code == 401:
                    self._logger.error("vt_api_key_invalid")
                    raise VTAPIKeyError("Invalid VirusTotal API Key")

                elif response.status_code == 429:
                    self._logger.warning("vt_rate_limit_hit", attempt=attempt+1)
                    if attempt == self.max_retries - 1:
                        raise VTRateLimitError("VirusTotal rate limit exceeded")
                    await asyncio.sleep(2 ** attempt)  # Backoff exponentiel
                    continue

                else:
                    self._logger.warning(
                        "vt_http_error",
                        status_code=response.status_code,
                        ioc=ioc.value
                    )
                    return

            except httpx.RequestError as e:
                self._logger.warning("vt_request_failed", error=str(e), ioc=ioc.value)
                if attempt == self.max_retries - 1:
                    return
                await asyncio.sleep(2 ** attempt)

    def _parse_response(self, data: dict, ioc: IOC) -> VTResult:
        """Parse le JSON de l'API v3 vers notre modèle VTResult."""
        try:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)

            # Calcul du verdict
            total_engines = malicious + suspicious + undetected + harmless
            score = 0
            verdict = "INCONNU"

            if total_engines > 0:
                score = int(((malicious + suspicious) / total_engines) * 100)
                if malicious >= 3 or (malicious + suspicious) >= 5:
                    verdict = "MALVEILLANT"
                elif malicious > 0 or suspicious > 0:
                    verdict = "SUSPECT"
                else:
                    verdict = "BÉNIN"

            return VTResult(
                value=ioc.value,
                ioc_type=ioc.type.value,
                found=True,
                malicious=malicious,
                suspicious=suspicious,
                undetected=undetected,
                harmless=harmless,
                confidence_score=score,
                verdict=verdict,
                vt_link=f"https://www.virustotal.com/gui/{self._gui_type(ioc.type)}/{self._gui_id(ioc)}"
            )
        except Exception as e:
            self._logger.error("vt_parse_error", error=str(e))
            return VTResult(value=ioc.value, ioc_type=ioc.type.value, found=True, error=str(e))

    def _gui_type(self, ioc_type: IOCType) -> str:
        mapping = {
            IOCType.IPV4: "ip-address",
            IOCType.IPV6: "ip-address",
            IOCType.DOMAIN: "domain",
            IOCType.URL: "url",
            IOCType.HASH_MD5: "file",
            IOCType.HASH_SHA1: "file",
            IOCType.HASH_SHA256: "file",
        }
        return mapping.get(ioc_type, "search")

    def _gui_id(self, ioc: IOC) -> str:
        import base64
        if ioc.type == IOCType.URL:
            # L'ID GUI de VT pour les URLs est le SHA256 de l'URL (!pas base64url)
            return hashlib.sha256(ioc.value.encode()).hexdigest()
        return ioc.value

    # --- Gestion du cache local (simplifiée pour l'exercice) ---

    def _cache_file(self) -> Path:
        cache_dir = self.settings.TEMP_DIR / "vt_cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / "vt_cache.json"

    def _load_cache(self) -> None:
        try:
            cf = self._cache_file()
            if cf.exists():
                with open(cf, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self._cache[k] = VTResult(**v)
        except Exception as e:
            self._logger.warning("vt_cache_load_failed", error=str(e))

    def _save_cache(self) -> None:
        try:
            cf = self._cache_file()
            with open(cf, "w", encoding="utf-8") as f:
                json.dump({k: v.model_dump() for k, v in self._cache.items()}, f)
        except Exception as e:
            self._logger.warning("vt_cache_save_failed", error=str(e))
