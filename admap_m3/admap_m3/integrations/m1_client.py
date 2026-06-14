"""
Module   : admap_m3.integrations.m1_client
Version  : 1.0.0
Dépend   : [httpx, structlog, admap_m3.config]

Client d'intégration avec le module M1 (IOC Extractor).
Consomme un ``IOCBundle`` M1 (fichier JSON local OU URL REST M1)
et extrait les tokens pertinents pour enrichir le corpus malware.

Les IPs sont **exclues** (trop génériques pour des règles YARA).
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from admap_m3.config import Settings

logger: structlog.stdlib.BoundLogger = structlog.get_logger()


class M1IOCClient:
    """Client pour consommer les IOCBundles produits par le module M1.

    Extrait les tokens pertinents :
    - Domaines → ``m1_ioc:domain``
    - URLs → ``m1_ioc:url``
    - Strings suspectes (commandes, mutex) → ``m1_ioc:string``

    Les IPs sont volontairement exclues (trop génériques pour YARA).
    """

    def __init__(self, settings: Settings) -> None:
        self._settings: Settings = settings
        self._base_url: str = settings.m1_base_url
        self._timeout: int = settings.m1_timeout_seconds

    async def load_bundle(self, bundle_path: str) -> dict[str, Any]:
        """Charge un IOCBundle JSON depuis le disque.

        Args:
            bundle_path: Chemin vers le fichier JSON IOCBundle.

        Returns:
            Dictionnaire du bundle IOC.

        Raises:
            FileNotFoundError: Si le fichier n'existe pas.
            json.JSONDecodeError: Si le JSON est invalide.
        """
        with open(bundle_path, "r", encoding="utf-8") as fh:
            bundle: dict[str, Any] = json.load(fh)

        logger.info(
            "m1_bundle_loaded",
            bundle_path=bundle_path,
            keys=list(bundle.keys()),
        )

        return bundle

    async def fetch_bundle(self, bundle_id: str) -> dict[str, Any]:
        """Requête GET vers M1 pour récupérer un IOCBundle.

        Args:
            bundle_id: Identifiant du job/bundle M1.

        Returns:
            Dictionnaire du bundle IOC.
        """
        url: str = f"{self._base_url}/api/v1/jobs/{bundle_id}/result"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            response: httpx.Response = await client.get(url)
            response.raise_for_status()
            bundle: dict[str, Any] = response.json()

        logger.info(
            "m1_bundle_fetched",
            bundle_id=bundle_id,
            url=url,
        )

        return bundle

    def extract_tokens(self, bundle: dict[str, Any]) -> list[str]:
        """Extrait les tokens pertinents d'un IOCBundle M1.

        Tokens extraits (préfixés ``m1_ioc:`` pour traçabilité) :
        - Domaines
        - URLs
        - Strings suspectes (commandes, mutex, noms de fichiers)

        Les IPs sont **exclues** (trop génériques).

        Args:
            bundle: Dictionnaire IOCBundle M1.

        Returns:
            Liste de tokens enrichis pour le corpus malware.
        """
        tokens: list[str] = []

        # Extraire les domaines
        domains: list[str] = self._extract_field(bundle, "domains")
        for domain in domains:
            if domain and len(domain) >= 4:
                tokens.append(f"m1_ioc:{domain}")

        # Extraire les URLs
        urls: list[str] = self._extract_field(bundle, "urls")
        for url in urls:
            if url and len(url) >= 6:
                tokens.append(f"m1_ioc:{url}")

        # Extraire les strings suspectes (commandes, mutex, noms de fichiers)
        for key in ("strings", "commands", "mutexes", "filenames", "suspicious_strings"):
            suspicious: list[str] = self._extract_field(bundle, key)
            for s in suspicious:
                if s and len(s) >= 6:
                    tokens.append(f"m1_ioc:{s}")

        # NE PAS extraire les IPs (volontairement exclu)

        logger.info(
            "m1_tokens_extracted",
            total_tokens=len(tokens),
            domains=len(domains),
            urls=len(urls),
        )

        return tokens

    def _extract_field(self, bundle: dict[str, Any], field_name: str) -> list[str]:
        """Extrait une liste de strings depuis un champ du bundle.

        Supporte les structures imbriquées (``iocs.domains``, etc.).
        """
        # Chercher au premier niveau
        value: Any = bundle.get(field_name)
        if isinstance(value, list):
            return [str(v) for v in value if v]

        # Chercher dans un sous-dict "iocs"
        iocs: Any = bundle.get("iocs", {})
        if isinstance(iocs, dict):
            value = iocs.get(field_name)
            if isinstance(value, list):
                return [str(v) for v in value if v]

        # Chercher dans "results"
        results: Any = bundle.get("results", {})
        if isinstance(results, dict):
            value = results.get(field_name)
            if isinstance(value, list):
                return [str(v) for v in value if v]

        return []
