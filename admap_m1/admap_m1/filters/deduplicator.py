"""
Module   : admap_m1.filters.deduplicator
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc]

Dédoublonnage intelligent des IOCs. Conserve l'occurrence avec le meilleur
score ou fusionne les contextes.
"""
from __future__ import annotations

from admap_m1.models.ioc import RawIOC


class IOCDeduplicator:
    """Dédoublonnage des IOCs extraits.

    Gère la normalisation (minuscules pour les domaines, etc.) et
    la fusion des contextes/scores pour éviter les doublons.
    """

    @staticmethod
    def deduplicate_raw(raw_iocs: list[RawIOC]) -> list[RawIOC]:
        """Dédoublonne une liste d'IOCs bruts avant scoring.

        - Normalise la valeur (tolower pour domaines/hashes/emails).
        - Si doublon : garde la version avec in_decoded_layer=True en priorité,
          sinon garde la première occurrence.

        Args:
            raw_iocs: Liste des RawIOC.

        Returns:
            Liste dédoublonnée.
        """
        seen: dict[tuple[str, str], RawIOC] = {}

        for ioc in raw_iocs:
            norm_val = IOCDeduplicator._normalize_value(ioc.value, ioc.type.value)
            key = (ioc.type.value, norm_val)

            if key not in seen:
                seen[key] = ioc
            else:
                existing = seen[key]
                # Privilégier un IOC extrait d'une couche déobfusquée
                if ioc.in_decoded_layer and not existing.in_decoded_layer:
                    seen[key] = ioc
                # Ou s'il a un offset et pas l'autre
                elif ioc.source_offset is not None and existing.source_offset is None:
                    seen[key] = ioc

        return list(seen.values())

    @staticmethod
    def _normalize_value(value: str, ioc_type_str: str) -> str:
        """Normalise la valeur pour la comparaison."""
        if ioc_type_str in {"domain", "email", "hash_md5", "hash_sha1", "hash_sha256", "hash_imphash"}:
            return value.lower()
        if ioc_type_str == "url":
            # Normaliser le scheme et le host en minuscules, garder le path
            parts = value.split("://", 1)
            if len(parts) == 2:
                scheme = parts[0].lower()
                rest = parts[1]
                path_idx = rest.find("/")
                if path_idx >= 0:
                    host = rest[:path_idx].lower()
                    path = rest[path_idx:]
                    return f"{scheme}://{host}{path}"
                else:
                    return f"{scheme}://{rest.lower()}"
        return value
