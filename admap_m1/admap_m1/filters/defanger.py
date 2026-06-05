"""
Module   : admap_m1.filters.defanger
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc]

Defanging et refanging d'IOCs réseau pour échange CTI sécurisé.
Empêche le clic accidentel sur des URLs/IPs malveillantes dans les rapports.
"""
from __future__ import annotations

from typing import ClassVar

from admap_m1.models.ioc import IOCType


class IOCDefanger:
    """Outil de defanging/refanging d'IOCs réseau.

    Le defanging transforme les IOCs réseau en formes non-cliquables
    (ex: ``https://evil.com`` → ``hxxps[://]evil[.]com``).
    Le refanging inverse la transformation pour l'analyse.
    """

    DEFANGED_PATTERNS: ClassVar[dict[str, str]] = {
        "hxxps[://]": "https://",
        "hxxp[://]": "http://",
        "hxxps://": "https://",
        "hxxp://": "http://",
        "fxp[://]": "ftp://",
        "[.]": ".",
        "[dot]": ".",
        "(.)": ".",
        "[@]": "@",
        "[at]": "@",
        "[:]": ":",
        "[//]": "//",
    }

    DEFANG_RULES: ClassVar[dict[IOCType, list[tuple[str, str]]]] = {
        IOCType.URL: [
            ("https://", "hxxps[://]"),
            ("http://", "hxxp[://]"),
            ("ftp://", "fxp[://]"),
            (".", "[.]"),
        ],
        IOCType.IPV4: [(".", "[.]")],
        IOCType.IPV6: [(":", "[:]")],
        IOCType.DOMAIN: [(".", "[.]")],
        IOCType.EMAIL: [("@", "[@]"), (".", "[.]")],
    }

    def defang(self, value: str, ioc_type: IOCType) -> str:
        """Transforme un IOC en forme défangée non-cliquable.

        Args:
            value: Valeur originale de l'IOC.
            ioc_type: Type de l'IOC pour choisir les règles appropriées.

        Returns:
            Valeur défangée. Si le type n'a pas de règle, retourne la valeur inchangée.
        """
        rules: list[tuple[str, str]] | None = self.DEFANG_RULES.get(ioc_type)
        if not rules:
            return value

        result: str = value
        for original, replacement in rules:
            if ioc_type == IOCType.URL and original == ".":
                # Ne défanger les points que dans le domaine, pas le path
                parts = result.split("://", 1)
                if len(parts) == 2:
                    scheme_part = parts[0]
                    rest = parts[1]
                    # Séparer domaine et path
                    path_idx = rest.find("/")
                    if path_idx >= 0:
                        domain_part = rest[:path_idx]
                        path_part = rest[path_idx:]
                    else:
                        domain_part = rest
                        path_part = ""
                    domain_part = domain_part.replace(original, replacement)
                    # Reconstruire avec le scheme déjà défangé
                    result = f"{scheme_part}://{domain_part}{path_part}"
                else:
                    result = result.replace(original, replacement)
            else:
                result = result.replace(original, replacement)
        return result

    def refang(self, value: str) -> str:
        """Inverse toutes les transformations de defanging.

        Args:
            value: Valeur défangée à restaurer.

        Returns:
            Valeur refangée (forme originale de l'IOC).
        """
        result: str = value
        # Appliquer les patterns du plus long au plus court
        # pour éviter les remplacements partiels
        sorted_patterns: list[tuple[str, str]] = sorted(
            self.DEFANGED_PATTERNS.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )
        for defanged, original in sorted_patterns:
            result = result.replace(defanged, original)
        return result

    def refang_text(self, text: str) -> str:
        """Refange toutes les occurrences d'IOCs défangés dans un texte.

        Args:
            text: Texte long pouvant contenir des IOCs défangés.

        Returns:
            Texte avec tous les IOCs refangés.
        """
        return self.refang(text)

    def contains_defanged(self, text: str) -> bool:
        """Détecte la présence d'IOCs défangés dans un texte.

        Args:
            text: Texte à analyser.

        Returns:
            True si au moins un pattern défangé est trouvé.
        """
        text_lower: str = text.lower()
        return any(
            pattern.lower() in text_lower
            for pattern in self.DEFANGED_PATTERNS
        )
