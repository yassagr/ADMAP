"""
Module   : admap_m1.deobfuscators.base
Version  : 3.0.0
Dépend   : [admap_m1.core.logging]

Classe de base pour les désobfuscateurs et structure de résultat.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from admap_m1.core.logging import get_logger


@dataclass
class DeobfuscationResult:
    """Résultat d'une tentative de désobfuscation."""
    
    success: bool
    technique_name: str
    decoded_data: bytes | None = None
    confidence: int = 0  # Score de certitude que la désobfuscation a réussi
    metadata: dict[str, str] = field(default_factory=dict)


class BaseDeobfuscator(ABC):
    """Classe de base pour tous les désobfuscateurs."""

    def __init__(self) -> None:
        self._logger = get_logger(f"deobfuscators.{self.technique_name}")

    @property
    @abstractmethod
    def technique_name(self) -> str:
        """Nom de la technique (ex: 'xor_1byte', 'base64')."""
        pass

    @abstractmethod
    def decode(self, data: bytes) -> list[DeobfuscationResult]:
        """Tente de décoder les données.

        Peut retourner plusieurs résultats si plusieurs clés/variantes
        sont trouvées (ex: multiples clés XOR valides).
        
        Args:
            data: Données brutes à désobfusquer.
            
        Returns:
            Liste des résultats réussis. Vide si aucun décodage n'est valide.
        """
        pass

    def _is_valid_plaintext(self, data: bytes) -> bool:
        """Heuristique simple pour valider un texte déchiffré.
        
        Vérifie qu'il y a une proportion suffisante de caractères imprimables.
        """
        if not data:
            return False
            
        # Comptage des caractères ASCII imprimables (32-126) + newline/tab
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        ratio = printable / len(data)
        
        # On considère valide si > 70% est imprimable
        return ratio > 0.7
