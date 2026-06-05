"""
Module   : admap_m1.core.logging
Version  : 3.0.0
Dépend   : [structlog, admap_m1.core.config]

Configuration structlog : JSON en production, console en debug.
Masquage automatique des champs sensibles (clés API, mots de passe).
"""
from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


# ── Champs sensibles à masquer dans TOUS les logs ──────────────────────────

_SENSITIVE_FIELDS: frozenset[str] = frozenset({
    "api_key",
    "vt_api_key",
    "misp_key",
    "key",
    "password",
    "token",
    "secret",
})

_REDACTED: str = "***REDACTED***"


def _mask_sensitive_fields(
    logger: Any,
    method_name: str,
    event_dict: dict[str, Any],
) -> dict[str, Any]:
    """Processeur structlog : masque les champs sensibles avant rendu.

    Args:
        logger: Instance du logger (ignoré).
        method_name: Nom de la méthode appelée (ignoré).
        event_dict: Dictionnaire de l'événement à traiter.

    Returns:
        event_dict avec les valeurs sensibles remplacées par ``***REDACTED***``.
    """
    for field_name in _SENSITIVE_FIELDS:
        if field_name in event_dict:
            value = event_dict[field_name]
            if value and isinstance(value, str) and len(value) > 0:
                event_dict[field_name] = _REDACTED
    return event_dict


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure structlog pour le module M1.

    Args:
        log_level: Niveau de log (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        log_format: Format de sortie (``json`` ou ``console``).
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        _mask_sensitive_fields,
    ]

    if log_format == "console":
        renderer: structlog.types.Processor = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configurer aussi le logging stdlib pour les bibliothèques tierces
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Retourne un logger structlog nommé.

    Remplace ``print()`` dans tout le module M1.

    Args:
        name: Nom du module (ex: ``pipeline.orchestrator``).

    Returns:
        Instance BoundLogger avec le nom du module en contexte.
    """
    return structlog.get_logger(name)
