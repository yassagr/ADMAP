"""ADMAP M5 — Attribution Module."""
__version__ = "1.0.0"

import sys
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
)
