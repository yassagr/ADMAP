"""
Module   : admap_m2.core.exceptions
Version  : 1.0.0
Dépend   : []
"""

class ADMAPM2Error(Exception):
    def __init__(self, message: str, code: str = "ADMAP_M2_ERROR",
                 details: dict[str, object] | None = None) -> None:
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(self.message)

class PCAPParsingError(ADMAPM2Error):
    pass

class PCAPTooLargeError(ADMAPM2Error):
    pass

class PCAPEmptyError(ADMAPM2Error):
    pass

class AnalysisTimeoutError(ADMAPM2Error):
    pass

class DetectorError(ADMAPM2Error):
    pass

class CorrelatorError(ADMAPM2Error):
    pass

class ExportError(ADMAPM2Error):
    pass

class JobNotFoundError(ADMAPM2Error):
    pass

class JobCancelledError(ADMAPM2Error):
    pass

class M1IntegrationError(ADMAPM2Error):
    pass
