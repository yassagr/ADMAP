"""
Module   : admap_m3.analyzers.text_analyzer
Version  : 1.0.0
Dépend   : [structlog]

Analyseur de fichiers texte (scripts, configs, rapports CTI) pour
l'extraction de tokens : mots, IPs, domaines, URLs, hashes hex,
chemins, séquences hex.
"""
from __future__ import annotations

import re

import structlog

from admap_m3.analyzers.base import BaseAnalyzer

logger: structlog.stdlib.BoundLogger = structlog.get_logger()

# ── Patterns regex ───────────────────────────────────────────────────────

# Adresses IP v4
_IP_RE: re.Pattern[str] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Domaines (ex: evil.example.com)
_DOMAIN_RE: re.Pattern[str] = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|xyz|top|ru|cn|tk|pw|cc|io|me|co|de|fr|uk|us|"
    r"onion|bit|exe|dll|bat|cmd|ps1)\b"
)

# URLs
_URL_RE: re.Pattern[str] = re.compile(
    r"https?://[^\s\"'<>]{6,}"
)

# Hashes hex (32+ caractères — MD5, SHA1, SHA256…)
_HEX_HASH_RE: re.Pattern[str] = re.compile(
    r"\b[0-9a-fA-F]{32,}\b"
)

# Chemins Windows
_WIN_PATH_RE: re.Pattern[str] = re.compile(
    r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]+"
)

# Chemins Unix
_UNIX_PATH_RE: re.Pattern[str] = re.compile(
    r"/(?:[a-zA-Z0-9._\-]+/)*[a-zA-Z0-9._\-]+"
)

# Séquences hexadécimales continues ≥ 8 chars (shellcode encodé)
_HEX_SEQ_RE: re.Pattern[str] = re.compile(
    r"\b[0-9a-fA-F]{8,}\b"
)

# Tokenisation par whitespace + ponctuation (mot ≥ 1 char)
_WORD_RE: re.Pattern[str] = re.compile(r"[a-zA-Z0-9_.\-:/\\@]{1,}")


class TextAnalyzer(BaseAnalyzer):
    """Analyse de fichiers texte (scripts, configs, rapports CTI).

    Extrait :
    1. Tokens par whitespace + ponctuation (longueur ≥ min_token_length).
    2. Patterns regex : IPs, domaines, URLs, hashes hex, chemins.
    3. Séquences hex continues ≥ 8 chars.
    """

    def __init__(self, min_token_length: int = 6) -> None:
        self._min_token_length: int = min_token_length

    @property
    def analyzer_name(self) -> str:
        return "TextAnalyzer"

    def extract_tokens(self, data: bytes, file_path: str) -> list[str]:
        """Extrait les tokens depuis un fichier texte."""
        try:
            text: str = data.decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.warning(
                "text_decode_error",
                file_path=file_path,
                error=str(exc),
                analyzer=self.analyzer_name,
            )
            return []

        tokens: list[str] = []
        seen: set[str] = set()

        # 1. Tokenisation par mots
        for match in _WORD_RE.finditer(text):
            word: str = match.group()
            if len(word) >= self._min_token_length and word not in seen:
                tokens.append(word)
                seen.add(word)

        # 2. IPs
        for match in _IP_RE.finditer(text):
            ip: str = match.group()
            if ip not in seen:
                tokens.append(ip)
                seen.add(ip)

        # 3. Domaines
        for match in _DOMAIN_RE.finditer(text):
            domain: str = match.group()
            if domain not in seen:
                tokens.append(domain)
                seen.add(domain)

        # 4. URLs
        for match in _URL_RE.finditer(text):
            url: str = match.group()
            if url not in seen:
                tokens.append(url)
                seen.add(url)

        # 5. Hashes hex (32+ chars)
        for match in _HEX_HASH_RE.finditer(text):
            hex_hash: str = match.group()
            if hex_hash not in seen:
                tokens.append(hex_hash)
                seen.add(hex_hash)

        # 6. Chemins Windows
        for match in _WIN_PATH_RE.finditer(text):
            win_path: str = match.group()
            if len(win_path) >= self._min_token_length and win_path not in seen:
                tokens.append(win_path)
                seen.add(win_path)

        # 7. Chemins Unix
        for match in _UNIX_PATH_RE.finditer(text):
            unix_path: str = match.group()
            if len(unix_path) >= self._min_token_length and unix_path not in seen:
                tokens.append(unix_path)
                seen.add(unix_path)

        # 8. Séquences hex ≥ 8 chars
        for match in _HEX_SEQ_RE.finditer(text):
            hex_seq: str = match.group()
            if hex_seq not in seen:
                tokens.append(hex_seq)
                seen.add(hex_seq)

        return tokens
