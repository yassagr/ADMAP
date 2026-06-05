"""
Module   : admap_m1.extractors.regex_extractor
Version  : 3.0.0
Dépend   : [re, admap_m1.models.ioc, admap_m1.extractors.base]

Extracteur basé sur des expressions régulières pour analyser le texte brut.
Porte TOUS les patterns exacts définis dans la spécification (Section 19).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from admap_m1.models.ioc import FileMetadata, IOCType, RawIOC
from admap_m1.extractors.base import BaseExtractor


class RegexExtractor(BaseExtractor):
    """Extracteur principal d'IOCs via expressions régulières.

    S'applique au texte brut ou aux chaînes de caractères extraites de binaires.
    """

    # 19.1 — Patterns réseau
    IPV4_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![.\d])'
    )

    IPV6_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:'
        r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'                # 1:2:3:4:5:6:7:8
        r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'                               # 1::
        r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'             # 1::8
        r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'   # 1::7:8
        r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'   # 1::6:7:8
        r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'   # 1::5:6:7:8
        r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'   # 1::4:5:6:7:8
        r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'             # 1::3:4:5:6:7:8
        r':(?::[0-9a-fA-F]{1,4}){1,7}|::|'                            # ::1 ou ::
        r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|'            # fe80::1%eth0
        r'::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'  # ::ffff:192.168.1.1
        r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}'
        r')'
    )

    DOMAIN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,24}\b'
    )

    URL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:https?|ftp|hxxps?|hxtp)(?:://|\[://\])'
        r'[^\s\'"<>{}\[\]|\\^`\x00-\x1f\x7f-\xff]{4,}',
        re.IGNORECASE
    )

    EMAIL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'\b[a-zA-Z0-9._%+\-]{1,64}'
        r'(?:@|\[@\]|\[at\])'
        r'[a-zA-Z0-9.\-]{1,255}'
        r'\.[a-zA-Z]{2,24}\b'
    )

    # 19.2 — Patterns de hachage
    MD5_RE: ClassVar[re.Pattern[str]] = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])')
    SHA1_RE: ClassVar[re.Pattern[str]] = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])')
    SHA256_RE: ClassVar[re.Pattern[str]] = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')
    SSDEEP_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'\b\d{1,7}:[A-Za-z0-9/+]{6,}:[A-Za-z0-9/+]{6,}(?:,[^\n\r]*)?\b'
    )
    IMPHASH_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?i)(?:imphash|import.?hash)[:\s="\']+'
        r'([0-9a-fA-F]{32})\b'
    )

    # 19.3 — Patterns système hôte
    FILEPATH_WIN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:'
        r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}\\)*'
        r'[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}|'
        r'\\\\[^\\\/:*?"<>|\r\n\x00-\x1f]{1,255}\\[^\\\/:*?"<>|\r\n\x00-\x1f]+'
        r'(?:\\[^\\\/:*?"<>|\r\n\x00-\x1f]+)*|'
        r'%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|SYSTEMROOT|WINDIR|PROGRAMFILES'
        r'|PROGRAMFILES\(X86\)|COMMONPROGRAMFILES|USERPROFILE|ALLUSERSPROFILE'
        r'|PUBLIC|SYSTEMDRIVE)%'
        r'\\[^\\\/:*?"<>|\r\n\x00-\x1f]+'
        r'(?:\\[^\\\/:*?"<>|\r\n\x00-\x1f]+)*'
        r')'
    )

    FILEPATH_UNIX_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'/(?:tmp|proc|dev/shm|var/tmp|run|home/[^/\s]+|root)'
        r'/[^\s\'"<>|*?\x00-\x1f\x7f]+'
    )

    REGISTRY_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:'
        r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS'
        r'|CURRENT_CONFIG|PERFORMANCE_DATA)|'
        r'HK(?:LM|CU|CR|U|CC)'
        r')'
        r'\\[^\n\r\'"<>|*?\x00-\x1f\x7f]{3,512}',
        re.IGNORECASE
    )

    MUTEX_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:'
        r'(?:Global\\|Local\\)[A-Za-z0-9_\-\.]{4,128}|'
        r'[A-Za-z0-9_\-\.]{8,64}(?:Mutex|Lock|Sync|Guard|Semaphore|Event)'
        r')',
        re.IGNORECASE
    )

    # 19.4 — Patterns de commandes suspectes
    POWERSHELL_ENCODED_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:powershell|pwsh)(?:\.exe)?'
        r'(?:\s+-\w+(?:\s+\w+)?)*\s+'
        r'-[eE](?:ncoded[cC]ommand|nc|nco|ncod|ncode|ncoded)?\s+'
        r'([A-Za-z0-9+/=]{20,})',
        re.IGNORECASE
    )

    POWERSHELL_DOWNLOAD_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:New-Object\s+)?(?:System\.)?Net\.WebClient\)'
        r'\.(?:DownloadString|DownloadFile|DownloadData)'
        r'\(["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    INVOKE_EXPR_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'(?:Invoke-Expression|IEX)\s*\(',
        re.IGNORECASE
    )

    CERTUTIL_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'certutil(?:\.exe)?\s+'
        r'(?:-\w+\s+)*'
        r'-(?:decode|encode|urlcache|verifyctl)\s+'
        r'([^\s\'"]{4,512})',
        re.IGNORECASE
    )

    BITSADMIN_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'bitsadmin(?:\.exe)?\s+'
        r'(?:/\w+\s+)*'
        r'/(?:transfer|addfile|create)\s+'
        r'([^\s\'"]{4,512})',
        re.IGNORECASE
    )

    REGSVR32_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'regsvr32(?:\.exe)?\s+'
        r'(?:/[suinUINk]\s+)*'
        r'(?:/i:)?(?:https?|ftp|\\\\)[^\s\'"]{4,512}',
        re.IGNORECASE
    )

    MSHTA_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'mshta(?:\.exe)?\s+'
        r'(?:vbscript:|javascript:)?'
        r'(?:https?://)?[^\s\'"]{4,512}',
        re.IGNORECASE
    )

    WMIC_PROCESS_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'wmic(?:\.exe)?\s+'
        r'(?:node:[^\s]+\s+)?'
        r'process\s+(?:call\s+create|create)\s+'
        r'["\']?([^"\';\n\r]{4,512})',
        re.IGNORECASE
    )

    RUNDLL32_RE: ClassVar[re.Pattern[str]] = re.compile(
        r'rundll32(?:\.exe)?\s+'
        r'([^\s,\'"]{4,512})',
        re.IGNORECASE
    )

    @property
    def extraction_method(self) -> str:
        return "regex_text"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """S'applique à tout texte brut ou bytes déja décodés.
        
        Note: Dans la pipeline, RegexExtractor est utilisé comme processeur
        universel sur le texte produit par les autres extracteurs ou désobfuscateurs.
        """
        # Généralement utilisé manuellement sur du texte
        return True

    def extract(
        self,
        file_bytes: bytes,
        file_path: Path,
        metadata: FileMetadata,
    ) -> list[RawIOC]:
        """Extrait les IOCs via regex.

        Les bytes sont d'abord décodés en texte en ignorant les erreurs.
        """
        text = file_bytes.decode("utf-8", errors="ignore")
        return self.extract_from_text(text)

    def extract_from_text(self, text: str) -> list[RawIOC]:
        """Méthode principale d'extraction depuis une chaîne de caractères."""
        iocs: list[RawIOC] = []

        # Table des regex classiques et leurs types correspondants
        patterns: list[tuple[IOCType, re.Pattern[str], bool]] = [
            (IOCType.IPV4, self.IPV4_RE, False),
            (IOCType.IPV6, self.IPV6_RE, False),
            (IOCType.URL, self.URL_RE, False),
            (IOCType.EMAIL, self.EMAIL_RE, False),
            (IOCType.HASH_MD5, self.MD5_RE, False),
            (IOCType.HASH_SHA1, self.SHA1_RE, False),
            (IOCType.HASH_SHA256, self.SHA256_RE, False),
            (IOCType.HASH_SSDEEP, self.SSDEEP_RE, False),
            (IOCType.FILEPATH, self.FILEPATH_WIN_RE, False),
            (IOCType.FILEPATH, self.FILEPATH_UNIX_RE, False),
            (IOCType.REGISTRY_KEY, self.REGISTRY_RE, False),
            (IOCType.MUTEX, self.MUTEX_RE, False),
        ]

        # Extractions simples
        for ioc_type, pattern, use_group in patterns:
            for match in pattern.finditer(text):
                # Parfois on veut capturer juste le groupe 1, parfois tout le match
                # Les patterns simples capturent tout le match
                value = match.group(1) if use_group and match.lastindex else match.group(0)
                snippet = self._get_context_snippet(text, match.start(), match.end())
                iocs.append(RawIOC(
                    type=ioc_type,
                    value=value,
                    context_snippet=snippet,
                    extraction_method=self.extraction_method,
                    source_offset=match.start(),
                ))

        # Les domaines requièrent un filtrage pour éviter de capturer ceux déjà dans des emails ou URLs
        # On extrait les domaines et on les ajoute seulement s'ils ne sont pas englobés
        for match in self.DOMAIN_RE.finditer(text):
            domain = match.group(0)
            start, end = match.span()
            
            # Heuristique simple: on regarde si le domaine est entouré par @ ou / (indiquant email ou URL)
            # Cette vérification basique évite beaucoup de doublons
            is_part_of_other = False
            if start > 0 and text[start-1] in {'@', '/'}:
                is_part_of_other = True
            
            if not is_part_of_other:
                snippet = self._get_context_snippet(text, start, end)
                iocs.append(RawIOC(
                    type=IOCType.DOMAIN,
                    value=domain,
                    context_snippet=snippet,
                    extraction_method=self.extraction_method,
                    source_offset=start,
                ))

        # Imphash (cas spécial où l'on extrait le groupe 1)
        for match in self.IMPHASH_RE.finditer(text):
            value = match.group(1)
            snippet = self._get_context_snippet(text, match.start(), match.end())
            iocs.append(RawIOC(
                type=IOCType.HASH_IMPHASH,
                value=value,
                context_snippet=snippet,
                extraction_method=self.extraction_method,
                source_offset=match.start(),
            ))

        # Commandes suspectes
        cmd_patterns: list[re.Pattern[str]] = [
            self.POWERSHELL_ENCODED_RE,
            self.POWERSHELL_DOWNLOAD_RE,
            self.INVOKE_EXPR_RE,
            self.CERTUTIL_RE,
            self.BITSADMIN_RE,
            self.REGSVR32_RE,
            self.MSHTA_RE,
            self.WMIC_PROCESS_RE,
            self.RUNDLL32_RE,
        ]

        for pattern in cmd_patterns:
            for match in pattern.finditer(text):
                value = match.group(0)
                snippet = self._get_context_snippet(text, match.start(), match.end())
                iocs.append(RawIOC(
                    type=IOCType.COMMAND,
                    value=value,
                    context_snippet=snippet,
                    extraction_method=self.extraction_method,
                    source_offset=match.start(),
                ))

        return iocs
