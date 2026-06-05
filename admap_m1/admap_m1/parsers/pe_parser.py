"""
Module   : admap_m1.parsers.pe_parser
Version  : 3.0.0
Dépend   : [pefile, admap_m1.models.ioc, admap_m1.core.exceptions, admap_m1.parsers.base]

Parser pour les fichiers Portable Executable (Windows EXE, DLL, SYS).
Extrait les métadonnées de structure, les imports/exports et les sections.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

import pefile

from admap_m1.core.exceptions import ExtractionWarning
from admap_m1.heuristics.entropy import EntropyCalculator
from admap_m1.models.ioc import FileMetadata, PEInfo, PESection
from admap_m1.parsers.base import BaseParser


class PEParser(BaseParser):
    """Parser pour les exécutables Windows (PE32 / PE32+).

    Utilise ``pefile`` pour extraire les imports, exports, sections
    et métadonnées structurelles, tout en gérant les exécutables malformés.
    """

    # Imports souvent utilisés par les malwares (injection, hooking, crypto)
    SUSPICIOUS_IMPORTS: ClassVar[frozenset[str]] = frozenset({
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "ZwUnmapViewOfSection", "SetThreadContext",
        "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrLoadDll",
        "LdrGetProcedureAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
        "InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
        "WSAStartup", "socket", "connect", "send", "recv",
        "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecute",
        "OpenProcess", "TerminateProcess", "AdjustTokenPrivileges",
    })

    @property
    def parser_name(self) -> str:
        return "pe_parser"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Vérifie si le fichier commence par le magic bytes 'MZ'."""
        return file_bytes.startswith(b"MZ")

    def parse_metadata(self, file_bytes: bytes, file_path: Path) -> FileMetadata:
        """Analyse le fichier PE et construit les métadonnées.

        En cas de PE malformé (ex: magic MZ mais structure cassée), retourne
        les métadonnées de base et log un avertissement au lieu d'échouer.
        """
        metadata = self._compute_basic_metadata(file_bytes, file_path, "PE/unknown")

        try:
            pe = pefile.PE(data=file_bytes, fast_load=False)
        except pefile.PEFormatError as e:
            self._logger.warning(
                "pe_format_error",
                filename=file_path.name,
                error=str(e)
            )
            metadata.filetype = "PE/corrupted"
            return metadata

        is_64bit = pe.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64
        metadata.filetype = "PE64" if is_64bit else "PE32"

        # Timestamp de compilation
        timestamp = pe.FILE_HEADER.TimeDateStamp
        compilation_time = None
        try:
            if 0 < timestamp < 0xFFFFFFFF:
                compilation_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OverflowError):
            pass

        # Sections
        sections: list[PESection] = []
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").rstrip("\x00")
            sec_data = section.get_data()
            sec_entropy = EntropyCalculator.calculate(sec_data) if sec_data else 0.0

            # Heuristique basique de section suspecte
            is_suspicious = sec_entropy > 7.0 or not sec_name.startswith(".")

            chars = []
            if section.Characteristics & 0x20000000: chars.append("EXECUTE")
            if section.Characteristics & 0x40000000: chars.append("READ")
            if section.Characteristics & 0x80000000: chars.append("WRITE")

            sections.append(
                PESection(
                    name=sec_name,
                    virtual_address=hex(section.VirtualAddress),
                    raw_size=section.SizeOfRawData,
                    entropy=sec_entropy,
                    characteristics=chars,
                    is_suspicious=is_suspicious,
                )
            )

        # Imports
        imports: dict[str, list[str]] = {}
        suspicious_found: list[str] = []

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if not entry.dll:
                    continue
                dll_name = entry.dll.decode("utf-8", errors="ignore").lower()
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore")
                        funcs.append(func_name)
                        # Identifier les imports suspects sans la casse
                        for susp in self.SUSPICIOUS_IMPORTS:
                            if susp.lower() == func_name.lower():
                                suspicious_found.append(func_name)
                                break
                    elif imp.ordinal:
                        funcs.append(f"ordinal_{imp.ordinal}")
                if funcs:
                    imports[dll_name] = funcs

        # Scoring de la suspicion basée sur les imports
        import_score = self._score_suspicious_imports(suspicious_found)

        # Exports
        exports: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode("utf-8", errors="ignore"))
                else:
                    exports.append(f"ordinal_{exp.ordinal}")

        # Détection .NET
        is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")

        # Entry point
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        metadata.pe_info = PEInfo(
            compilation_timestamp=compilation_time,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
            is_dotnet=is_dotnet,
            is_64bit=is_64bit,
            suspicious_imports=suspicious_found,
            import_suspicion_score=import_score,
        )

        return metadata

    def _score_suspicious_imports(self, suspicious_imports: list[str]) -> int:
        """Calcule un score de 0 à 100 basé sur la densité et la nature des imports suspects."""
        if not suspicious_imports:
            return 0

        # Pondération basique par mot-clé
        score = 0
        for imp in suspicious_imports:
            lower_imp = imp.lower()
            if "virtual" in lower_imp or "thread" in lower_imp or "process" in lower_imp:
                score += 15
            elif "crypt" in lower_imp:
                score += 10
            elif "http" in lower_imp or "internet" in lower_imp or "socket" in lower_imp:
                score += 10
            else:
                score += 5

        return min(100, score)
