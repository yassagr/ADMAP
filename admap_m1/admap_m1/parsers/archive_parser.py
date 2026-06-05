"""
Module   : admap_m1.parsers.archive_parser
Version  : 3.0.0
Dépend   : [admap_m1.models.ioc, admap_m1.core.exceptions, admap_m1.parsers.base]

Parser pour les archives (ZIP, GZIP, TAR, 7z).
Implémente une protection anti-zip-bomb avec limitation de taille et profondeur.
"""
from __future__ import annotations

import gzip
import io
import tarfile
import zipfile
from pathlib import Path
from typing import ClassVar

from admap_m1.core.exceptions import ArchiveExtractionError, ZipBombError
from admap_m1.models.ioc import FileMetadata
from admap_m1.parsers.base import BaseParser

try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False


class ArchiveParser(BaseParser):
    """Parser pour les fichiers d'archive.

    Extrait de façon récursive les membres des archives (ZIP, GZIP, TAR, 7z).
    Intègre une protection stricte contre les bombes de décompression (zip bombs)
    limitant la profondeur de récursion et la taille totale extraite.
    """

    MAX_DEPTH: ClassVar[int] = 3
    MAX_EXTRACTED_SIZE: ClassVar[int] = 200 * 1024 * 1024  # 200 MB

    @property
    def parser_name(self) -> str:
        return "archive_parser"

    def can_handle(self, file_bytes: bytes, file_path: Path) -> bool:
        """Vérifie si le fichier est une archive supportée (magic bytes)."""
        return self._detect_format(file_bytes) is not None

    def parse_metadata(self, file_bytes: bytes, file_path: Path) -> FileMetadata:
        """Extrait les métadonnées de base de l'archive."""
        fmt = self._detect_format(file_bytes) or "unknown"
        metadata = self._compute_basic_metadata(file_bytes, file_path, f"Archive/{fmt}")
        return metadata

    def extract_members(
        self,
        file_bytes: bytes,
        archive_path: Path,
        depth: int = 0,
        total_size_ref: list[int] | None = None,
    ) -> list[tuple[str, bytes]]:
        """Extrait récursivement le contenu d'une archive.

        Args:
            file_bytes: Contenu de l'archive en bytes.
            archive_path: Chemin original (pour les logs et les labels).
            depth: Profondeur de récursion actuelle (0 = archive racine).
            total_size_ref: Compteur partagé de taille totale extraite.
                Passé par référence via list[int] pour mutation inter-appels.

        Returns:
            Liste de (chemin_relatif_dans_archive, contenu_bytes).
            Chaque chemin est préfixé par le nom de l'archive parente :
            "archive.zip/subfolder/malware.exe"

        Raises:
            ArchiveExtractionError: Si depth > MAX_DEPTH.
            ZipBombError: Si total extrait > MAX_EXTRACTED_SIZE.
        """
        if total_size_ref is None:
            total_size_ref = [0]

        if depth > self.MAX_DEPTH:
            self._logger.warning(
                "archive_max_depth_reached",
                depth=depth,
                archive=str(archive_path),
            )
            raise ArchiveExtractionError(
                f"Archive recursion depth {depth} exceeds maximum {self.MAX_DEPTH}",
                "ARCHIVE_MAX_DEPTH",
                {"depth": depth, "archive": str(archive_path)},
            )

        results: list[tuple[str, bytes]] = []
        archive_name = archive_path.name

        # Détecter le type d'archive
        fmt = self._detect_format(file_bytes)
        if fmt is None:
            return []

        try:
            members = self._open_archive(file_bytes, fmt, archive_path)
        except Exception as e:
            self._logger.warning(
                "archive_open_failed",
                archive=str(archive_path),
                error=str(e),
            )
            return []

        for member_name, member_bytes in members:
            # Vérification taille cumulée (protection zip-bomb)
            total_size_ref[0] += len(member_bytes)
            if total_size_ref[0] > self.MAX_EXTRACTED_SIZE:
                raise ZipBombError(
                    f"Total extracted size exceeds {self.MAX_EXTRACTED_SIZE // (1024*1024)} MB",
                    "ZIP_BOMB_DETECTED",
                    {
                        "total_extracted_mb": total_size_ref[0] // (1024 * 1024),
                        "limit_mb": self.MAX_EXTRACTED_SIZE // (1024 * 1024),
                        "archive": str(archive_path),
                    },
                )

            relative_path = f"{archive_name}/{member_name}"
            results.append((relative_path, member_bytes))

            # Récursion si le membre est lui-même une archive
            if self._is_archive(member_bytes):
                try:
                    sub_members = self.extract_members(
                        file_bytes=member_bytes,
                        archive_path=Path(relative_path),
                        depth=depth + 1,
                        total_size_ref=total_size_ref,
                    )
                    results.extend(sub_members)
                except (ZipBombError, ArchiveExtractionError):
                    raise  # Propager les erreurs critiques
                except Exception as e:
                    self._logger.warning(
                        "archive_sub_extraction_failed",
                        member=relative_path,
                        error=str(e),
                    )

        return results

    def _detect_format(self, file_bytes: bytes) -> str | None:
        """Identifier le format d'archive par magic bytes.

        Retourner 'zip', 'gzip', '7z', 'tar', ou None.
        """
        if file_bytes[:4] == b"PK\x03\x04":
            return "zip"
        if file_bytes[:2] == b"\x1f\x8b":
            return "gzip"
        if file_bytes[:6] == b"7z\xbc\xaf\x27\x1c":
            if PY7ZR_AVAILABLE:
                return "7z"
            else:
                return None
        # TAR : pas de magic fixe avant octets 257
        try:
            if file_bytes[257:262] == b"ustar":
                return "tar"
        except IndexError:
            pass
        return None

    def _open_archive(
        self,
        file_bytes: bytes,
        fmt: str,
        archive_path: Path,
    ) -> list[tuple[str, bytes]]:
        """Ouvrir l'archive et retourner liste (nom_membre, contenu_bytes).

        Gérer les erreurs de chaque format distinctement.
        """
        members: list[tuple[str, bytes]] = []

        if fmt == "zip":
            zf = self._try_zip_passwords(file_bytes)
            if zf is None:
                try:
                    zf = zipfile.ZipFile(io.BytesIO(file_bytes))
                except zipfile.BadZipFile as e:
                    raise ArchiveExtractionError(str(e), "BAD_ZIP")
            with zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    try:
                        data = zf.read(info.filename)
                        members.append((info.filename, data))
                    except Exception as e:
                        self._logger.warning(
                            "zip_member_read_failed",
                            member=info.filename,
                            error=str(e),
                        )

        elif fmt == "gzip":
            try:
                with gzip.open(io.BytesIO(file_bytes)) as gf:
                    data = gf.read(self.MAX_EXTRACTED_SIZE + 1)
                stem = archive_path.stem
                # Si extension est .gz, stem supprime .gz (ex: file.txt.gz -> file.txt)
                members.append((stem, data))
            except Exception as e:
                self._logger.warning("gzip_read_failed", archive=str(archive_path), error=str(e))

        elif fmt == "tar":
            try:
                with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tf:
                    for member in tf.getmembers():
                        if not member.isfile():
                            continue
                        try:
                            f = tf.extractfile(member)
                            if f:
                                members.append((member.name, f.read()))
                        except Exception as e:
                            self._logger.warning(
                                "tar_member_read_failed",
                                member=member.name,
                                error=str(e),
                            )
            except tarfile.TarError as e:
                raise ArchiveExtractionError(str(e), "BAD_TAR")

        elif fmt == "7z":
            if not PY7ZR_AVAILABLE:
                self._logger.warning("py7zr_unavailable_skipping_7z_archive")
            else:
                try:
                    with py7zr.SevenZipFile(io.BytesIO(file_bytes)) as szf:
                        extracted = szf.readall()
                        for name, bio in (extracted or {}).items():
                            members.append((name, bio.read()))
                except Exception as e:
                    raise ArchiveExtractionError(str(e), "BAD_7Z")

        return members

    def _is_archive(self, data: bytes) -> bool:
        """True si les bytes correspondent à une archive connue."""
        return self._detect_format(data) is not None

    def _try_zip_passwords(self, file_bytes: bytes) -> zipfile.ZipFile | None:
        """Tente d'ouvrir un ZIP avec des mots de passe courants (ex: 'infected')."""
        passwords = [b"infected", b"malware", b"password", b"1234"]
        for pwd in passwords:
            try:
                zf = zipfile.ZipFile(io.BytesIO(file_bytes))
                zf.setpassword(pwd)
                # Tenter de lire le premier fichier pour vérifier le mot de passe
                infolist = zf.infolist()
                if infolist:
                    zf.read(infolist[0].filename)
                return zf
            except (RuntimeError, zipfile.BadZipFile):
                continue
        return None
