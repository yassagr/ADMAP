"""
Tests unitaires pour la CLI Click (admap_m3.cli.main).
"""
from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from click.testing import CliRunner

from admap_m3.cli.main import cli, _list_files


class TestCLI:
    """Tests de la CLI Click M3."""

    def test_cli_help(self) -> None:
        """La CLI affiche l'aide sans erreur."""
        runner: CliRunner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ADMAP M3" in result.output

    def test_generate_help(self) -> None:
        """La commande generate affiche l'aide."""
        runner: CliRunner = CliRunner()
        result = runner.invoke(cli, ["generate", "--help"])
        assert result.exit_code == 0
        assert "--malware-dir" in result.output
        assert "--benign-dir" in result.output
        assert "--output-dir" in result.output

    def test_validate_help(self) -> None:
        """La commande validate affiche l'aide."""
        runner: CliRunner = CliRunner()
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0
        assert "YARA_FILE" in result.output

    def test_serve_help(self) -> None:
        """La commande serve affiche l'aide."""
        runner: CliRunner = CliRunner()
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output

    def test_generate_no_malware_files(self) -> None:
        """generate avec un dossier malware vide → erreur."""
        runner: CliRunner = CliRunner()
        with tempfile.TemporaryDirectory() as malware_dir, \
             tempfile.TemporaryDirectory() as benign_dir, \
             tempfile.TemporaryDirectory() as output_dir:
            result = runner.invoke(cli, [
                "generate",
                "--malware-dir", malware_dir,
                "--benign-dir", benign_dir,
                "--output-dir", output_dir,
            ])
            assert result.exit_code == 1

    def test_generate_no_benign_files(self) -> None:
        """generate avec des malware mais pas de bénins → erreur."""
        runner: CliRunner = CliRunner()
        with tempfile.TemporaryDirectory() as malware_dir, \
             tempfile.TemporaryDirectory() as benign_dir, \
             tempfile.TemporaryDirectory() as output_dir:
            # Créer un fichier malware
            with open(os.path.join(malware_dir, "malware.txt"), "w") as fh:
                fh.write("CreateRemoteThread VirtualAllocEx evil_payload")
            result = runner.invoke(cli, [
                "generate",
                "--malware-dir", malware_dir,
                "--benign-dir", benign_dir,
                "--output-dir", output_dir,
            ])
            assert result.exit_code == 1

    def test_generate_success(self) -> None:
        """generate avec des fichiers valides → succès."""
        runner: CliRunner = CliRunner()
        with tempfile.TemporaryDirectory() as malware_dir, \
             tempfile.TemporaryDirectory() as benign_dir, \
             tempfile.TemporaryDirectory() as output_dir:
            # Créer des fichiers malware
            for i in range(2):
                with open(os.path.join(malware_dir, f"mal_{i}.txt"), "w") as fh:
                    fh.write(f"CreateRemoteThread VirtualAllocEx evil_payload_{i} shellcode_dropper INJECT001")
            # Créer des fichiers bénins
            for i in range(2):
                with open(os.path.join(benign_dir, f"ben_{i}.txt"), "w") as fh:
                    fh.write(f"CreateFile ReadFile WriteFile CloseHandle normal_op_{i}")

            result = runner.invoke(cli, [
                "generate",
                "--malware-dir", malware_dir,
                "--benign-dir", benign_dir,
                "--output-dir", output_dir,
                "--format", "all",
            ])
            assert result.exit_code == 0
            json_str: str = result.output[result.output.find("{"):]
            output: dict[str, Any] = json.loads(json_str)
            assert output["status"] == "ok"
            assert output["total_rules"] >= 0

    def test_validate_valid_yara(self) -> None:
        """validate avec un fichier YARA valide → succès."""
        runner: CliRunner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False, encoding="utf-8") as fh:
            fh.write('rule test_rule { strings: $a = "test_string" condition: $a }')
            tmp_path: str = fh.name

        try:
            result = runner.invoke(cli, ["validate", tmp_path])
            assert result.exit_code == 0
            output = json.loads(result.output)
            assert output["status"] == "ok"
        finally:
            os.unlink(tmp_path)

    def test_validate_invalid_yara(self) -> None:
        """validate avec un fichier YARA invalide → erreur."""
        runner: CliRunner = CliRunner()
        with tempfile.NamedTemporaryFile(suffix=".yar", mode="w", delete=False, encoding="utf-8") as fh:
            fh.write("rule broken { invalid syntax here }")
            tmp_path: str = fh.name

        try:
            result = runner.invoke(cli, ["validate", tmp_path])
            assert result.exit_code == 1
        finally:
            os.unlink(tmp_path)


class TestListFiles:
    """Tests de la fonction utilitaire _list_files."""

    def test_list_files_empty(self) -> None:
        """Dossier vide → liste vide."""
        with tempfile.TemporaryDirectory() as tmp:
            assert _list_files(tmp) == []

    def test_list_files_with_files(self) -> None:
        """Dossier avec fichiers → liste de chemins."""
        with tempfile.TemporaryDirectory() as tmp:
            for name in ["a.txt", "b.txt"]:
                with open(os.path.join(tmp, name), "w") as fh:
                    fh.write("content")
            files: list[str] = _list_files(tmp)
            assert len(files) == 2

    def test_list_files_recursive(self) -> None:
        """Dossier avec sous-dossiers → liste récursive."""
        with tempfile.TemporaryDirectory() as tmp:
            sub: str = os.path.join(tmp, "sub")
            os.makedirs(sub)
            with open(os.path.join(tmp, "root.txt"), "w") as fh:
                fh.write("root")
            with open(os.path.join(sub, "child.txt"), "w") as fh:
                fh.write("child")
            files: list[str] = _list_files(tmp)
            assert len(files) == 2
