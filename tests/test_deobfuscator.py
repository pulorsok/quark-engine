# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

"""Tests for quark.deobfuscator module."""

import os
import subprocess
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from quark.deobfuscator import _find_jadx, deobfuscate_apk, is_jadx_available


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_fake_apk(tmp_path) -> str:
    """Create a minimal (empty) file that acts as a fake APK for path checks."""
    apk = os.path.join(str(tmp_path), "sample.apk")
    with open(apk, "wb") as fh:
        fh.write(b"PK")  # fake APK header
    return apk


# ---------------------------------------------------------------------------
# is_jadx_available / _find_jadx
# ---------------------------------------------------------------------------

class TestIsJadxAvailable:
    def test_returns_true_when_jadx_on_path(self):
        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"):
            assert is_jadx_available() is True

    def test_returns_false_when_jadx_missing(self):
        with patch("quark.deobfuscator.shutil.which", return_value=None):
            assert is_jadx_available() is False

    def test_find_jadx_returns_none_when_missing(self):
        with patch("quark.deobfuscator.shutil.which", return_value=None):
            assert _find_jadx() is None

    def test_find_jadx_returns_path_when_present(self):
        with patch("quark.deobfuscator.shutil.which", return_value="/opt/jadx/bin/jadx"):
            assert _find_jadx() == "/opt/jadx/bin/jadx"


# ---------------------------------------------------------------------------
# deobfuscate_apk — missing jadx
# ---------------------------------------------------------------------------

class TestDeobfuscateApkNoJadx:
    def test_returns_none_gracefully_when_jadx_missing(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        with patch("quark.deobfuscator.shutil.which", return_value=None):
            result = deobfuscate_apk(apk)
        assert result is None

    def test_does_not_raise_when_jadx_missing(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        with patch("quark.deobfuscator.shutil.which", return_value=None):
            # Should not raise any exception
            deobfuscate_apk(apk)


# ---------------------------------------------------------------------------
# deobfuscate_apk — file not found
# ---------------------------------------------------------------------------

class TestDeobfuscateApkFileNotFound:
    def test_raises_file_not_found_for_missing_apk(self):
        with pytest.raises(FileNotFoundError):
            deobfuscate_apk("/nonexistent/path/sample.apk")


# ---------------------------------------------------------------------------
# deobfuscate_apk — correct subprocess invocation
# ---------------------------------------------------------------------------

class TestDeobfuscateApkSubprocess:
    def test_passes_deobf_flags_to_jadx(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        out_dir = str(tmp_path / "out")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch("quark.deobfuscator.subprocess.run", return_value=mock_result) as mock_run:
            result = deobfuscate_apk(apk, out_dir)

        assert result == out_dir
        called_cmd = mock_run.call_args[0][0]
        assert "--deobf" in called_cmd
        assert "--deobf-min" in called_cmd
        assert "--deobf-max" in called_cmd
        assert "--output-dir" in called_cmd
        assert apk in called_cmd

    def test_uses_custom_min_max_lengths(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        out_dir = str(tmp_path / "out")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch("quark.deobfuscator.subprocess.run", return_value=mock_result) as mock_run:
            deobfuscate_apk(apk, out_dir, deobf_min_len=5, deobf_max_len=32)

        called_cmd = mock_run.call_args[0][0]
        min_idx = called_cmd.index("--deobf-min")
        max_idx = called_cmd.index("--deobf-max")
        assert called_cmd[min_idx + 1] == "5"
        assert called_cmd[max_idx + 1] == "32"

    def test_returns_none_on_nonzero_exit(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        out_dir = str(tmp_path / "out")

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = b"ERROR: something went wrong"

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch("quark.deobfuscator.subprocess.run", return_value=mock_result):
            result = deobfuscate_apk(apk, out_dir)

        assert result is None

    def test_returns_none_on_timeout(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        out_dir = str(tmp_path / "out")

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch(
                "quark.deobfuscator.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="jadx", timeout=300),
             ):
            result = deobfuscate_apk(apk, out_dir)

        assert result is None

    def test_creates_output_dir_automatically(self, tmp_path):
        apk = _make_fake_apk(tmp_path)
        # Use a subdirectory that does not exist yet
        out_dir = str(tmp_path / "nested" / "output")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch("quark.deobfuscator.subprocess.run", return_value=mock_result):
            result = deobfuscate_apk(apk, out_dir)

        assert result == out_dir
        assert os.path.isdir(out_dir)

    def test_creates_temp_dir_when_output_dir_is_none(self, tmp_path):
        apk = _make_fake_apk(tmp_path)

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("quark.deobfuscator.shutil.which", return_value="/usr/bin/jadx"), \
             patch("quark.deobfuscator.subprocess.run", return_value=mock_result):
            result = deobfuscate_apk(apk, output_dir=None)

        assert result is not None
        assert os.path.isdir(result)
