# -*- coding: utf-8 -*-
# This file is part of Quark-Engine - https://github.com/quark-engine/quark-engine
# See the file 'LICENSE' for copying permission.

"""
Built-in Deobfuscator

Integrates jadx's deobfuscation as a pre-processing step before Quark-Engine
runs its crime detection rules. By renaming obfuscated class/method names via
jadx's ``--deobf`` flag, analysis accuracy improves significantly on heavily
obfuscated malware APKs.

Usage::

    from quark.deobfuscator import deobfuscate_apk

    deobf_dir = deobfuscate_apk("/path/to/sample.apk", "/tmp/deobf_out")
    if deobf_dir:
        # deobf_dir contains the jadx output with renamed symbols
        ...

Reference: https://github.com/skylot/jadx (--deobf option)
"""

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _find_jadx() -> Optional[str]:
    """Return the path to the ``jadx`` binary, or None if not found."""
    return shutil.which("jadx")


def deobfuscate_apk(
    apk_path: str,
    output_dir: Optional[str] = None,
    deobf_min_len: int = 3,
    deobf_max_len: int = 64,
) -> Optional[str]:
    """Run jadx deobfuscation on an APK and return the output directory.

    Uses jadx's ``--deobf`` flag to rename obfuscated class/method names
    before Quark-Engine processes the APK.  Falls back gracefully if jadx
    is not installed.

    :param apk_path: Path to the APK file to deobfuscate.
    :param output_dir: Directory where jadx writes its output.  A temporary
        directory is created automatically when this is ``None``.
    :param deobf_min_len: Minimum identifier length to trigger renaming
        (passed as ``--deobf-min``).  Defaults to ``3``.
    :param deobf_max_len: Maximum identifier length to trigger renaming
        (passed as ``--deobf-max``).  Defaults to ``64``.
    :returns: Path to the output directory on success, or ``None`` if jadx
        is unavailable or deobfuscation failed.
    :raises FileNotFoundError: If *apk_path* does not exist.
    """
    apk_path = str(apk_path)
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    jadx_bin = _find_jadx()
    if jadx_bin is None:
        logger.warning(
            "jadx is not installed or not on PATH — skipping deobfuscation. "
            "Install jadx (https://github.com/skylot/jadx) to enable this feature."
        )
        return None

    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="quark_deobf_")
    else:
        os.makedirs(output_dir, exist_ok=True)

    cmd = [
        jadx_bin,
        "--deobf",
        "--deobf-min", str(deobf_min_len),
        "--deobf-max", str(deobf_max_len),
        "--output-dir", output_dir,
        apk_path,
    ]

    logger.info("Running jadx deobfuscation: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.error("jadx deobfuscation timed out for %s", apk_path)
        return None
    except OSError as exc:
        logger.error("Failed to execute jadx: %s", exc)
        return None

    if result.returncode != 0:
        stderr_msg = result.stderr.decode(errors="replace").strip()
        logger.error(
            "jadx exited with code %d: %s", result.returncode, stderr_msg
        )
        return None

    logger.info("Deobfuscation complete. Output: %s", output_dir)
    return output_dir


def is_jadx_available() -> bool:
    """Return ``True`` if jadx is available on the system PATH."""
    return _find_jadx() is not None
