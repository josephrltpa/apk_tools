"""Helpers that shell out to the official Android SDK build-tools binaries.

Requires ``apksigner``, ``zipalign`` and/or ``keytool`` on PATH (or set via
environment variables ``APKSIGNER``, ``ZIPALIGN``, ``KEYTOOL``).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class ToolNotFound(RuntimeError):
    """Raised when a required SDK build-tool binary cannot be located."""


def _find(tool: str, env_var: str) -> str:
    override = os.environ.get(env_var)
    if override:
        return override
    found = shutil.which(tool)
    if not found:
        raise ToolNotFound(
            f"'{tool}' not found on PATH. Install Android SDK build-tools "
            f"or set the {env_var} environment variable."
        )
    return found


def _run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({' '.join(cmd)}):\n{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout


def zipalign(in_apk: str | Path, out_apk: str | Path, pagesize: int = 4) -> None:
    """Align an (unsigned or v1-only-signed) APK using ``zipalign``."""
    tool = _find("zipalign", "ZIPALIGN")
    Path(out_apk).parent.mkdir(parents=True, exist_ok=True)
    _run([tool, "-f", str(pagesize), str(in_apk), str(out_apk)])


def verify_alignment(apk: str | Path, pagesize: int = 4) -> bool:
    """Return True if *apk* is zip-aligned."""
    tool = _find("zipalign", "ZIPALIGN")
    proc = subprocess.run([tool, "-c", str(pagesize), str(apk)],
                          capture_output=True, text=True)
    return proc.returncode == 0


def sign(
    apk: str | Path,
    keystore: str | Path,
    keystore_password: str,
    key_alias: str,
    key_password: str | None = None,
    out: str | Path | None = None,
    min_sdk_version: int | None = None,
) -> Path:
    """Sign *apk* in place (or write to *out*) with ``apksigner``.

    Returns the path of the signed APK.
    """
    tool = _find("apksigner", "APKSIGNER")
    target = Path(out) if out else Path(apk)
    if out:
        shutil.copy2(apk, target)

    cmd = [
        tool, "sign",
        "--ks", str(keystore),
        "--ks-pass", f"pass:{keystore_password}",
        "--ks-key-alias", key_alias,
    ]
    if key_password:
        cmd += ["--key-pass", f"pass:{key_password}"]
    if min_sdk_version is not None:
        cmd += ["--min-sdk-version", str(min_sdk_version)]
    cmd.append(str(target))
    _run(cmd)
    return target


def verify_signature(apk: str | Path) -> str:
    """Verify APK signatures with ``apksigner``; returns its output."""
    tool = _find("apksigner", "APKSIGNER")
    return _run([tool, "verify", "--print-certs", "-v", str(apk)])


def generate_keystore(
    keystore: str | Path,
    alias: str,
    password: str,
    dname: str = "CN=apk_tools,OU=dev,O=none,L=none,ST=none,C=US",
    validity_days: int = 10000,
    key_algorithm: str = "RSA",
    key_size: int = 2048,
) -> Path:
    """Create a new JKS keystore with a single key pair (for debug signing)."""
    tool = _find("keytool", "KEYTOOL")
    path = Path(keystore)
    if path.exists():
        raise FileExistsError(f"Keystore already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    _run([
        tool, "-genkeypair",
        "-keystore", str(path),
        "-storepass", password,
        "-alias", alias,
        "-keypass", password,
        "-dname", dname,
        "-validity", str(validity_days),
        "-keyalg", key_algorithm,
        "-keysize", str(key_size),
    ])
    return path
