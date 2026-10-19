"""Extract APK contents (a ZIP archive) to a directory."""

from __future__ import annotations

import zipfile
from pathlib import Path


def safe_extract(apk_path: str | Path, dest: str | Path = ".") -> list[str]:
    """Safely extract all entries of an APK into *dest*.

    Guards against path-traversal ("zip slip") attacks. Returns the list
    of extracted file paths.
    """
    apk = Path(apk_path)
    out = Path(dest).resolve()
    out.mkdir(parents=True, exist_ok=True)

    extracted: list[str] = []
    prefix = str(out) + "/"
    with zipfile.ZipFile(apk) as zf:
        for member in zf.infolist():
            target = (out / member.filename).resolve()
            if not (str(target) == str(out) or str(target).startswith(prefix)):
                raise ValueError(f"Unsafe zip entry detected (path traversal): {member.filename}")
            zf.extract(member, out)
            extracted.append(str(target))
    return extracted
