"""Extract metadata from an APK: manifest, permissions, size, and entry summary."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def summarize(apk_path: str | Path) -> dict[str, Any]:
    """Return a JSON-serializable summary of the APK at *apk_path*."""
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK not found: {path}")

    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        entries = [
            {
                "name": info.filename,
                "compressed": info.compress_size,
                "uncompressed": info.file_size,
            }
            for info in zf.infolist()
        ]

        has_manifest = "AndroidManifest.xml" in names
        dex_files = [n for n in names if n.endswith(".dex")]
        native_libs = [n for n in names if n.startswith("lib/")]
        resources = [n for n in names if n.startswith("res/")]
        assets = [n for n in names if n.startswith("assets/")]

        # Best-effort plain-text manifest (binary AXML needs androguard).
        manifest_snippet = ""
        if has_manifest:
            raw = zf.read("AndroidManifest.xml")
            if raw[:4] not in (b"\x03\x00\x08\x00", b"\x01\x00\x10\x00"):
                manifest_snippet = raw.decode("utf-8", errors="replace")[:2000]

        result = {
            "file": str(path),
            "size_human": _human_size(path.stat().st_size),
            "size_bytes": path.stat().st_size,
            "entry_count": len(names),
            "has_android_manifest": has_manifest,
            "manifest_is_binary_axml": bool(has_manifest and not manifest_snippet),
            "dex_files": dex_files,
            "native_library_abi_dirs": sorted(
                {n.split("/")[1] for n in native_libs if len(n.split("/")) > 2}
            ),
            "resource_file_count": len(resources),
            "asset_file_count": len(assets),
            "largest_entries": sorted(entries, key=lambda e: e["uncompressed"], reverse=True)[:10],
        }
        if manifest_snippet:
            result["manifest_text_preview"] = manifest_snippet
        return result


def print_info(apk_path: str | Path, as_json: bool = False) -> None:
    data = summarize(apk_path)
    if as_json:
        print(json.dumps(data, indent=2))
        return
    print(f"APK           : {data['file']}")
    print(f"Size          : {data['size_human']} ({data['size_bytes']} bytes)")
    print(f"Entries       : {data['entry_count']}")
    print(
        f"Manifest      : {'present' if data['has_android_manifest'] else 'MISSING'}"
        + (" (binary AXML - use androguard/apkanalyzer to decode)"
           if data["manifest_is_binary_axml"] else "")
    )
    print(f"DEX files     : {', '.join(data['dex_files']) or 'none'}")
    print(f"Native ABIs   : {', '.join(data['native_library_abi_dirs']) or 'none'}")
    print(f"Resources     : {data['resource_file_count']} files under res/")
    print(f"Assets        : {data['asset_file_count']} files under assets/")
    print("\nLargest entries:")
    for e in data["largest_entries"]:
        print(f"  {_human_size(e['uncompressed']):>10}  {e['name']}")
