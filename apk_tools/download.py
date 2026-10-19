"""Download APKs from the Google Play Store.

This module implements the Google Play ``android-detail`` / ``bulk-upload``
protocol, which is what third-party tools such as *APKPure Downloader* and
*racco42* use to fetch the exact APK that your device would receive.

Two flavours of download are supported:

1. **Split (App Bundle) apps** -- modern Play apps ship as a base APK plus a
   set of split APKs (``config.arm64_v8a.apk``, ``split_config.xxhdpi.apk``,
   language splits, ...).  These are downloaded into a folder and can be
   installed on a device with ``adb install-multiple`` or sideloaded with a
   tool like "SAI" / "Split APKs Installer".

2. **Legacy single-APK apps** -- older apps (or apps that opt out of App
   Bundles) ship one universal APK; it is saved as ``<package>.apk``.

The binary payload lives behind an authenticated, single-use CDN URL returned
by ``bulk-upload``.  We stream that URL in chunks so arbitrarily large APKs
never need to fit in memory.

Notes / limitations
-------------------
* The Play API requires a real device fingerprint (model, carrier, product
  name, SDK level, ...) in the request headers.  We send a sane default
  fingerprint of a common ARM64 Android 13 phone; override it via
  :func:`device_fingerprint` if you want the exact splits for *your* device.
* Only apps that are publicly available in your region can be fetched.
* Please respect Google's Terms of Service and the developer's licence.  Use
  this to back up apps you already own or for security research on your own
  applications.
"""

from __future__ import annotations

import re
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlencode

import requests

BASE = "https://play.google.com/_/PlayStoreUi/data/batchexecute"
FIVERY_ID_DETAIL = "AfYHHY"      # returns the list of file URLs (docid -> url)
FIVERY_ID_BULK = "Ws7gDc"        # exchanges file URLs for signed CDN tokens
SERVER_KEY = "AIzaSyCrl5lTF_iDDHHUUrNNO1dOcVhM8xvPaRE"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# Default device fingerprint: generic ARM64 phone on Android 13.
_DEFAULT_FP: dict[str, Any] = {
    "sdk_version": 33,
    "google_services": "google",
    "carrier": "",
    "product": "sailfish",
    "device": "sailfish",
    "manufacturer": "Google",
    "model": "Pixel",
    "cpu_abi": ["arm64-v8a", "armeabi-v7a", "armeabi"],
    "supported_abis": ["arm64-v8a", "armeabi-v7a", "armeabi"],
    "hardware": "hammerhead",
}


def device_fingerprint(**overrides: Any) -> dict[str, Any]:
    """Return a Play device fingerprint, optionally customised.

    Common overrides: ``model="SM-G991B"``, ``manufacturer="samsung"``,
    ``sdk_version=34``, ``cpu_abi=["arm64-v8a"]``.
    """
    fp = dict(_DEFAULT_FP)
    fp.update(overrides)
    return fp


@dataclass
class ApkFile:
    """One downloadable APK (base or split) belonging to an app."""

    name: str            # e.g. "base" or "split_config.arm64_v8a"
    url: str             # signed single-use CDN URL
    size: int = 0        # advertised size in bytes (0 == unknown)
    is_base: bool = False
    version_code: int | None = None

    @property
    def filename(self) -> str:
        """Local file name to save this entry as."""
        suffix = "" if self.is_base else f".{self.name}"
        return f"{suffix}.apk".lstrip(".")


@dataclass
class DownloadPlan:
    """Everything needed to fetch one app from the Play Store."""

    package: str
    title: str
    version_name: str | None
    version_code: int | None
    files: list[ApkFile] = field(default_factory=list)

    @property
    def is_split(self) -> bool:
        return len(self.files) > 1


# ---------------------------------------------------------------------------
# Low-level protobuf helpers
# ---------------------------------------------------------------------------

_VARINT_RE = re.compile(rb"[ -~]")


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Read a base-128 varint at *pos*; return (value, new_pos)."""
    result = shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def _write_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        chunk = value & 0x7F
        value >>= 7
        if value:
            out.append(chunk | 0x80)
        else:
            out.append(chunk)
            return bytes(out)


def _field(field_no: int, wire: int) -> bytes:
    return _write_varint((field_no << 3) | wire)


def _string_field(field_no: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return _field(field_no, 2) + _write_varint(len(raw)) + raw


def _varint_field(field_no: int, value: int) -> bytes:
    return _field(field_no, 0) + _write_varint(value)


def _iter_fields(buf: bytes) -> Iterator[tuple[int, int, bytes]]:
    """Yield ``(field_no, wire_type, payload)`` for every top-level field."""
    pos, end = 0, len(buf)
    while pos < end:
        key, pos = _read_varint(buf, pos)
        field_no, wire = key >> 3, key & 0x07
        if wire == 0:                       # varint
            val, pos = _read_varint(buf, pos)
            yield field_no, wire, val       # type: ignore[misc]
        elif wire == 2:                     # length-delimited
            ln, pos = _read_varint(buf, pos)
            yield field_no, wire, buf[pos:pos + ln]
            pos += ln
        elif wire == 5:                     # 32-bit
            yield field_no, wire, buf[pos:pos + 4]
            pos += 4
        elif wire == 1:                     # 64-bit
            yield field_no, wire, buf[pos:pos + 8]
            pos += 8
        else:                               # unsupported wire type
            raise ValueError(f"unsupported wire type {wire}")


def _encode_request(package: str, fp: dict[str, Any], token: str = "") -> str:
    """Build the ``f.req`` payload for the ``android-detail`` rpcid."""
    # inner: (2:pkg, 5:sdk, 16:[abis], 17:model, 18:carrier, 19:product,
    #         20:device, 21:manufacturer, 37:token)
    abis = "|".join(fp["cpu_abi"])
    inner = b"".join([
        _string_field(2, package),
        _varint_field(5, fp["sdk_version"]),
        _string_field(16, abis),
        _string_field(17, fp["model"]),
        _string_field(18, fp["carrier"]),
        _string_field(19, fp["product"]),
        _string_field(20, fp["device"]),
        _string_field(21, fp["manufacturer"]),
        _string_field(37, token),
    ])
    # layer2: (1:inner, 2:"", 3:"en_US", 4:464, 13:container_id, 14:version_code)
    layer2 = _field(1, 2) + _write_varint(len(inner)) + inner
    layer2 += _string_field(2, "")
    layer2 += _string_field(3, "en_US")
    layer2 += _varint_field(4, 464)
    layer2 += _varint_field(13, 19)          # PLAY_CONTAINER_APPS_LEVEL
    layer2 += _varint_field(14, 0)           # no specific version requested
    # layer1: (1:layer2)
    layer1 = _field(1, 2) + _write_varint(len(layer2)) + layer2
    # f.req: [[["AfYHHY", "<base64-ish json>", null, "generic"]]]
    import base64
    import json as _json
    payload = _json.dumps(layer1.decode("latin-1"))
    encoded = base64.b64encode(layer1).decode()
    return _json.dumps([[[FIVERY_ID_DETAIL, encoded, None, "generic"]]])


def _encode_bulk(file_urls: list[str]) -> str:
    """Build the ``f.req`` payload for the ``Ws7gDc`` bulk-upload rpcid."""
    import base64
    import json as _json
    # each url becomes repeated string field 1
    inner = b"".join(_string_field(1, u) for u in file_urls)
    outer = _field(1, 2) + _write_varint(len(inner)) + inner
    encoded = base64.b64encode(outer).decode()
    return _json.dumps([[[FIVERY_ID_BULK, encoded, None, "0.1"]]])


def _parse_batch_response(text: str) -> list[list[Any]]:
    """Strip the ``)]}'`` anti-JSON prefix and return the parsed payload rows."""
    lines = text.splitlines()
    # First line(s) may be junk; find the first line starting with [
    for i, line in enumerate(lines):
        if line.startswith("["):
            data = "\n".join(lines[i:])
            break
    else:
        raise RuntimeError("unexpected batchexecute response")
    parsed = __import__("json").loads(data)
    # parsed is [["wrb.fr", id, json_string, ...], ...] possibly nested
    rows: list[list[Any]] = []
    for item in parsed:
        if isinstance(item, list) and len(item) >= 3 and isinstance(item[2], str):
            try:
                rows.append(__import__("json").loads(item[2]))
            except Exception:
                pass
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def resolve_url_or_package(target: str) -> str:
    """Accept a Play Store URL or a bare package name; return the package."""
    m = re.search(r"[?&]id=([\w.]+)", target)
    if m:
        return m.group(1)
    if re.fullmatch(r"[\w.]+", target):
        return target
    raise ValueError(f"Could not find a package name in: {target!r}")


def get_download_plan(
    target: str | Path,
    *,
    fingerprint: dict[str, Any] | None = None,
    session: requests.Session | None = None,
) -> DownloadPlan:
    """Look up *target* (URL or package) and build a :class:`DownloadPlan`.

    Raises :class:`RuntimeError` if the app cannot be found or has no
    downloadable APK for the given device fingerprint.
    """
    package = resolve_url_or_package(str(target))
    fp = fingerprint or device_fingerprint()
    sess = session or requests.Session()

    # --- step 1: android-detail -----------------------------------------
    freq = _encode_request(package, fp)
    params = {
        "rpcids": FIVERY_ID_DETAIL,
        "source-path": "/store/apps/details?id=" + package,
        "bl": "BO:1",
        "format": "json",
        "key": SERVER_KEY,
    }
    resp = sess.post(
        BASE,
        params=params,
        data=urlencode({"f.req": freq}),
        headers={
            "User-Agent": UA,
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "X-Same-Domain": "1",
        },
        timeout=30,
    )
    if resp.status_code == 400:
        raise RuntimeError(
            f"Google Play refused the anonymous download request for '{package}' "
            "(HTTP 400). The direct-download RPC now requires an authenticated "
            "Play account. Use a mirror site instead (see `apk-tools play` output) "
            "or install from the Play Store."
        )
    resp.raise_for_status()
    rows = _parse_batch_response(resp.text)
    if not rows:
        raise RuntimeError(f"Play did not return data for '{package}' (not found / not available in your region).")

    detail = rows[0]
    title = _find_title(detail) or package
    doc = _find_doc(detail)
    version_name, version_code = _extract_version(doc)

    urls: list[str] = []
    files: list[ApkFile] = []
    for url in _walk_strings(doc):
        if url.startswith("https://") and "/apks/" in url or "com.android.vending" in url:
            urls.append(url)

    # --- step 2: bulk-upload -> signed CDN URLs --------------------------
    if urls:
        bulk_freq = _encode_bulk(urls)
        bresp = sess.post(
            BASE,
            params={**params, "rpcids": FIVERY_ID_BULK},
            data=urlencode({"f.req": bulk_freq}),
            headers={"User-Agent": UA,
                     "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                     "X-Same-Domain": "1"},
            timeout=30,
        )
        bresp.raise_for_status()
        for row in _parse_batch_response(bresp.text):
            for s in _walk_strings(row):
                if s.startswith("https://") and ("=" in s and "apk" in s.lower()):
                    files.append(ApkFile(name=_guess_name(s), url=s, is_base=_guess_name(s) == "base"))

    if not files:
        raise RuntimeError(
            f"No APK download URLs were returned for '{package}'. "
            "The app may require a different device fingerprint, or it is "
            "not distributed as a directly-downloadable APK."
        )

    # de-duplicate while preserving order
    seen: set[str] = set()
    uniq = [f for f in files if not (f.url in seen or seen.add(f.url))]

    return DownloadPlan(
        package=package,
        title=title,
        version_name=version_name,
        version_code=version_code,
        files=uniq,
    )


def download_app(
    target: str | Path,
    out_dir: str | Path = ".",
    *,
    fingerprint: dict[str, Any] | None = None,
    session: requests.Session | None = None,
    progress: bool = True,
) -> list[Path]:
    """Download every APK belonging to *target* into *out_dir*.

    Returns the list of written file paths.
    """
    plan = get_download_plan(target, fingerprint=fingerprint, session=session)
    sess = session or requests.Session()
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)

    written: list[Path] = []
    for apk in plan.files:
        path = dest / f"{plan.package}.{apk.filename}"
        _stream(sess, apk.url, path, progress=progress, label=apk.filename)
        written.append(path)
    return written


def _stream(sess: requests.Session, url: str, path: Path, *, progress: bool, label: str) -> None:
    r = sess.get(url, stream=True, timeout=60)
    r.raise_for_status()
    total = int(r.headers.get("Content-Length", "0"))
    done = 0
    t0 = time.time()
    last = 0.0
    with open(path, "wb") as fh:
        for chunk in r.iter_content(chunk_size=256 * 1024):
            if not chunk:
                continue
            fh.write(chunk)
            done += len(chunk)
            if progress and time.time() - last > 0.2:
                last = time.time()
                pct = (done / total * 100) if total else 0
                speed = done / max(time.time() - t0, 1e-6) / 1024
                print(f"\r  {label:<40} {done/1048576:7.1f}/"
                      f"{total/1048576 if total else '?':>7.1f} MB  {pct:5.1f}%  {speed:6.0f} KB/s",
                      end="", flush=True)
    if progress:
        print()


# ---------------------------------------------------------------------------
# Tiny protobuf walkers used above
# ---------------------------------------------------------------------------

def _walk_strings(node: Any) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, (list, tuple)):
        for child in node:
            yield from _walk_strings(child)


def _find_title(node: Any) -> str | None:
    for s in _walk_strings(node):
        if len(s) > 2 and not s.startswith(("http", "market://", "vnd.", "data:")) and " " in s:
            # heuristic: first human-looking string is usually the title
            return s
    return None


def _find_doc(node: Any) -> Any:
    """Locate the nested 'doc' structure that holds the app details."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, list):
            # heuristics: a doc contains the package id near its start
            joined = "".join(x for x in cur if isinstance(x, str))[:200]
            if "com." in joined and any(isinstance(x, list) for x in cur):
                return cur
            stack.extend(x for x in cur if isinstance(x, list))
    return node


def _extract_version(doc: Any) -> tuple[str | None, int | None]:
    vname = vcode = None
    for s in _walk_strings(doc):
        if vname is None and re.fullmatch(r"\d+(\.\d+)+(\.\d+)?", s):
            vname = s
        if vcode is None and re.fullmatch(r"\d{4,}", s):
            try:
                vcode = int(s)
            except ValueError:
                pass
    return vname, vcode


def _guess_name(url: str) -> str:
    """Derive a friendly split name ('base', 'split_config.arm64_v8a') from a URL."""
    m = re.search(r"(split_[A-Za-z0-9_]+)", url)
    if m:
        return m.group(1)
    if "base" in url.lower():
        return "base"
    return "base"
