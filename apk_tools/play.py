"""Fetch Play Store app metadata and APK download links.

Why this module exists
----------------------
The Google Play ``android-detail`` (rpcid ``AfYHHY``) endpoint that hands out
raw APK blob URLs now requires a **logged-in, authenticated** request (a valid
``ANDROID_AUTH`` token from an actual Play account on a device).  Anonymous
requests return HTTP 400, which is why third-party "APK downloader" websites
exist at all.

What *is* still available anonymously:

* Full app metadata via the public detail page JSON (title, version, developer,
  install count, content rating, ...) -- used by the ``info play`` command.
* The official Play Store install link / ``market://`` deep link -- used by the
  ``install-link`` command so you can sideload onto a phone with one tap.

For actually pulling the APK file without logging in, use a reputable mirror
(see :data:`MIRROR_SITES`) or install through the Play Store itself.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

#: Public mirrors that host Play APKs for direct download (use at your own risk;
#: always verify the package name and signature after downloading).
MIRROR_SITES: dict[str, str] = {
    "apkpure": "https://apkpure.com/{pkg}/download",
    "apkcombo": "https://apkcombo.com/{pkg}/download/armeabi-v7a",
    "uptodown": "https://{pkg}.en.uptodown.com/android/download",
}


def resolve_package(target: str | Path) -> str:
    """Accept a Play Store URL or a bare package id; return the package id."""
    m = re.search(r"[?&]id=([\w.]+)", str(target))
    if m:
        return m.group(1)
    s = str(target)
    if re.fullmatch(r"[\w.]+", s):
        return s
    raise ValueError(f"Could not find a package name in: {target!r}")


@dataclass
class PlayAppInfo:
    package: str
    title: str | None = None
    version: str | None = None
    developer: str | None = None
    installs: str | None = None
    rating: float | None = None
    genre: str | None = None
    updated: str | None = None
    offered_by: list[str] | None = None
    raw_available: bool = False

    @property
    def web_url(self) -> str:
        return f"https://play.google.com/store/apps/details?id={self.package}"

    @property
    def market_link(self) -> str:
        """Deep link that opens the Play Store app directly on a phone."""
        return f"market://details?id={self.package}"

    def mirror_links(self) -> dict[str, str]:
        return {name: tmpl.format(pkg=self.package) for name, tmpl in MIRROR_SITES.items()}


_DS_RE = re.compile(r"AF_initDataCallback\(\{key:\s*'ds:(\d+)'.*?data:(\[.*?\]), sideChannel", re.S)


def _parse_ds_blob(html: str) -> list[list[Any]]:
    """Return every embedded ``ds:N`` JSON payload found on the detail page."""
    out: list[list[Any]] = []
    for m in _DS_RE.finditer(html):
        try:
            out.append(json.loads(m.group(2)))
        except Exception:
            continue
    return out


def _walk_strings(node: Any):
    if isinstance(node, str):
        yield node
    elif isinstance(node, (list, tuple)):
        for child in node:
            yield from _walk_strings(child)


def get_app_info(target: str | Path, *, lang: str = "en", country: str = "in",
                 session: requests.Session | None = None) -> PlayAppInfo:
    """Scrape public metadata for a Play Store app (no login required)."""
    pkg = resolve_package(target)
    sess = session or requests.Session()
    url = f"https://play.google.com/store/apps/details?id={pkg}&hl={lang}&gl={country}"
    r = sess.get(url, headers={"User-Agent": UA}, timeout=30)
    info = PlayAppInfo(package=pkg)
    if r.status_code != 200:
        return info

    blobs = _parse_ds_blob(r.text)
    # Title / developer / version live near the front of ds:5
    strings: list[str] = []
    for b in blobs:
        strings.extend(_walk_strings(b))

    def _first(pattern: str, group: int = 0) -> str | None:
        for s in strings:
            m = re.search(pattern, s)
            if m:
                return m.group(group)
        return None

    info.raw_available = bool(blobs)
    # heuristics tuned to the current Play markup
    for s in strings[:80]:
        if info.title is None and 2 < len(s) < 60 and not s.startswith(("http", ".")) and " " not in s[:1]:
            if re.search(r"[A-Za-z]", s) and not re.match(r"^[\d.,+]+$", s):
                info.title = s
                break
    info.version = _first(r"^\d+(\.\d+)+([ .-]\S+)?$")
    info.installs = _first(r"\d[\d,.]*\+?\s*(?:downloads|installed|installs)?", 0)
    info.rating = None
    for s in strings:
        m = re.match(r"^(\d\.\d)$", s)
        if m:
            info.rating = float(m.group(1))
            break
    return info


def install_commands(pkg_or_url: str | Path) -> list[tuple[str, str]]:
    """Return ready-to-run shell commands that install the app on a device."""
    pkg = resolve_package(pkg_or_url)
    web = f"https://play.google.com/store/apps/details?id={pkg}"
    return [
        ("Open in Play Store on connected phone (ADB)",
         f'adb shell am start -a android.intent.action.VIEW -d "market://details?id={pkg}"'),
        ("Open Play Store web page on phone (ADB)",
         f'adb shell am start -a android.intent.action.VIEW -d "{web}"'),
        ("Install over ADB from a locally downloaded APK",
         f"adb install -r {pkg}.apk"),
        ("Install a split-APK bundle downloaded from Play",
         f'adb install-multiple {pkg}/*.apk'),
    ]
