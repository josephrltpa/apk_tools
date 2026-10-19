"""Tests for apk_tools info/extract using a synthetic fake APK (a zip file)."""

import json
import zipfile
from io import BytesIO

import pytest

from apk_tools.extract import safe_extract
from apk_tools.info import print_info, summarize


@pytest.fixture
def fake_apk(tmp_path):
    """Build a minimal zip that mimics APK structure."""
    apk = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"<manifest package='com.example.app'/>")
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        zf.writestr("res/values/strings.xml", b"<resources/>")
        zf.writestr("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 50)
        zf.writestr("assets/data.bin", b"A" * 200)
    return apk


def test_summarize(fake_apk):
    data = summarize(fake_apk)
    assert data["has_android_manifest"] is True
    assert data["manifest_is_binary_axml"] is False
    assert "classes.dex" in data["dex_files"]
    assert "arm64-v8a" in data["native_library_abi_dirs"]
    assert data["resource_file_count"] == 1
    assert data["asset_file_count"] == 1
    assert data["entry_count"] == 5
    assert "com.example.app" in data["manifest_text_preview"]


def test_summarize_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        summarize(tmp_path / "nope.apk")


def test_print_info_json(fake_apk, capsys):
    print_info(fake_apk, as_json=True)
    out = json.loads(capsys.readouterr().out)
    assert out["entry_count"] == 5


def test_safe_extract(fake_apk, tmp_path):
    dest = tmp_path / "out"
    files = safe_extract(fake_apk, dest)
    assert len(files) == 5
    assert (dest / "AndroidManifest.xml").is_file()
    assert (dest / "lib/arm64-v8a/libnative.so").is_file()


def test_safe_extract_blocks_zip_slip(tmp_path):
    evil = tmp_path / "evil.apk"
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../escape.txt", b"pwned")
    evil.write_bytes(buf.getvalue())
    with pytest.raises(ValueError, match="path traversal"):
        safe_extract(evil, tmp_path / "out")
