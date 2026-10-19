"""apk_tools command-line interface.

Usage examples:
    apk-tools info app.apk
    apk-tools info app.apk --json
    apk-tools extract app.apk -o ./out
    apk-tools sign app.apk --keystore release.jks --storepass SECRET --alias mykey
    apk-tools verify app.apk
    apk-tools zipalign in.apk out.apk
    apk-tools keystore debug.jks --alias androiddebugkey --storepass android
    apk-tools play "https://play.google.com/store/apps/details?id=com.dord.nmms"
    apk-tools play com.dord.nmms --install-link
    apk-tools download com.dord.nmms -o ./downloads
"""

from __future__ import annotations

import argparse
import sys

import requests
from pathlib import Path

from . import __version__, sign as sign_mod
from .extract import safe_extract
from .info import print_info
from . import play as play_mod
from . import download as download_mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apk-tools",
        description="Inspect, extract, align and sign Android APK files.",
    )
    parser.add_argument("--version", action="version", version=f"apk-tools {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="Show APK metadata and entry summary")
    p_info.add_argument("apk", help="Path to the APK file")
    p_info.add_argument("--json", action="store_true", help="Print JSON output")

    p_extract = sub.add_parser("extract", help="Extract APK contents safely")
    p_extract.add_argument("apk", help="Path to the APK file")
    p_extract.add_argument("-o", "--out", default=".", help="Destination directory (default: .)")

    p_sign = sub.add_parser("sign", help="Sign an APK with apksigner")
    p_sign.add_argument("apk", help="Path to the (zip-aligned) APK file")
    p_sign.add_argument("--keystore", required=True, help="Path to the .jks/.keystore file")
    p_sign.add_argument("--storepass", required=True, help="Keystore password")
    p_sign.add_argument("--alias", required=True, help="Key alias")
    p_sign.add_argument("--keypass", default=None, help="Key password (defaults to storepass)")
    p_sign.add_argument("-o", "--out", default=None, help="Output path (default: sign in place)")
    p_sign.add_argument("--min-sdk-version", type=int, default=None)

    p_verify = sub.add_parser("verify", help="Verify APK signatures with apksigner")
    p_verify.add_argument("apk", help="Path to the APK file")

    p_align = sub.add_parser("zipalign", help="Zip-align an APK")
    p_align.add_argument("apk", help="Input APK")
    p_align.add_argument("out", help="Output aligned APK")
    p_align.add_argument("--check", action="store_true", help="Only check alignment of 'apk'")

    p_ks = sub.add_parser("keystore", help="Generate a new keystore (for debug signing)")
    p_ks.add_argument("path", help="Output keystore path")
    p_ks.add_argument("--alias", default="androiddebugkey")
    p_ks.add_argument("--storepass", default="android")
    p_ks.add_argument("--cn", default="CN=apk_tools,OU=dev,O=none,L=none,ST=none,C=US")

    p_play = sub.add_parser(
        "play",
        help="Look up a Google Play app (URL or package id) and print install/download options",
    )
    p_play.add_argument("target", help="Play Store URL (e.g. https://play.google.com/store/apps/details?id=com.dord.nmms) or package id")
    p_play.add_argument("--lang", default="en", help="Store language (default: en)")
    p_play.add_argument("--country", default="in", help="Store country (default: in)")
    p_play.add_argument("--install-link", action="store_true",
                        help="Only print ready-to-run adb install / deep-link commands")
    p_play.add_argument("--json", action="store_true", help="Print JSON output")

    p_dl = sub.add_parser(
        "download",
        help="Download the APK(s) of a Google Play app (URL or package id)",
    )
    p_dl.add_argument("target", help="Play Store URL or package id (e.g. com.dord.nmms)")
    p_dl.add_argument("-o", "--out", default="./downloads",
                      help="Output directory (default: ./downloads)")
    p_dl.add_argument("--lang", default="en_IN", help="Store language (default: en_IN)")
    p_dl.add_argument("--country", default="in", help="Store country code (default: in)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "info":
            print_info(args.apk, as_json=args.json)
        elif args.command == "extract":
            files = safe_extract(args.apk, args.out)
            print(f"Extracted {len(files)} entries to {Path(args.out).resolve()}")
        elif args.command == "sign":
            out = sign_mod.sign(
                args.apk, args.keystore, args.storepass, args.alias,
                key_password=args.keypass or args.storepass,
                out=args.out, min_sdk_version=args.min_sdk_version,
            )
            print(f"Signed APK written to: {out}")
        elif args.command == "verify":
            print(sign_mod.verify_signature(args.apk))
        elif args.command == "zipalign":
            if args.check:
                ok = sign_mod.verify_alignment(args.apk)
                print("Aligned" if ok else "NOT aligned")
                return 0 if ok else 1
            sign_mod.zipalign(args.apk, args.out)
            print(f"Aligned APK written to: {args.out}")
        elif args.command == "keystore":
            path = sign_mod.generate_keystore(args.path, args.alias, args.storepass, dname=args.cn)
            print(f"Created keystore: {path} (alias={args.alias})")
        elif args.command == "play":
            if args.install_link:
                for label, cmd in play_mod.install_commands(args.target):
                    print(f"# {label}\n{cmd}\n")
            else:
                info = play_mod.get_app_info(args.target, lang=args.lang, country=args.country)
                if args.json:
                    import json as _json
                    print(_json.dumps(info.to_dict(), indent=2, ensure_ascii=False))
                else:
                    print(_render_play_info(info))
                    print("\nMirror download pages:")
                    for name, url in info.mirror_links().items():
                        print(f"  {name}: {url}")
        elif args.command == "download":
            written = download_mod.download_app(args.target, out_dir=args.out)
            print(f"\nDownloaded {len(written)} file(s):")
            for p in written:
                size = Path(p).stat().st_size / 1048576
                print(f"  {p}  ({size:.1f} MB)")
    except (FileNotFoundError, ValueError, RuntimeError, FileExistsError,
            requests.exceptions.RequestException) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except sign_mod.ToolNotFound as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def _render_play_info(info) -> str:
    """Format a PlayAppInfo for terminal output."""
    lines = [f"Package   : {info.package}",
             f"Title     : {info.title or '(unknown)'}",
             f"Version   : {info.version or '(unknown)'}",
             f"Developer : {info.developer or '(unknown)'}",
             f"Installs  : {info.installs or '(unknown)'}",
             f"Rating    : {info.rating if info.rating is not None else '(unknown)'}",
             f"Play page : {info.web_url}"]
    return "\n".join(lines)
