# apk_tools

A Python command-line toolkit to **inspect, extract, zip-align and sign Android APK files**.

`apk_tools` wraps the tedious parts of working with APKs:

- `info` — quick structural summary of any APK (entries, DEX files, native ABIs, resources, manifest preview), human-readable or JSON.
- `extract` — safely unpack an APK (protects against "zip-slip" path-traversal attacks).
- `zipalign` / `sign` / `verify` — thin wrappers around the official Android SDK build-tools (`zipalign`, `apksigner`).
- `keystore` — generate a keystore for debug signing via `keytool`.

## Requirements

- Python **3.9+**
- For alignment/signing: Android SDK **build-tools** on your `PATH`
  (`apksigner`, `zipalign`) and JDK's `keytool`. You can also point at them
  explicitly via the `APKSIGNER`, `ZIPALIGN`, and `KEYTOOL` environment variables.
  (`info` and `extract` work with no external tools.)

## Installation

```bash
pip install .
# or for development:
pip install -e ".[dev]"
```

## Usage

```bash
# Inspect an APK
apk-tools info app.apk
apk-tools info app.apk --json

# Extract contents safely
apk-tools extract app.apk -o ./unpacked

# Zip-align (must be done BEFORE v1 signing; after re-zipping for v2+)
apk-tools zipalign unsigned.apk aligned.apk
apk-tools zipalign aligned.apk --check --unused  # check only

# Generate a debug keystore
apk-tools keystore debug.jks --alias androiddebugkey --storepass android

# Sign and verify
apk-tools sign aligned.apk --keystore debug.jks --storepass android --alias androiddebugkey
apk-tools verify aligned.apk
```

Or run without installing:

```bash
python -m apk_tools.cli info app.apk
```

## Library use

```python
from apk_tools.info import summarize
from apk_tools.extract import safe_extract

meta = summarize("app.apk")
print(meta["dex_files"], meta["native_library_abi_dirs"])

safe_extract("app.apk", "./out")
```

## Project layout

```
apk_tools/
  __init__.py   # package metadata
  cli.py        # argparse CLI (apk-tools ...)
  info.py       # APK structure summary
  extract.py    # safe extraction
  sign.py       # zipalign / apksigner / keytool wrappers
tests/
  test_apk_tools.py
pyproject.toml
```

## Notes on binary manifests

Real APKs store `AndroidManifest.xml` in **binary AXML** format. `apk-tools info`
detects this and flags it. To decode permissions/activities fully, pair this tool
with [`androguard`](https://github.com/androguard/androguard) or the SDK's
`apkanalyzer`:

```bash
apkanalyzer manifest print app.apk
```

## Testing

```bash
pytest
```

## License

MIT — see [LICENSE](LICENSE).
