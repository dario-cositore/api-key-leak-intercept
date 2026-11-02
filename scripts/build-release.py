#!/usr/bin/env python3
"""Build the release package for API Key Leak Intercept.

Produces the store zip and, when a signing key is given, the signed CRX.
The zip entry order and directory entries match the packages already on the
Chrome Web Store, so a rebuild of unchanged source is reproducible.

Usage:
    python3 scripts/build-release.py [--key /path/to/privatekey.pem]

The signing key lives OUTSIDE the workspace and is never copied into the
extension folder. Without --key the zip is still built.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "extension"
DIST = ROOT / "dist"

# Fixed order. Directory entries come before their contents.
ORDER = [
    "icons/",
    "icons/icon128.png",
    "icons/icon48.png",
    "icons/icon32.png",
    "icons/icon16.png",
    "manifest.json",
    "content.css",
    "popup.css",
    "popup.html",
    "popup.js",
    "fonts/",
    "fonts/fonts.css",
    "fonts/Inter.woff2",
    "fonts/JetBrainsMono.woff2",
    "fonts/Geist.woff2",
    "fonts/GeistMono.woff2",
    "fonts/OFL.txt",
    "detect.js",
    "managed_schema.json",
    "_locales/",
    "_locales/en/",
    "_locales/en/messages.json",
    "background.js",
    "content.js",
    "welcome.html",
    "setupcode.js",
    "configverify.js",
    "entitlement-state.js",
    "welcome.js",
]


def build_zip(dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ORDER:
            path = SRC / name
            if name.endswith("/"):
                if not path.is_dir():
                    raise SystemExit(f"missing directory in source: {name}")
                continue
            if not path.is_file():
                raise SystemExit(f"missing file in source: {name}")
            zf.write(path, name)
    print(f"zip   {dest.name}  {dest.stat().st_size} bytes")
    print(f"sha256 {hashlib.sha256(dest.read_bytes()).hexdigest()}")


def build_crx(src: Path, key: Path, dest: Path) -> None:
    if not key.is_file():
        raise SystemExit(f"signing key not found: {key}")
    staging = DIST / "_staging"
    if staging.exists():
        shutil.rmtree(staging)
    shutil.copytree(src, staging)
    chrome = "/opt/google/chrome/chrome"
    if not Path(chrome).exists():
        chrome = shutil.which("google-chrome-stable") or "google-chrome"
    subprocess.run(
        [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            f"--pack-extension={staging}",
            f"--pack-extension-key={key}",
        ],
        check=True,
        capture_output=True,
    )
    produced = staging.with_suffix(".crx")
    if not produced.exists():
        raise SystemExit("chrome did not produce a crx")
    produced.replace(dest)
    shutil.rmtree(staging)
    print(f"crx   {dest.name}  {dest.stat().st_size} bytes")
    print(f"sha256 {hashlib.sha256(dest.read_bytes()).hexdigest()}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", type=Path, help="CRX signing key, outside the workspace")
    args = ap.parse_args()

    version = "unknown"
    import json

    version = json.loads((SRC / "manifest.json").read_text()).get("version", version)
    DIST.mkdir(exist_ok=True)
    zip_dest = DIST / f"api-key-leak-intercept-v{version}.zip"
    build_zip(zip_dest)

    if args.key:
        build_crx(SRC, args.key, DIST / f"api-key-leak-intercept-v{version}.crx")
    else:
        print("crx   skipped (no --key)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
