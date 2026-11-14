#!/usr/bin/env python3
"""Verify the unsigned bundle handed off for developer signing."""
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile


def verify(path):
    with zipfile.ZipFile(path) as bundle:
        names = set(bundle.namelist())
        for name in ("BundleConfig.pb", "base/manifest/AndroidManifest.xml",
                     "base/dex/classes.dex", "base/assets/index.android.bundle"):
            if name not in names:
                raise ValueError(f"Missing AAB entry: {name}")
        for name in names:
            upper = name.upper()
            if upper.startswith("META-INF/") and (
                upper.endswith((".SF", ".RSA", ".DSA", ".EC"))
                or upper.rsplit("/", 1)[-1].startswith("SIG-")
            ):
                raise ValueError(f"AAB must be unsigned; found signature entry: {name}")
        for abi in ("arm64-v8a", "x86_64"):
            engine = f"base/lib/{abi}/libmonero_wallet2_api_c.so"
            if not bundle.read(engine).startswith(b"\x7fELF"):
                raise ValueError(f"Invalid native engine: {abi}")
            if f"base/lib/{abi}/libjnidispatch.so" not in names:
                raise ValueError(f"JNA native loader missing: {abi}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    path = Path(sys.argv[1])
    digest = verify(path)
    path.with_name("SHA256SUMS").write_text(f"{digest}  {path.name}\n")
    path.with_name("build-manifest.json").write_text(json.dumps({
        "commit": os.environ.get("GITHUB_SHA"),
        "engine": "MrCyjaneK/monero_c v0.18.4.6-RC2",
        "signing": "Unsigned; developer must sign before Google Play upload",
        "abis": ["arm64-v8a", "x86_64"],
        "aabSha256": digest,
    }, indent=2) + "\n")
    print("AAB verified: bundle contents, both native ABIs, JNA loaders, no JAR signatures.")
