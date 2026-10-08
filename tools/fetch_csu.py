#!/usr/bin/env python3
"""Fetches the Colorado State University heavy-vehicle J1939 candump logs used to validate
vn-ids on real trucks. The logs are NOT redistributed in this repository; this script
downloads them on demand and checks each against a known SHA-256.

Source: Jeremy Daily's heavy-vehicle CAN data,
https://www.engr.colostate.edu/~jdaily/J1939/candata.html
The page states no licence; these files are downloaded for local research use only and are
never committed here. See docs/data-sources.md.

Usage: fetch_csu.py [t660|t270|all] [--dir DIR]
  t660  2015 Kenworth T660 drive, ~137k frames   (candump_kw_drive.zip, ~1.2 MB)
  t270  2014 Kenworth T270 long drive, ~9.86M frames (~86 MB zip, ~513 MB unzipped)
"""

import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

BASE = "https://www.engr.colostate.edu/~jdaily/J1939/files"
FILES = {
    "t660": {
        "zip": "candump_kw_drive.zip",
        "zip_sha256": "2b5b59a7f6c79a60315b964b93e17239bee4e854321a9c207701e66cd03a003f",
        "member": "candump_kw_drive.txt",
    },
    "t270": {
        "zip": "2014_KW_T270_LongDrive_CSU090BJ.zip",
        "zip_sha256": "16dca5bc799d8decd1b9126c5ba80e09ca76c9c31f8f0b7dcde7e6f19d71703b",
        "member": "CSU090BJ.txt",
    },
}


def fetch(name, out_dir):
    spec = FILES[name]
    url = f"{BASE}/{spec['zip']}"
    print(f"downloading {url} ...", file=sys.stderr)
    raw = urllib.request.urlopen(url, timeout=600).read()  # noqa: S310 (fixed https host)
    got = hashlib.sha256(raw).hexdigest()
    if got != spec["zip_sha256"]:
        raise SystemExit(f"SHA-256 mismatch for {spec['zip']}:\n  expected {spec['zip_sha256']}\n  got      {got}")
    zf = zipfile.ZipFile(io.BytesIO(raw))
    member = spec["member"]
    if member not in zf.namelist():
        raise SystemExit(f"{member} not in {spec['zip']}: {zf.namelist()}")
    dest = Path(out_dir) / f"{name}.log"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zf.open(member) as src, open(dest, "wb") as f:
        f.write(src.read())
    print(f"wrote {dest} ({dest.stat().st_size} bytes)", file=sys.stderr)
    return dest


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out_dir = "data/csu"
    if "--dir" in sys.argv:
        out_dir = sys.argv[sys.argv.index("--dir") + 1]
    which = args[0] if args else "all"
    names = list(FILES) if which == "all" else [which]
    for n in names:
        if n not in FILES:
            raise SystemExit(f"unknown dataset {n}; choose from {list(FILES)} or 'all'")
        fetch(n, out_dir)


if __name__ == "__main__":
    main()
