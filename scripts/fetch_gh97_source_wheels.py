"""Fetch the two inert source wheels used by the GH97 static audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

WHEELS = {
    "httpx-0.28.1-py3-none-any.whl": (
        "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"
    ),
    "requests-2.32.3-py3-none-any.whl": (
        "70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)

    for filename, expected_hash in WHEELS.items():
        package, version, _ = filename.split("-", 2)
        url = f"https://pypi.org/pypi/{package}/{version}/json"
        with urlopen(url, timeout=30) as response:
            release = json.load(response)
        artifact = next(item for item in release["urls"] if item["filename"] == filename)
        artifact_url = urlparse(artifact["url"])
        if artifact_url.scheme != "https" or artifact_url.hostname != "files.pythonhosted.org":
            raise SystemExit(f"unexpected PyPI artifact host for {filename}")
        if artifact["digests"]["sha256"] != expected_hash:
            raise SystemExit(f"PyPI metadata hash mismatch for {filename}")
        with urlopen(artifact_url.geturl(), timeout=60) as response:
            content = response.read()
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise SystemExit(f"download hash mismatch for {filename}: {actual_hash}")
        (args.destination / filename).write_bytes(content)
        print(f"verified {filename} sha256:{actual_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
