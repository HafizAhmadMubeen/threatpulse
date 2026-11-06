"""Fetch the pinned ATT&CK data and embedding model: python -m backend.rag.fetch

This and nothing else in backend/rag/ uses the network. Each file must match a pinned
SHA-256 before it's kept, so a bad download can never reach the index.
"""

import hashlib
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

from backend.rag.attack_data import (
    MODEL_ARCHIVE,
    MODEL_DIR,
    MODEL_MAX_BYTES,
    MODEL_SHA256,
    MODEL_URL,
    STIX_MAX_BYTES,
    STIX_PATH,
    STIX_SHA256,
    STIX_URL,
)

CHUNK_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 60


class FetchError(Exception):
    pass


def sha256_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            hasher.update(chunk)
    return hasher.hexdigest()


def fetch_file(url: str, target: Path, sha256: str, max_bytes: int) -> None:
    """Keeps the file only if the whole download matches the pin. A partial or wrong file
    is deleted, so the target is either correct or absent."""
    if not url.startswith("https://"):
        raise FetchError(f"refusing a non-HTTPS URL: {url}")
    if target.is_file() and sha256_of(target) == sha256:
        print(f"{target.name}: already present and correct")
        return

    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_name(target.name + ".part")
    hasher = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:
            if not response.geturl().startswith("https://"):
                raise FetchError(f"redirected away from HTTPS: {response.geturl()}")
            with partial.open("wb") as output:
                while chunk := response.read(CHUNK_BYTES):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError(f"{target.name}: larger than the {max_bytes} byte limit")
                    hasher.update(chunk)
                    output.write(chunk)
        if hasher.hexdigest() != sha256:
            raise FetchError(f"{target.name}: SHA-256 is {hasher.hexdigest()}, expected {sha256}")
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    print(f"{target.name}: downloaded {size} bytes, SHA-256 verified")


def extract_model(archive: Path, directory: Path) -> None:
    """filter="data" refuses paths outside the folder, links and device files."""
    with tarfile.open(archive, "r:gz") as tar:
        tar.extractall(directory, filter="data")


def main() -> int:
    try:
        fetch_file(STIX_URL, STIX_PATH, STIX_SHA256, STIX_MAX_BYTES)
        fetch_file(MODEL_URL, MODEL_ARCHIVE, MODEL_SHA256, MODEL_MAX_BYTES)
        extract_model(MODEL_ARCHIVE, MODEL_DIR)
    except (FetchError, OSError, tarfile.TarError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
