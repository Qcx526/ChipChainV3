"""Explicit local file identity utility; never called by domain validation."""

import hashlib
import stat
from pathlib import Path

from chipchain.domain.case import ArtifactFingerprint

HASH_CHUNK_BYTES = 1024 * 1024


def fingerprint_artifact(path: str | Path) -> ArtifactFingerprint:
    """Read a regular local file in bounded chunks. Missing files raise FileNotFoundError."""
    if "://" in str(path):
        raise ValueError("Artifact fingerprinting accepts local file paths, not URLs")
    local = Path(path)
    if not stat.S_ISREG(local.stat().st_mode):
        raise ValueError("Artifact fingerprinting requires a regular local file")
    digest = hashlib.sha256()
    size = 0
    with local.open("rb") as stream:
        while chunk := stream.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return ArtifactFingerprint(sha256=digest.hexdigest(), size_bytes=size)
