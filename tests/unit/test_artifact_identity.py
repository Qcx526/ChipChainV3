import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.domain.case import ArtifactRef, CaseBundle
from chipchain.tools.artifacts import HASH_CHUNK_BYTES, fingerprint_artifact


def test_legacy_case_schema_default_and_round_trip(load_case: Callable[[str], CaseBundle]) -> None:
    case = load_case("paired")
    assert case.schema_version == "1.0"
    assert CaseBundle.model_validate_json(case.model_dump_json()) == case
    data = case.model_dump()
    data["schema_version"] = "unsupported"
    with pytest.raises(ValidationError):
        CaseBundle.model_validate(data)


@pytest.mark.parametrize("digest", ["a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n", 123])
def test_invalid_sha256(load_case: Callable[[str], CaseBundle], digest: object) -> None:
    data = load_case("hardware_only").hardware_artifacts[0].model_dump()
    data["sha256"] = digest
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate(data)


@pytest.mark.parametrize("size", [-1, True, "1", 1.0])
def test_invalid_file_size(load_case: Callable[[str], CaseBundle], size: object) -> None:
    data = load_case("hardware_only").hardware_artifacts[0].model_dump()
    data["size_bytes"] = size
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate(data)


def test_validation_never_accesses_artifact_files(
    load_case: Callable[[str], CaseBundle], monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = load_case("hardware_only").model_dump()
    data["hardware_artifacts"][0].update(path="/customer/read-only/nonexistent.elf", sha256="a" * 64, size_bytes=0)

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Artifact validation must not access files")

    monkeypatch.setattr(Path, "open", forbidden)
    monkeypatch.setattr(Path, "stat", forbidden)
    case = CaseBundle.model_validate(data)
    assert case.hardware_artifacts[0].size_bytes == 0
    assert CaseBundle.model_validate_json(case.model_dump_json()) == case


def test_fingerprint_known_file_and_content_change(tmp_path: Path) -> None:
    path = tmp_path / "synthetic.dat"
    path.write_bytes(b"abc")
    first = fingerprint_artifact(path)
    assert first.sha256 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert first.size_bytes == 3 and path.read_bytes() == b"abc"
    path.write_bytes(b"def")
    second = fingerprint_artifact(path)
    assert first.sha256 != second.sha256 and first.size_bytes == second.size_bytes
    path.write_bytes(b"")
    assert fingerprint_artifact(path).sha256 == hashlib.sha256(b"").hexdigest()
    assert fingerprint_artifact(path).size_bytes == 0


def test_fingerprint_uses_bounded_reads(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "synthetic.dat"
    content = b"x" * (HASH_CHUNK_BYTES + 11)
    path.write_bytes(content)
    original_open = Path.open
    reads = []

    class Reader:
        def __enter__(self):
            self.stream = original_open(path, "rb")
            return self

        def read(self, size: int) -> bytes:
            reads.append(size)
            assert size == HASH_CHUNK_BYTES
            return self.stream.read(size)

        def __exit__(self, *args: object) -> None:
            self.stream.close()

    monkeypatch.setattr(Path, "open", lambda *args, **kwargs: Reader())
    result = fingerprint_artifact(path)
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.size_bytes == len(content)
    assert len(reads) == 3


def test_fingerprint_missing_nonfile_and_url(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fingerprint_artifact(tmp_path / "missing")
    with pytest.raises(ValueError, match="regular"):
        fingerprint_artifact(tmp_path)
    with pytest.raises(ValueError, match="local"):
        fingerprint_artifact("https://invalid.example/test.elf")
