"""Project-managed Ghidra headless invocation."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile

from chipchain.firmware.elf import ElfImage, ghidra_language
from chipchain.firmware.ghidra_models import GhidraExport

ROOT = Path(__file__).resolve().parents[3]
GHIDRA_VERSION = "12.3_DEV-d6192cb3f900f74152a4eeec1aa6758b6143b093"


def analyze_headless(path: str | Path, image: ElfImage, *, ghidra_home: str | Path | None = None,
                     work_root: str | Path | None = None) -> GhidraExport:
    home = Path(ghidra_home) if ghidra_home is not None else ROOT / "tools/ghidra/install"
    executable = home / "support/analyzeHeadless"
    script = ROOT / "scripts/ghidra/ExportFirmwareFacts.java"
    if not executable.is_file() or not script.is_file():
        raise FileNotFoundError("Project Ghidra installation or exporter unavailable")
    properties = {}
    for line in (home / "Ghidra/application.properties").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            properties[key] = value
    installed = (f"{properties.get('application.version')}_{properties.get('application.release.name')}-"
                 f"{properties.get('application.revision.ghidra')}")
    if installed != GHIDRA_VERSION:
        raise ValueError(f"Ghidra installation is not the pinned version: {installed}")
    root = Path(work_root) if work_root is not None else ROOT / "output"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="firmware-ghidra-", dir=root) as temporary:
        workspace = Path(temporary)
        output = workspace / "export.json"
        compiler = "gcc" if image.identity.architecture == "riscv" else "default"
        command = [str(executable), str(workspace), "project", "-import", str(Path(path).resolve()),
                   "-processor", ghidra_language(image.identity), "-cspec", compiler,
                   "-scriptPath", str(script.parent), "-postScript", script.name, str(output),
                   "-deleteProject", "-analysisTimeoutPerFile", "120"]
        completed = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=240, check=False)
        if completed.returncode or not output.is_file() or "REPORT SCRIPT ERROR" in completed.stdout:
            raise RuntimeError(f"Ghidra analysis failed: {completed.stdout[-4000:]}")
        result = GhidraExport.model_validate(json.loads(output.read_text()))
    if result.language != ghidra_language(image.identity):
        raise ValueError("Ghidra language disagrees with ELF")
    return result
