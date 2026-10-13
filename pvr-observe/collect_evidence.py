#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def git(path, *args):
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


REQUIRED_CONFIGS = (
    "CONFIG_DEBUG_FS", "CONFIG_MODVERSIONS", "CONFIG_KSU", "CONFIG_KSU_SUSFS",
    "CONFIG_SYSVIPC", "CONFIG_POSIX_MQUEUE", "CONFIG_IPC_NS", "CONFIG_PID_NS",
    "CONFIG_USER_NS", "CONFIG_DEVTMPFS", "CONFIG_NTSYNC",
)


def validate_feature_config(contents):
    lines = set(contents.decode().splitlines())
    missing = [key for key in REQUIRED_CONFIGS if key + "=y" not in lines]
    if missing:
        raise ValueError(f"Missing required observer/root/container features: {missing}")


def validate_inputs(output):
    inputs_path = output / "inputs.json"
    if not inputs_path.is_file():
        raise ValueError("Missing recorded build inputs")
    inputs = json.loads(inputs_path.read_text())
    baseline = json.loads(Path(__file__).resolve().parent.parent.joinpath(
        "pvr-observation-baseline.json").read_text())["inputs"]
    expected = {("ksu_variant" if key == "kernelsu_variant" else key): value
                for key, value in baseline.items()}
    expected.update(enable_susfs=True, export_susfs_patches=False,
                    artifact_upload_mode="仅上传 AnyKernel3.zip", revision="r1",
                    pvr_observe=True)
    mismatch = {key: {"expected": value, "actual": inputs.get(key)}
                for key, value in expected.items() if inputs.get(key) != value}
    if mismatch:
        raise ValueError(f"Build inputs differ from working baseline: {mismatch}")


def collect_sources(kernel, output):
    validate_inputs(output)
    workspace = kernel.parent
    repositories = {}
    candidates = [workspace, kernel / "common"]
    candidates.extend(p for p in workspace.iterdir() if p.is_dir() and not p.name.startswith("."))
    candidates.extend(p for p in kernel.iterdir() if p.is_dir() and not p.name.startswith("."))
    for path in candidates:
        if not (path / ".git").exists():
            continue
        resolved = path.resolve()
        if str(resolved) in repositories:
            continue
        repositories[str(resolved)] = {
            "head": git(path, "rev-parse", "HEAD"),
            "status": git(path, "status", "--porcelain"),
        }
    provenance = {
        "github_sha": __import__("os").environ.get("GITHUB_SHA"),
        "repositories": repositories,
        "compatibility_verified": False,
        "warning": "Moving third-party dependencies are not proven identical to the running build. No KABI or boot validation yet.",
    }
    (output / "source-provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    (output / "common-tracked-changes.patch").write_text(git(kernel / "common", "diff", "HEAD") + "\n")
    configs = output / "source-config"
    configs.mkdir(exist_ok=True)
    for name in ("gki_defconfig", "gki_defconfig.orig", "ksu.fragment"):
        source = kernel / "common/arch/arm64/configs" / name
        if source.is_file():
            shutil.copyfile(source, configs / name)


def collect_outputs(kernel, output):
    roots = [kernel / "bazel-bin/common/kernel_aarch64",
             kernel / "out/android15-6.6/dist"]
    inventory = []
    found = set()
    for index, root in enumerate(roots):
        for name in (".config", "Module.symvers", "vmlinux.symvers", "kernel.release", "System.map"):
            source = root / name
            if not source.is_file():
                continue
            destination = output / "build-output" / str(index) / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            contents = destination.read_bytes()
            inventory.append({"path": str(source), "saved": str(destination.relative_to(output)),
                              "sha256": hashlib.sha256(contents).hexdigest(), "bytes": len(contents)})
            found.add(name)
            if name == ".config":
                validate_feature_config(contents)
    (output / "build-output-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    missing = {".config"} - found
    if not ({"Module.symvers", "vmlinux.symvers"} & found):
        missing.add("Module.symvers or vmlinux.symvers")
    if missing:
        raise ValueError(f"Missing actual build outputs: {sorted(missing)}. Do not flash or substitute stock_defconfig.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("kernel", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-only", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    collect_sources(args.kernel, args.output)
    if not args.source_only:
        collect_outputs(args.kernel, args.output)
