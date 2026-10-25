#!/usr/bin/env python3
"""Verify a published source snapshot and emit one bounded MSRV request.

This prepares files only. It does not launch Cargo, the helper, or any other
program. The request environment is constructed explicitly rather than inherited.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

if sys.flags.optimize:
    raise SystemExit("Assertions required")

REPORT = Path(__file__).resolve().parent
PROFILES = {
    "pass": (
        "word-7a4e571-20261025", "exact_revision",
        "635488fcbdc2699ac7bdf12f2e6278250cda2910a49914852f1527f7cc1fab8f",
    ),
    "failed-snapshot": (
        "msrv-v3-failed-snapshot-20261025", "failed_worktree_snapshot",
        "7aef4e52384609f1172c104f8a9d5412fa8136e11a4cb40ff0e640a9dcd7db55",
    ),
}
TOOLS = {
    "cargo": "1815642e0eaa0cf4ea86c3ba4299c21c4f2d68ae4a427881ea1f33070b2aae9b",
    "rustc": "07d5a76ba859dc045883efd538d96c7b86cf10166f4e834afbb5981012b461c3",
}
FLAGS = "-Dwarnings -Wmissing-docs -Funsafe-op-in-unsafe-fn -Ccodegen-units=1"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--toolchain", type=Path, required=True,
                        help="Rust 1.85.0 toolchain root containing bin/cargo and bin/rustc")
    parser.add_argument("--cargo-home", type=Path, required=True)
    parser.add_argument("--user-home", type=Path, required=True)
    parser.add_argument("--mode", choices=PROFILES, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    toolchain = args.toolchain.resolve(strict=True)
    cargo_home = args.cargo_home.resolve(strict=True)
    user_home = args.user_home.resolve(strict=True)
    output = args.output.resolve()
    assert all(p.is_dir() for p in (repo, toolchain, cargo_home, user_home))
    assert output.is_relative_to(repo / "ignored") and output != repo / "ignored"
    assert not output.exists() and not args.output.is_symlink()
    assert output.parent.is_dir(), "Create only the private parent directory first"

    run_id, source_id, inventory_sha = PROFILES[args.mode]
    inventory_path = REPORT / "results" / run_id / "source-files.json"
    assert sha(inventory_path) == inventory_sha
    files = json.loads(inventory_path.read_text())[source_id]
    assert len(files) == 165
    for name, expected in files.items():
        rel = Path(name)
        assert not rel.is_absolute() and ".." not in rel.parts
        assert rel.parts[0] not in ("ignored", "target", ".git")
        assert re.fullmatch(r"[0-9a-f]{64}", expected)
        source = repo / rel
        assert source.is_file() and source.resolve() == source
        assert sha(source) == expected, name

    identities = {}
    for name, expected in TOOLS.items():
        path = toolchain / "bin" / name
        assert path.is_file() and os.access(path, os.X_OK)
        assert sha(path) == expected, "Requires the published Rust 1.85.0 tool bytes"
        identities[name] = {"path": str(path), "resolved": str(path.resolve()), "sha256": expected}
    helper = repo / "tools/word-sync-oracle/bounded_command.py"
    assert sha(helper) == files["tools/word-sync-oracle/bounded_command.py"]
    env = {
        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(repo / "target"),
        "CARGO_HOME": str(cargo_home), "HOME": str(user_home), "LC_ALL": "C",
        "PATH": str(toolchain / "bin") + ":/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1", "RUSTC": identities["rustc"]["path"],
        "RUSTFLAGS": FLAGS, "TMPDIR": str(output / "tmp"),
    }
    assert not {"CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"} & env.keys()
    request = {
        "argv": [identities["cargo"]["path"], "check", "--manifest-path",
                 str(repo / "Cargo.toml"), "-p", "liteinst2", "--all-targets",
                 "--all-features", "--offline", "--locked",
                 "--message-format=json-render-diagnostics"],
        "cwd": str(repo), "env": env,
        "stdout": str(output / "check.stdout"), "stderr": str(output / "check.stderr"),
        "cpu_seconds": 60, "wall_seconds": 90, "file_bytes": 134217728,
    }
    output.mkdir()
    (output / "tmp").mkdir()
    write(output / "request.json", request)
    # Recheck the same explicit inputs after preparation; this does not replace
    # independent launch-time review of host Cargo configuration and receipts.
    assert sha(inventory_path) == inventory_sha
    for name, expected in files.items():
        assert sha(repo / name) == expected, name
    for name, row in identities.items():
        assert sha(Path(row["path"])) == row["sha256"]
        assert str(Path(row["path"]).resolve()) == row["resolved"]
    write(output / "admission.json", {
        "status": "REQUEST_PREPARED_NOT_EXECUTED", "mode": args.mode,
        "historical_run_id": run_id, "matched_source_id": source_id,
        "source_inventory_sha256": inventory_sha, "source_files": files,
        "reproduction_tested_revision": None,
        "identity_note": "Byte match to a published source snapshot; this new attempt has not run.",
        "tool_identities": identities, "helper_sha256": sha(helper),
        "generator_sha256": sha(Path(__file__).resolve()),
        "request_sha256": sha(output / "request.json"),
        "receipt": str(output / "receipt.json"),
        "local_configuration": "Requires separate review; inherited Cargo config is not qualified by source-file equality.",
    })
    print(output / "request.json")


if __name__ == "__main__":
    main()
