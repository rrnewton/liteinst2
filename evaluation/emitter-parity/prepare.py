#!/usr/bin/env python3
"""Copy two exact Git core trees for static parity; no build or capture execution."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

if sys.flags.optimize:
    raise SystemExit("optimized Python is refused: every admission is mandatory")

BASE = "474094a7355c14c673f794cf34aa63d53566f030"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args, data=None):
    return subprocess.run(["git", "-C", str(repo), *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout


def tree(repo, revision):
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    assert git(repo, "rev-parse", "--verify", revision + "^{commit}").strip().decode() == revision
    entries = []
    for row in git(repo, "ls-tree", "-rz", revision).split(b"\0"):
        if not row:
            continue
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        name = name.decode()
        assert kind == "blob" and mode in {"100644", "100755"}
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        entries.append((name, mode, oid))
    output = git(repo, "cat-file", "--batch", data="".join(oid + "\n" for _, _, oid in entries).encode())
    files, inventory, cursor = {}, {}, 0
    for name, mode, oid in entries:
        end = output.index(b"\n", cursor)
        actual, kind, size = output[cursor:end].decode().split()
        assert (actual, kind) == (oid, "blob")
        cursor = end + 1
        content = output[cursor:cursor + int(size)]
        cursor += int(size)
        assert output[cursor:cursor + 1] == b"\n"
        cursor += 1
        inventory[name] = {"git_blob": oid, "git_mode": mode, "bytes": len(content), "sha256": sha(content)}
        if name.startswith("src/") or name in {"README.md", "Cargo.toml", "Cargo.lock", "tests/support/eviction_chain_cases.rs"}:
            files[name] = content
    assert cursor == len(output) and "src/lib.rs" in files
    return files, inventory


def core_lock(content):
    # Preserve literal package blocks from the supplied Git lock, selecting the
    # complete dependency closure of the core package, not resolving versions.
    text = content.decode()
    parsed = tomllib.loads(text)
    assert parsed["version"] == 4
    blocks = text.split("\n[[package]]\n")
    packages = {}
    for block in blocks[1:]:
        value = tomllib.loads("[[package]]\n" + block)["package"][0]
        assert value["name"] not in packages, "ambiguous package names need a new explicit recipe"
        packages[value["name"]] = (value, block)
    needed, pending = set(), ["liteinst2"]
    while pending:
        name = pending.pop()
        if name in needed:
            continue
        needed.add(name)
        value, _ = packages[name]
        for dependency in value.get("dependencies", []):
            assert dependency in packages, "version/source-qualified dependency needs an explicit recipe"
            pending.append(dependency)
    return (blocks[0] + "".join("\n[[package]]\n" + packages[name][1] for name in sorted(needed))).encode()


def stage(source, inventory, revision, side, destination, material):
    assert not destination.exists()
    cargo = tomllib.loads(source["Cargo.toml"].decode())
    package = cargo["package"]
    assert package["name"] == "liteinst2" and package["edition"] == "2024"
    text = source["Cargo.toml"].decode()
    def section(name):
        marker = f"[{name}]\n"
        assert text.count(marker) == 1
        return marker + text.split(marker, 1)[1].split("\n[", 1)[0].rstrip() + "\n"
    library = f"liteinst2_parity_{side}_{revision[:12]}"
    manifest = (f'[package]\nname = "liteinst2"\nversion = {json.dumps(package["version"])}\n'
                f'edition = "2024"\nrust-version = {json.dumps(package["rust-version"])}\n'
                'autobins = false\nautoexamples = false\nautotests = false\nautobenches = false\n'
                f'[workspace]\nmembers = []\n[lib]\nname = "{library}"\npath = "src/lib.rs"\n'
                + section("dependencies") + section("features"))
    for name in ("dependencies", "features"):
        assert tomllib.loads(manifest)[name] == cargo[name]
    files = {name: data for name, data in source.items() if name.startswith("src/") or name == "README.md"}
    assert "src/emitter_parity.rs" not in files and "emitter_parity" not in files["src/lib.rs"].decode()
    files["Cargo.toml"] = manifest.encode()
    files["Cargo.lock"] = core_lock(source["Cargo.lock"])
    files["src/lib.rs"] += b'\n#[cfg(test)]\nextern crate self as liteinst2;\n#[cfg(test)]\nmod emitter_parity;\n'
    # The old capture is a whole literal prefix. Its only suffix names the new,
    # separate child module, which can reuse the private operand authenticator.
    files["src/emitter_parity.rs"] = material["capture.rs"] + b'\n#[path = "parity/current_features.rs"]\nmod current_features;\n'
    files["src/parity/current_features.rs"] = material["current_features.rs"]
    assert source["tests/support/eviction_chain_cases.rs"] == material["chain_cases.rs"]
    files["src/parity/chain_cases.rs"] = material["chain_cases.rs"]
    destination.mkdir()
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
    return {"revision": revision, "directory": str(destination), "library_target": library,
            "git_inventory": inventory, "prepared_sha256": {name: sha(data) for name, data in files.items()},
            "core_source_sha256": {name: sha(data) for name, data in source.items()},
            "source_revision_tested_by_preparation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve(strict=True)
    assert git(repo, "rev-parse", "--show-toplevel").strip().decode() == str(repo)
    assert args.candidate != BASE
    here = Path(__file__).resolve().parent
    declared = json.loads((here / "materials.json").read_text())
    assert {p.name for p in here.iterdir()} == set(declared) | {"materials.json"}
    material = {}
    for name, expected in declared.items():
        path = here / name
        assert path.is_file() and not path.is_symlink()
        material[name] = path.read_bytes()
        assert sha(material[name]) == expected
    output = args.output.absolute()
    assert output.parent.resolve(strict=True) == output.parent
    assert (repo / "ignored").resolve(strict=True) in output.parents
    assert not output.exists() and not output.is_symlink()
    old, old_inventory = tree(repo, BASE)
    new, new_inventory = tree(repo, args.candidate)
    for name in ("dependencies", "features"):
        assert tomllib.loads(old["Cargo.toml"].decode())[name] == tomllib.loads(new["Cargo.toml"].decode())[name]
    assert core_lock(old["Cargo.lock"]) == core_lock(new["Cargo.lock"])
    output.mkdir()
    manifest = {"status": "PREPARED_NOT_COMPILED_OR_RUN", "harness_sha256": declared,
                "old": stage(old, old_inventory, BASE, "old", output / "old", material),
                "new": stage(new, new_inventory, args.candidate, "new", output / "new", material)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"manifest": str(output / "manifest.json"), "sha256": sha((output / "manifest.json").read_bytes())}))


if __name__ == "__main__":
    main()
