#!/usr/bin/env python3
"""Read one closed ELF-exec recipe tree; no compilation or subject execution."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
NATIVE_STDOUT = ("PASS kernel-exec MOV5/RET: 8 original + 16 rewritten traces; 72 full-state comparisons; "
                 "24 subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows\n")
COMPLETE = ("status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\nfull_state_comparisons\t72\n"
            "subject_call_ret_witnesses\t24\nhook_call_return_witnesses\t8\nrecording_hook_rows\t4\n"
            "manual_load_mappings\t0\npost_seed_state_repairs\t0\n")
PROFILE = dict(opt_level="0", debuginfo=2, debug_assertions=True, overflow_checks=True, test=False)
RUNTIME_ENV = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
RECEIPT_KEYS = {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants",
                "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events",
                "cleanup_error", "aborted", "inputs_unchanged"}
PINNED_SOURCE = {'evaluation/elf-exec/reproduce.py': 'ab041ad6611d0c8000a77b70cdaaee4ef25433c94e5c9e4ff4d46b81a14b2c36', 'evaluation/elf-exec/render_selection.py': 'de1028fa9b590a6f1ba37627ac5ff78470c9f3b225eed794f7c32959c1a1c00c', 'evaluation/required-gates.py': '6d71d2a6518b8d93e136fb5fcb8170dded37e7bcfa0eae2c1fdefb1582a1fb8b', 'tools/unwind-oracle/bounded_command.py': 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44', 'tools/elf-rewrite/tests/compare_sites.py': '2ad3fcbe848154729556e3e650155c7c85390b379f0f3d4043c9ae4b380fc644', 'tests/support/elf_exec_driver.rs': 'eab2b3e0fdd0dc1c7520a2b04fa0430a93c3b1b03e62deb2266fc8b7f705b340', 'tests/support/elf_exec_oracle.rs': '22f06519dc3e6e54950c274fbbfcd1c6fb461c44732a4ead9271d6aeb045eb88', 'tests/support/quiescent_oracle.rs': 'e8c17e5daaf6e9720d6c515fd5e6f986307eca9c12ce115cdd51b465406dc756', 'tests/fixtures/elf-exec/subject.S': '6e13c95bd7cf00200b7d3d49f3fb3f4498fdd31df11084a53ccb199388577f81', 'tests/fixtures/elf-exec/subject.ld': 'c11637564a3f75ad67e66190149db2ee014e762621d7c3c834bf3eb75279ea52', 'tools/elf-rewrite/examples/verify_elf_exec.rs': 'af81840d319760a6d821f7e1d0476f559e2ee4208fa655dcd3fb46cd6ffc8eb4', 'tests/support/elf_exec_provider.rs': '9b5562034fc6bbdc32f889ab64df7f414e96ee5d9a99c06e39bf6728f128e730', 'tests/elf_exec_provider_contract.rs': '5c2dcebd4b2c845527718ddd640b757821f4a7c74c9ac56ee08666b0a38337fd'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    assert stat.S_ISREG(path.lstat().st_mode), str(path)
    return path.read_bytes()


def js(path):
    return json.loads(read(path))


def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0


def tsv(path):
    rows = [line.split("\t") for line in read(path).decode().splitlines()]
    assert all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows)
    return dict(rows)


def unsigned(value):
    assert re.fullmatch(rb"[0-9]{1,20}", value)
    result = int(value)
    assert result <= (1 << 64) - 1
    return result


def provider_record(path, executable):
    value, cursor = read(path), 0

    def line():
        nonlocal cursor
        end = value.index(b"\n", cursor)
        result = value[cursor:end]
        cursor = end + 1
        return result

    def field(name):
        parts = line().split(b"\t")
        assert len(parts) == 2 and parts[0] == name
        return unsigned(parts[1])

    assert line() == b"elf-exec-provider-v1"
    device, inode, size = field(b"stat_dev"), field(b"stat_inode"), field(b"stat_bytes")
    length = field(b"fdinfo_bytes")
    assert 0 < length <= 4096 and cursor + length <= len(value)
    fdinfo = value[cursor:cursor + length]
    cursor += length
    assert fdinfo.endswith(b"\n")
    length = field(b"mount_record_bytes")
    assert 0 < length <= 1024 * 1024 and cursor + length == len(value)
    mount = value[cursor:cursor + length]
    assert mount.endswith(b"\n") and mount.count(b"\n") == 1
    fields = mount.split()
    assert len(fields) >= 10
    separator = fields.index(b"-")
    assert separator >= 6 and separator + 4 == len(fields)
    assert unsigned(fields[1]) > 0 and fields[3].startswith(b"/") and fields[4].startswith(b"/")

    def fd_field(name):
        found = [row[len(name):].strip() for row in fdinfo.splitlines() if row.startswith(name)]
        assert len(found) == 1
        return unsigned(found[0])

    mount_id = fd_field(b"mnt_id:")
    assert mount_id > 0 and unsigned(fields[0]) == mount_id
    assert inode > 0 and fd_field(b"ino:") == inode
    pair = fields[2].split(b":")
    assert len(pair) == 2
    mapping_device = tuple(unsigned(part) for part in pair)
    owner = executable.lstat()
    assert stat.S_ISREG(owner.st_mode)
    assert (owner.st_dev, owner.st_ino, owner.st_size) == (device, inode, size)
    return dict(stat_device=device, inode=inode, bytes=size, mount_id=mount_id,
                mapping_device=mapping_device, record_sha256=sha(value), mount_record_sha256=sha(mount))


def map_file_records(path, maps, executable, provider):
    value = read(path)
    prefix = b"elf-exec-map-files-v1\n"
    assert value.startswith(prefix)
    cursor, count = len(prefix), 0
    expected_path = os.fsencode(str(executable.resolve(strict=True)))
    for row in maps.splitlines():
        fields = row.split(None, 5)
        assert len(fields) >= 5
        inode = unsigned(fields[4])
        if inode == 0:
            continue
        assert re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", fields[0])
        start, end = (int(part, 16) for part in fields[0].split(b"-"))
        assert start < end
        pair = fields[3].split(b":")
        assert len(pair) == 2 and all(re.fullmatch(rb"[0-9a-f]+", part) for part in pair)
        assert tuple(int(part, 16) for part in pair) == provider["mapping_device"]
        assert inode == provider["inode"]
        end = value.index(b"\n", cursor)
        recorded = value[cursor:end].split(b"\t")
        assert len(recorded) == 2 and recorded[0] == fields[0]
        length = unsigned(recorded[1])
        cursor = end + 1
        assert cursor + length < len(value)
        assert value[cursor:cursor + length] == expected_path
        cursor += length
        assert value[cursor:cursor + 1] == b"\n"
        cursor += 1
        count += 1
    assert count > 0 and cursor == len(value)
    return count


def git_source(revision):
    assert re.fullmatch("[0-9a-f]{40}", revision)
    prefix = ["/usr/bin/git", "-C", str(REPO)]
    tree = subprocess.check_output(prefix + ["ls-tree", "-rz", revision], timeout=20)
    records = []
    for row in tree.split(b"\0")[:-1]:
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.split()
        assert mode in (b"100644", b"100755") and kind == b"blob"
        records.append((name.decode(), oid.decode()))
    batch = subprocess.check_output(prefix + ["cat-file", "--batch"],
                                    input="".join(oid + "\n" for _, oid in records).encode(), timeout=30)
    at, result = 0, {}
    for name, oid in records:
        end = batch.index(b"\n", at)
        actual, kind, size = batch[at:end].split()
        assert actual.decode() == oid and kind == b"blob"
        size = int(size)
        at = end + 1
        result[name] = sha(batch[at:at + size])
        at += size
        assert batch[at:at + 1] == b"\n"
        at += 1
    assert at == len(batch)
    return result


def expected_commands(raw, cargo):
    subject = raw / "subjects"
    artifacts = raw / "artifacts"
    fixture = REPO / "tests/fixtures/elf-exec"
    rows = [
        ("required", ["/usr/bin/python3.9", "-B", str(REPO / "evaluation/required-gates.py"),
                      "--repo", str(REPO), "--output", str(raw / "required/gates")]),
        ("comparison", ["/usr/bin/python3.9", "-B", str(REPO / "tools/elf-rewrite/tests/compare_sites.py")]),
        ("native-compile", [cargo, "build", "-p", "liteinst2", "-p", "liteinst-rewrite", "--bin",
                            "elf-exec-oracle", "--bin", "liteinst-rewrite", "--offline", "--locked", "--message-format=json"]),
        ("codec-compile", [cargo, "build", "-p", "liteinst-rewrite", "--example", "verify_elf_exec",
                           "--offline", "--locked", "--message-format=json"]),
        ("target", [str(artifacts / "elf-exec-oracle"), "target"]),
        ("assemble", ["/usr/bin/gcc", "-c", "-nostdlib", "-fno-pie", "-Wa,--fatal-warnings",
                       str(fixture / "subject.S"), "-o", str(subject / "subject.o")]),
        ("link", ["/usr/bin/ld", "-m", "elf_x86_64", "-nostdlib", "--build-id=none", "-z", "noexecstack",
                  "-T", str(fixture / "subject.ld"), str(subject / "subject.o"), "-o", str(subject / "original-unstripped")]),
        ("strip", ["/usr/bin/strip", "--strip-all", "-o", str(subject / "original-stripped"), str(subject / "original-unstripped")]),
    ]
    candidates = []
    for stripped in ("unstripped", "stripped"):
        for hook in ("null", "journal"):
            name = stripped + "-" + hook
            original, selection, output = subject / ("original-" + stripped), subject / (name + ".selection"), raw / (name + "-candidate")
            rows += [("select-" + name, ["/usr/bin/python3.9", "-B", str(REPO / "evaluation/elf-exec/render_selection.py"),
                                         str(original), str(raw / "target/stdout.txt"), hook, str(selection)]),
                     ("prepare-" + name, [str(artifacts / "liteinst-rewrite"), "prepare", str(original), str(selection), str(output)]),
                     ("verify-" + name, [str(artifacts / "verify_elf_exec"), str(original), str(selection), str(output)])]
            candidates.append(output)
    rows.append(("native", [str(artifacts / "elf-exec-oracle"), "run", str(subject / "original-unstripped"),
                             str(subject / "original-stripped"), *map(str, candidates), str(raw / "captures")]))
    copies = ["original-unstripped", "original-stripped"] + ["candidate-" + str(i) for i in range(4)]
    rows += [("ordinary-" + name, [str(raw / "captures" / name)]) for name in copies]
    return rows, copies, candidates


def main():
    assert not sys.flags.optimize, "assertions required"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    raw = parser.parse_args().raw
    assert raw.is_absolute() and raw.resolve() == raw and raw.is_relative_to(REPO / "ignored")
    output = raw / "runtime-audit-oracle-v3"
    assert not output.exists() and not output.is_symlink()
    source = js(raw / "source.json")
    assert source == js(raw / "source-after.json")
    assert source["files"] == git_source(source["revision"])
    assert all(source["files"][name] == value for name, value in PINNED_SOURCE.items())
    results = js(raw / "results.json")
    assert len(results) == 27
    compiler_env = dict(results[0]["env"])
    del compiler_env["TMPDIR"]
    tool = Path(compiler_env["RUSTC"]).parent
    assert compiler_env == dict(CARGO_BUILD_JOBS="4", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(REPO / "target"), CARGO_HOME=compiler_env["CARGO_HOME"], HOME=compiler_env["HOME"],
        RUSTC=str(tool / "rustc"), RUSTDOC=str(tool / "rustdoc"), RUSTC_WORKSPACE_WRAPPER="", RUSTC_WRAPPER="",
        RUST_TEST_THREADS="4", LC_ALL="C", PATH=str(tool) + ":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    for path in (tool, Path(compiler_env["HOME"]), Path(compiler_env["CARGO_HOME"])):
        assert path.is_absolute() and ".." not in path.parts
    expected, copies, candidates = expected_commands(raw, str(tool / "cargo"))
    assert js(raw / "stage-inventory.json") == [name for name, _ in expected]
    receipt_hashes = {}
    for result, (name, argv) in zip(results, expected):
        directory = raw / name
        assert result == js(directory / "result.json")
        command = js(directory / "command.json")
        assert result == dict(command, exit=0, elapsed_seconds=result["elapsed_seconds"])
        finite(result["elapsed_seconds"])
        assert result["name"] == name and result["argv"] == argv and result["cwd"] == str(REPO)
        compiler = name in ("native-compile", "codec-compile")
        environment = compiler_env if compiler or name == "required" else RUNTIME_ENV
        assert result["env"] == dict(environment, TMPDIR=str(directory / "tmp"))
        if name == "required":
            assert result["outer_argv"] == argv and result["outer_env"] == result["env"]
            assert result["parent_timeout_seconds"] == 1000
            continue
        request = dict(argv=argv, cwd=str(REPO), env=result["env"], stdout=str(directory / "stdout.txt"),
                       stderr=str(directory / "stderr.txt"), cpu_seconds=60 if compiler else 20,
                       wall_seconds=90 if compiler else 30, file_bytes=(128 if compiler else 16) * 1024 * 1024)
        assert request == result["request"] == js(directory / "request.json")
        assert result["outer_argv"] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
            "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(REPO / "tools/unwind-oracle/bounded_command.py"),
            "--request", str(directory / "request.json"), "--receipt", str(directory / "receipt.json")]
        assert result["outer_env"] == RUNTIME_ENV and result["parent_timeout_seconds"] == (115 if compiler else 55)
        receipt = js(directory / "receipt.json")
        assert set(receipt) == RECEIPT_KEYS and type(receipt["exit"]) is int and receipt["exit"] == 0
        assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
        assert receipt["absence_proof"] == "ECHILD" and receipt["unexpected_descendants"] == receipt["cleanup_events"] == []
        assert receipt["aborted"] is None and receipt["cleanup_error"] is None
        finite(receipt["elapsed_seconds"])
        assert receipt["request_sha256"] == sha(read(directory / "request.json"))
        assert receipt["helper_sha256"] == source["files"]["tools/unwind-oracle/bounded_command.py"]
        for stream in ("stdout", "stderr"):
            assert receipt[stream + "_sha256"] == sha(read(directory / (stream + ".txt")))
        assert read(directory / "helper.stderr") == b""
        assert read(directory / "helper.stdout") == (json.dumps(dict(exit=0, wall_timeout=False,
            absence_proof="ECHILD", descendants=0, success=True)) + "\n").encode()
        receipt_hashes[name] = sha(read(directory / "receipt.json"))
    gates = js(raw / "required/gates/commands.json")
    assert gates["head"] == source["revision"] and gates["source_sha256"] == source["files"]
    assert gates["tracked_diff_sha256"] == sha(b"")
    gate_argv = [["cargo", "fmt", "--check"], ["cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"],
                 ["cargo", "test", "--workspace"], ["cargo", "check", "--workspace", "--all-features", "--all-targets"]]
    assert len(gates["records"]) == 4
    for row, name, argv in zip(gates["records"], ("fmt", "clippy", "test", "check"), gate_argv):
        assert row["name"] == name and row["argv"] == argv and type(row["exit"]) is int and row["exit"] == 0
        assert row["timeout_seconds"] == (360 if name == "test" else 180)
        assert row["log"] == str((raw / "required/gates" / (name + ".log")).relative_to(REPO))
        assert row["sha256"] == sha(read(REPO / row["log"]))
        finite(row["seconds"])
    required_stdout = "".join(json.dumps(row) + "\n" for row in gates["records"])
    required_stdout += "PASS exact-head receipt " + str(raw / "required/gates/commands.json") + "\n"
    assert read(raw / "required/stdout.txt") == required_stdout.encode() and read(raw / "required/stderr.txt") == b""
    assert read(raw / "comparison/stdout.txt") == (
        "comparison calibrations: one exact loss/trap inventory and five required refusals\n"
        "comparison calibrations: original one/five retained; total three positives and 24 required refusals\n").encode()
    assert read(raw / "comparison/stderr.txt") == b"" and read(raw / "target/stderr.txt") == b""

    artifacts = js(raw / "artifacts.json")
    assert set(artifacts) == {"elf-exec-oracle", "liteinst-rewrite", "verify_elf_exec"}
    for name, item in artifacts.items():
        stage = "codec-compile" if name == "verify_elf_exec" else "native-compile"
        messages = [json.loads(line) for line in read(raw / stage / "stdout.txt").splitlines()]
        assert 1 <= len(messages) <= 256 and messages[-1] == dict(reason="build-finished", success=True)
        assert sum(m.get("reason") == "build-finished" for m in messages) == 1
        assert all(m.get("reason") in ("compiler-artifact", "build-script-executed", "build-finished") for m in messages)
        assert not any(line.startswith((b"warning:", b"error:")) for line in read(raw / stage / "stderr.txt").splitlines())
        selected = [m for m in messages if m.get("reason") == "compiler-artifact" and m["target"]["name"] == name and m.get("executable")]
        assert selected == [item["artifact"]] and item["artifact"]["profile"] == PROFILE
        assert item["artifact"]["features"] == [] and type(item["artifact"]["fresh"]) is bool
        kind = "example" if name == "verify_elf_exec" else "bin"
        package = REPO if name == "elf-exec-oracle" else REPO / "tools/elf-rewrite"
        parent = REPO / "target/debug" / ("examples" if kind == "example" else "")
        assert item["artifact"]["manifest_path"] == str(package / "Cargo.toml")
        assert item["artifact"]["target"]["kind"] == [kind] and item["artifact"]["target"]["crate_types"] == ["bin"]
        assert item["artifact"]["filenames"] == [str(parent / name)] and item["artifact"]["executable"] == str(parent / name)
        assert sha(read(raw / "artifacts" / name)) == item["sha256"]
    before = js(raw / "candidate-files-before.json")
    assert before == js(raw / "candidate-files-after.json")
    names = [s + "-" + h for s in ("unstripped", "stripped") for h in ("null", "journal")]
    assert list(before) == names
    members = {"COMPLETE", "bundle-index.tsv", "candidate.elf", "image-0000.bin", "ledger.tsv", "metadata.li2meta",
               "plan-ledger.tsv", "report.tsv", "selection.txt", "site-1.diagnostics.txt", "source.li2sparse", "target.tsv"}
    original_hashes = js(raw / "originals.json")
    assert set(original_hashes) == {"unstripped", "stripped"}
    for name, directory in zip(names, candidates):
        assert set(before[name]) == members == {p.name for p in directory.iterdir()}
        assert {member: sha(read(directory / member)) for member in members} == before[name]
        assert all(stat.S_IMODE((directory / member).stat().st_mode) == 0o600 for member in members)
        strip_state = name.rsplit("-", 1)[0]
        assert original_hashes[strip_state] == sha(read(raw / "subjects" / ("original-" + strip_state)))
        index = read(directory / "bundle-index.tsv")
        assert read(directory / "COMPLETE") == ("LI2TOOL-DIRECTORY 1\nindex_sha256 " + sha(index) +
            "\ncandidate_complete true\nqualification_complete false\n").encode()
        rows = ["LI2BUNDLE\t1", "original_sha256\t" + original_hashes[strip_state], "qualification_complete\tfalse",
                "consumer_action\tRuntimeScan-while-gated-until-qualified"]
        rows += ["file\t" + member + "\t" + str(len(read(directory / member))) + "\t" + before[name][member]
                 for member in sorted(members - {"COMPLETE", "bundle-index.tsv"})]
        assert index == ("\n".join(rows) + "\n").encode()
        assert read(directory / "selection.txt") == read(raw / "subjects" / (name + ".selection"))
        for prefix, expected_stdout in (
            ("select-", "selection prepared: sites=1 heads=2 hook=" + name.rsplit("-", 1)[1] + " qualification_complete=false\n"),
            ("prepare-", "candidate_complete=true qualification_complete=false sites=1\n"),
            ("verify-", "elf exec artifact verified: metadata=1 sparse_pages=1 images=1 qualification_complete=false\n"),
        ):
            assert read(raw / (prefix + name) / "stdout.txt") == expected_stdout.encode()
            assert read(raw / (prefix + name) / "stderr.txt") == b""
        assert read(raw / "captures/runtime-target.tsv") == read(directory / "target.tsv")

    capture = raw / "captures"
    assert read(raw / "native/stdout.txt") == NATIVE_STDOUT.encode() and read(raw / "native/stderr.txt") == b""
    assert read(capture / "complete.tsv") == COMPLETE.encode()
    targets = [raw / "subjects/original-unstripped", raw / "subjects/original-stripped"] + [p / "candidate.elf" for p in candidates]
    for name, original in zip(copies, targets):
        assert read(capture / name) == read(original) and stat.S_IMODE((capture / name).stat().st_mode) == 0o500
        assert read(raw / ("ordinary-" + name) / "stdout.txt") == b"elf exec ok\n"
        assert read(raw / ("ordinary-" + name) / "stderr.txt") == b""
    providers = {name: provider_record(capture / (name + ".provider"), capture / name) for name in copies}
    expected_files = set(copies) | {"complete.tsv", "runtime-target.tsv"}
    expected_files.update(name + ".provider" for name in copies)
    directories, pids, xstate_lengths, trace_rows = set(), set(), set(), []
    pages = [0x400000, 0x401000, 0x403000, 0x404000] + list(range(0x406000, 0x416000, 4096))
    for strip_state in range(2):
        for head in range(2):
            for seed in range(2):
                for variant in ("original", "hook-0", "hook-1"):
                    name = f"strip-{strip_state}-head-{head}-seed-{seed}-{variant}"
                    directory = capture / name
                    directories.add(name)
                    files = {"exec.auxv", "exec.maps", "terminal.auxv", "terminal.maps", "startup-pcs.bin", "before-seed.tsv", "journal.bin", "complete.tsv"}
                    files |= {"exec.map-files", "terminal.map-files"}
                    for address in pages + ([] if variant == "original" else [0x418000, 0x420000]):
                        filename = f"loaded-{address:x}.bin"
                        files.add(filename)
                        assert len(read(directory / filename)) == 4096
                    for stem in ["before-call", "after-call"] + [f"point-{i}" for i in range(3 - head)]:
                        for suffix, length in (("regs", 216), ("data", 4096), ("stack", 392), ("xstate", None)):
                            filename = stem + "." + suffix
                            files.add(filename)
                            value = read(directory / filename)
                            if length is not None:
                                assert len(value) == length
                            else:
                                assert value
                                xstate_lengths.add(len(value))
                    if variant != "original" and head == 0:
                        files |= {"hook-call.tsv", "hook-ret.tsv", "hook-context.bin", "hook-saved-xstate.bin"}
                        assert len(read(directory / "hook-context.bin")) == 176
                        assert read(directory / "hook-saved-xstate.bin")
                        assert set(tsv(directory / "hook-call.tsv")) == {"pc", "rsp", "return_word"}
                        assert set(tsv(directory / "hook-ret.tsv")) == {"pc", "return_pc", "rsp_before"}
                    call = [0x401080, 0x401090][head]
                    start = tsv(directory / "before-seed.tsv")
                    assert set(start) == {"entry", "call", "startup_steps", "pid"}
                    assert int(start["entry"]) == 0x401000 and int(start["call"]) == call
                    pid = int(start["pid"])
                    assert pid > 0
                    pids.add(pid)
                    startup = read(directory / "startup-pcs.bin")
                    assert len(startup) == 8 * int(start["startup_steps"]) and startup
                    assert all(0x401000 <= pc < 0x401080 for (pc,) in struct.iter_unpack("<Q", startup))
                    end = tsv(directory / "complete.tsv")
                    assert set(end) == {"status", "steps", "terminal", "owned_tracee_killed_and_reaped"}
                    assert end["status"] == "passed" and end["owned_tracee_killed_and_reaped"] == "true"
                    assert int(end["terminal"]) == call + 5 and int(start["startup_steps"]) < int(end["steps"]) <= 20000
                    copy_name = ("original-" + ("unstripped", "stripped")[strip_state] if variant == "original"
                                 else "candidate-" + str(strip_state * 2 + int(variant[-1])))
                    mapping_links = {}
                    for phase in ("exec", "terminal"):
                        maps, aux = read(directory / (phase + ".maps")), read(directory / (phase + ".auxv"))
                        assert 0 < len(maps) <= 65536 and 0 < len(aux) <= 8192 and len(aux) % 16 == 0
                        mapping_links[phase] = map_file_records(directory / (phase + ".map-files"), maps,
                                                                capture / copy_name, providers[copy_name])
                    recorded = variant == "hook-1" and head == 0
                    assert read(directory / "journal.bin") == (struct.pack("<QQ", 1, 0x401100) + bytes(4080) if recorded else bytes(4096))
                    expected_files.update(name + "/" + filename for filename in files)
                    trace_rows.append(dict(name=name, pid=pid, files=len(files), steps=int(end["steps"]), recording_rows=int(recorded)))
                    trace_rows[-1]["mapping_link_rows"] = mapping_links
    assert len(directories) == len(trace_rows) == 24 and len(expected_files) == 1230
    walked = list(capture.rglob("*"))
    assert all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in walked)
    assert {str(p.relative_to(capture)) for p in walked if p.is_dir()} == directories
    assert {str(p.relative_to(capture)) for p in walked if p.is_file()} == expected_files
    hashes = {name: sha(read(capture / name)) for name in sorted(expected_files)}
    assert hashes == js(raw / "capture-files.json")
    assert sum(row["recording_rows"] for row in trace_rows) == 4
    assert source == js(raw / "source-after.json")
    report = dict(schema=1, status="PASS_SAVED_RECORD_AND_INVENTORY_AUDIT", source_revision=source["revision"],
        source_files=len(source["files"]), stages=27, helper_receipts=receipt_hashes, required_gates=4,
        capture_files=1230, provider_records=providers, mapping_link_records=48, captures_sha256=sha(read(raw / "capture-files.json")), traces=trace_rows,
        ordinary_processes=6, recording_journal_rows=4, observed_pid_values=len(pids), canonical_xstate_lengths=sorted(xstate_lengths),
        architectural_state_authority="Existing reviewed driver assertions; this audit checks snapshot inventory, not a replacement comparator.",
        scope="No new workload/native/performance/full-A3 credit. This audit only reads the closed recipe tree and recorded Git blobs.")
    output.mkdir()
    with (output / "audit.json").open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("PASS closed ELF-exec records: 27 stages, 26 helper receipts, 24 traces, 1230 captures, six ordinary processes")


if __name__ == "__main__":
    main()
