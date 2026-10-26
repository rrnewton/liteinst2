#!/usr/bin/env python3
"""Build the finite common-corpus input and check originals; perform no rewriting."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import time

HELPER_SHA = "c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44"
DATASETS = ["empty", "singleton", "pair-reverse", "equal-17", "sorted-17", "reverse-17", "duplicates-17", "mixed-64"]
RUNTIME = dict(PATH="/usr/bin:/bin", LC_ALL="C", PYTHONDONTWRITEBYTECODE="1")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_loads(path):
    data = path.read_bytes()
    assert 64 <= len(data) <= 4 * 1024 * 1024
    assert data[:7] == b"\x7fELF\x02\x01\x01"
    assert struct.unpack_from("<HHI", data, 16) == (2, 62, 1)
    assert struct.unpack_from("<HH", data, 52) == (64, 56)
    offset, count = struct.unpack_from("<Q", data, 32)[0], struct.unpack_from("<H", data, 56)[0]
    assert 1 <= count <= 64 and offset + count * 56 <= len(data)
    headers = [struct.unpack_from("<IIQQQQQQ", data, offset + i * 56) for i in range(count)]
    loads = [row for row in headers if row[0] == 1]
    assert loads and all(row[2] + row[5] <= len(data) and row[5] <= row[6] for row in loads)
    assert all(row[1] & 3 != 3 and row[2] % 4096 == row[3] % 4096 for row in loads)
    assert sum(row[0] == 3 for row in headers) == 1, "ordinary interpreter required"
    return data, headers, loads


def main():
    assert not sys.flags.optimize, "Assertions required"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    raw = parser.parse_args().raw
    source = Path(__file__).resolve().parent
    repo = source.parents[1]
    assert raw.is_absolute() and raw.parent.resolve(strict=True) == raw.parent
    assert raw.is_relative_to(repo / "ignored") and not raw.exists()
    git = lambda *args: subprocess.check_output(["/usr/bin/git", "-C", str(repo), *args], timeout=15)
    assert not git("diff", "HEAD", "--"), "clean tracked source required"
    revision = git("rev-parse", "HEAD").decode().strip()
    names = [name for name in git("ls-files", "-z").decode().split("\0") if name]
    assert "BRIEF-li2core.md" not in names and str(Path(__file__).resolve().relative_to(repo)) in names
    before = {name: digest(repo / name) for name in names}
    helper = repo / "tools/unwind-oracle/bounded_command.py"
    assert digest(helper) == HELPER_SHA
    fixture = json.loads((source / "datasets.json").read_bytes())["datasets"]
    assert [row["name"] for row in fixture] == DATASETS
    for i, row in enumerate(fixture):
        assert row["id"] == i and len(row["input"]) <= 64
        assert all(type(x) is int and 0 <= x < 1 << 64 for x in row["input"])
        assert row["expected"] == sorted(row["input"])
        expected = f"case={row['name']} n={len(row['input'])} sorted=" + ",".join(map(str, sorted(row["input"]))) + "\n"
        assert row["expected_stdout"] == expected
        assert (source / "expected" / (row["name"] + ".stdout")).read_bytes() == expected.encode()
    raw.mkdir()

    def save(name, value):
        with (raw / name).open("x") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")

    hardware = dict(host_label="AMD EPYC Zen 5 dev host", architecture=platform.machine(),
                    cpu_model=next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")),
                    logical_cpus=os.cpu_count(), kernel_release=platform.release(), libc=platform.libc_ver())
    assert hardware["architecture"] == "x86_64" and "AMD EPYC" in hardware["cpu_model"]
    save("source.json", dict(revision=revision, files=before))
    save("hardware.json", hardware)
    tool_paths = [Path("/usr/bin") / name for name in ("gcc", "strip", "readelf", "nm")]
    tools = {str(path): dict(resolved=str(path.resolve(strict=True)), sha256=digest(path.resolve())) for path in tool_paths}
    save("tools.json", tools)
    stage_names = ["gcc-version", "strip-version", "compile", "strip"]
    for variant in ("unstripped", "stripped"):
        stage_names += [variant + "-readelf", variant + "-nm"]
        stage_names += [variant + "-" + name for name in DATASETS]
        stage_names += [variant + "-refuse-" + name for name in ("usage", "dataset", "overwrite")]
    assert len(stage_names) == 30
    save("stage-inventory.json", stage_names)
    results, checks, artifacts = [], [], {}
    complete = False
    phase = "build"

    def execute(name, argv, expected_exit=0, compiler=False):
        assert name == stage_names[len(results)]
        directory = raw / name
        directory.mkdir()
        (directory / "tmp").mkdir()
        request = dict(argv=list(map(str, argv)), cwd=str(repo), env=dict(RUNTIME, TMPDIR=str(directory / "tmp")),
                       stdout=str(directory / "stdout.txt"), stderr=str(directory / "stderr.txt"),
                       cpu_seconds=60 if compiler else 20, wall_seconds=90 if compiler else 30,
                       file_bytes=(128 if compiler else 16) * 1024 * 1024)
        save(name + "/request.json", request)
        outer = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "100s" if compiler else "40s",
                 "/usr/bin/python3.9", "-B", str(helper), "--request", str(directory / "request.json"),
                 "--receipt", str(directory / "receipt.json")]
        command = dict(name=name, request=request, expected_exit=expected_exit, outer_argv=outer,
                       outer_env=RUNTIME, parent_timeout_seconds=115 if compiler else 55)
        save(name + "/command.json", command)
        started = time.monotonic()
        with (directory / "helper.stdout").open("xb") as stdout, (directory / "helper.stderr").open("xb") as stderr:
            process = subprocess.Popen(outer, cwd=repo, env=RUNTIME, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            timed_out = False
            try:
                code = process.wait(timeout=command["parent_timeout_seconds"])
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
        result = dict(command, parent_exit=code, parent_timeout=timed_out, operational_seconds=time.monotonic()-started)
        results.append(result)
        save(name + "/result.json", result)
        print(name, code, flush=True)
        assert not timed_out and code == (0 if expected_exit == 0 else 1)
        receipt = json.loads((directory / "receipt.json").read_bytes())
        assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
        assert type(receipt["exit"]) is int and receipt["exit"] == expected_exit
        assert receipt["request_sha256"] == digest(directory / "request.json") and receipt["helper_sha256"] == HELPER_SHA
        assert receipt["absence_proof"] == "ECHILD" and receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
        assert receipt["unexpected_descendants"] == receipt["cleanup_events"] == []
        assert receipt["cleanup_error"] is None and receipt["aborted"] is None
        for stream in ("stdout", "stderr"):
            assert receipt[stream + "_sha256"] == digest(directory / (stream + ".txt"))
        terminal = dict(exit=expected_exit, wall_timeout=False, absence_proof="ECHILD", descendants=0, success=expected_exit == 0)
        assert (directory / "helper.stdout").read_bytes() == (json.dumps(terminal) + "\n").encode()
        assert not (directory / "helper.stderr").read_bytes()
        return directory

    try:
        for tool in ("gcc", "strip"):
            directory = execute(tool + "-version", ["/usr/bin/" + tool, "--version"])
            assert (directory / "stdout.txt").read_bytes() and not (directory / "stderr.txt").read_bytes()
        original = raw / "original-unstripped"
        compile_args = ["/usr/bin/gcc", "-std=c11", "-O2", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
                        "-fno-pie", "-no-pie", "-fno-lto", "-fno-toplevel-reorder", "-fno-reorder-blocks-and-partition",
                        "-fno-stack-protector", "-fcf-protection=none", "-Wall", "-Wextra", "-Werror",
                        "-MD", "-MF", str(raw / "compile.d"),
                        "-Wl,-Map," + str(raw / "link.map"), str(source / "heap_sort.c"), "-o", str(original)]
        directory = execute("compile", compile_args, compiler=True)
        assert not (directory / "stdout.txt").read_bytes() and not (directory / "stderr.txt").read_bytes()
        directory = execute("strip", ["/usr/bin/strip", "--strip-all", "-o", raw / "original-stripped", original])
        assert not (directory / "stdout.txt").read_bytes() and not (directory / "stderr.txt").read_bytes()
        phase = "ELF strip parity"
        a, ph_a, loads_a = elf_loads(original)
        b, ph_b, loads_b = elf_loads(raw / "original-stripped")
        assert ph_a == ph_b and loads_a == loads_b
        for load in loads_a:
            offset, length = load[2], load[5]
            left, right = bytearray(a[offset:offset+length]), bytearray(b[offset:offset+length])
            for position in list(range(40, 48)) + list(range(60, 64)):
                if offset <= position < offset + length:
                    left[position-offset] = right[position-offset] = 0
            assert left == right, "identical loaded bytes except declared ELF section-table coordinates"
        checks.append("Exact original LOAD parity with only e_shoff/e_shnum/e_shstrndx masked in ELF header")
        for variant in ("unstripped", "stripped"):
            executable = raw / ("original-" + variant)
            artifacts[variant] = dict(sha256=digest(executable), bytes=executable.stat().st_size)
            phase = variant + " metadata"
            directory = execute(variant + "-readelf", ["/usr/bin/readelf", "--wide", "--headers", "--program-headers", "--sections", "--symbols", executable])
            assert not (directory / "stderr.txt").read_bytes()
            directory = execute(variant + "-nm", ["/usr/bin/nm", "-S", "--defined-only", "--format=posix", executable])
            if variant == "stripped":
                assert not (directory / "stdout.txt").read_bytes()
                assert (directory / "stderr.txt").read_bytes() == ("/usr/bin/nm: " + str(executable) + ": no symbols\n").encode()
            else:
                assert not (directory / "stderr.txt").read_bytes()
            for row in fixture:
                phase = variant + " " + row["name"]
                journal = raw / (variant + "-" + row["name"] + ".journal")
                directory = execute(variant + "-" + row["name"], [executable, row["name"], journal])
                assert (directory / "stdout.txt").read_bytes() == row["expected_stdout"].encode()
                assert not (directory / "stderr.txt").read_bytes()
                saved = journal.read_bytes()
                expected = struct.pack("<8Q", 0x6c69326a6f75726e, 1, 16384, 0, 0, 0, 0, 0) + bytes(16384 * 8) + struct.pack("<Q", 0x7265636f72647321)
                assert saved == expected and len(saved) == 131144
                checks.append(variant + "/" + row["name"] + ": exact complete sorted output and zero journal")
            for name, code, stderr in (("usage", 64, b"usage: heap-sort DATASET NEW_JOURNAL_FILE\n"),
                                       ("dataset", 65, b"dataset or page-size refusal\n"),
                                       ("overwrite", 67, b"journal output failure\n")):
                phase = variant + " refusal " + name
                journal = raw / (variant + "-refuse-" + name + ".journal")
                if name == "overwrite":
                    with journal.open("xb") as stream:
                        stream.write(b"preserve existing journal\n")
                argv = [executable] if name == "usage" else [executable, "not-a-dataset" if name == "dataset" else "mixed-64", journal]
                directory = execute(variant + "-refuse-" + name, argv, expected_exit=code)
                assert not (directory / "stdout.txt").read_bytes() and (directory / "stderr.txt").read_bytes() == stderr
                if name == "overwrite":
                    assert journal.read_bytes() == b"preserve existing journal\n"
                else:
                    assert not journal.exists()
                checks.append(variant + "/" + name + ": exact required refusal")
            assert digest(executable) == artifacts[variant]["sha256"]
        complete = True
    finally:
        after = {name: digest(repo / name) for name in names}
        save("source-after.json", dict(revision=git("rev-parse", "HEAD").decode().strip(), files=after))
        save("results.json", results)
        save("checks.json", checks)
        save("artifacts.json", artifacts)
        for path, recorded in tools.items():
            assert str(Path(path).resolve(strict=True)) == recorded["resolved"] and digest(Path(path).resolve()) == recorded["sha256"]
        assert before == after and git("rev-parse", "HEAD").decode().strip() == revision
        assert not git("diff", "HEAD", "--")
        save("summary.json", dict(schema=1, revision=revision, hardware=hardware, completed=complete,
                                  last_phase=phase, planned_stages=30, observed_stages=len(results),
                                  checks=checks, artifacts=artifacts, ordinary_original_runs=16 if complete else None,
                                  required_refusals=6 if complete else None, rewriting_runs=0, qualified=False,
                                  scope="Original fixture build/output only; no rewrite, decoder, site-retention, journal-hook, or architectural-state qualification"))


if __name__ == "__main__":
    main()
