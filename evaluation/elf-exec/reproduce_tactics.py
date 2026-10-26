#!/usr/bin/env python3
"""Qualify the offline frontend and its four additional normally loaded ET_EXEC tactic fixtures."""
import argparse
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time


def main():
    if sys.flags.optimize:
        raise SystemExit("Assertions required")
    parser = argparse.ArgumentParser()
    for name in ("raw", "toolchain", "user-home", "cargo-home", "b1-raw"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--b1-closed-and-reaped", action="store_true", required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    raw = args.raw
    assert raw.is_absolute() and raw.parent.resolve() == raw.parent
    assert raw.is_relative_to(repo / "ignored") and not raw.exists()
    for path in (args.toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve() == path and path.is_dir()
    git = lambda *a: subprocess.check_output(["/usr/bin/git", "-C", str(repo), *a], timeout=15)
    digest = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    revision = git("rev-parse", "HEAD").decode().strip()
    assert not git("diff", "HEAD", "--"), "clean tracked source required"
    sources = {name: digest(repo / name)
               for name in git("ls-files", "-z").decode().split("\0") if name}
    assert "BRIEF-li2core.md" not in sources
    assert str(Path(__file__).resolve().relative_to(repo)) in sources
    raw.mkdir()

    def save(name, value):
        with (raw / name).open("x") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")

    save("source.json", {"revision": revision, "files": sources})
    cpu = Path("/proc/cpuinfo").read_text()
    save("hardware.json", {
        "cpu_model": next(row.split(":", 1)[1].strip() for row in cpu.splitlines()
                          if row.startswith("model name")),
        "architecture": platform.machine(), "logical_cpus": os.cpu_count(),
        "kernel_release": platform.release(), "libc": platform.libc_ver(),
    })
    tool = args.toolchain / "bin"
    env = {
        "CARGO_BUILD_JOBS": "4", "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(repo / "target"),
        "CARGO_HOME": str(args.cargo_home), "HOME": str(args.user_home),
        "RUSTC": str(tool / "rustc"), "RUSTDOC": str(tool / "rustdoc"),
        "RUSTC_WORKSPACE_WRAPPER": "", "RUSTC_WRAPPER": "",
        "RUST_TEST_THREADS": "4", "LC_ALL": "C",
        "PATH": str(tool) + ":/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
    }
    runtime_env = {"LC_ALL": "C", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"}
    tools = {}
    for name, executable, option in (
        ("rustc", tool / "rustc", "-vV"), ("cargo", tool / "cargo", "-V"),
        ("gcc", Path("/usr/bin/gcc"), "--version"),
        ("ld", Path("/usr/bin/ld"), "--version"),
        ("strip", Path("/usr/bin/strip"), "--version"),
    ):
        tools[name] = {"argv": [str(executable), option], "sha256": digest(executable.resolve()),
                       "output": subprocess.check_output([str(executable), option], env=env,
                                                         text=True, timeout=15)}
    save("tools.json", tools)
    # All old B1 source/gate/native phases are a separate closed prerequisite.
    # The caller runs unchanged reproduce.py first and confirms its parent exit.
    b1 = args.b1_raw
    assert b1.is_absolute() and b1.resolve(strict=True) == b1 and b1.is_dir()
    assert b1.is_relative_to(repo / "ignored")
    assert not b1.is_relative_to(raw) and not raw.is_relative_to(b1)
    assert digest(repo / "evaluation/elf-exec/reproduce.py") == "ab041ad6611d0c8000a77b70cdaaee4ef25433c94e5c9e4ff4d46b81a14b2c36"
    family = {
        "B2": {"define": 2, "heads": [0,3,8], "points": [[4,3,2],[4,3,2]], "images": 1, "comparisons": 120},
        "T1": {"define": 3, "heads": [0,2,7], "points": [[4,3,2],[4,3,2]], "images": 1, "comparisons": 120},
        "T2": {"define": 4, "heads": [0,3,11,16,64,74], "points": [[5,4,3,2,3,2],[5,4,3,2,3,2]], "images": 2, "comparisons": 248},
        "T3": {"define": 5, "heads": [0,2,3,64,74], "points": [[3,3,2,3,2],[4,3,2,3,2]], "images": 2, "comparisons": 188},
    }
    assert sum(len(row["heads"]) for row in family.values()) == 17
    assert sum(row["comparisons"] for row in family.values()) == 676
    stage_names = ["codec-compile"]
    for tactic in family:
        stage_names += [prefix + tactic for prefix in ("assemble-", "link-", "strip-")]
        for strip_state in ("unstripped", "stripped"):
            for hook in ("null", "journal"):
                stage_names += [prefix + tactic + "-" + strip_state + "-" + hook
                                for prefix in ("select-", "prepare-", "verify-")]
        stage_names += ["controls-" + tactic, "native-" + tactic]
        stage_names += ["ordinary-" + tactic + "-" + name for name in
                        ("original-unstripped", "original-stripped", "candidate-0", "candidate-1", "candidate-2", "candidate-3")]
    assert len(stage_names) == 93
    save("stage-inventory.json", stage_names)
    results = []
    helper = repo / "tools/unwind-oracle/bounded_command.py"

    def execute(name, argv, environment, compiler=False, required=False):
        assert name == stage_names[len(results)], "finite stage inventory and order"
        directory = raw / name
        directory.mkdir()
        (directory / "tmp").mkdir()
        environment = dict(environment, TMPDIR=str(directory / "tmp"))
        row = {"name": name, "argv": argv, "cwd": str(repo), "env": environment,
               "start_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if required:
            actual, outer_env, timeout = argv, environment, 1000
            stdout, stderr = "stdout.txt", "stderr.txt"
        else:
            request = dict(argv=argv, cwd=str(repo), env=environment,
                           stdout=str(directory / "stdout.txt"), stderr=str(directory / "stderr.txt"),
                           cpu_seconds=60 if compiler else 20,
                           wall_seconds=90 if compiler else 30,
                           file_bytes=(128 if compiler else 16) * 1024 * 1024)
            save(name + "/request.json", request)
            actual = ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
                      "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(helper),
                      "--request", str(directory / "request.json"),
                      "--receipt", str(directory / "receipt.json")]
            outer_env = runtime_env
            timeout = 115 if compiler else 55
            stdout, stderr = "helper.stdout", "helper.stderr"
            row["request"] = request
        row.update(outer_argv=actual, outer_env=outer_env, parent_timeout_seconds=timeout)
        save(name + "/command.json", row)
        started = time.monotonic()
        with (directory / stdout).open("xb") as out, (directory / stderr).open("xb") as err:
            process = subprocess.Popen(actual, cwd=repo, env=outer_env, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
                row["parent_timeout"] = True
        row.update(exit=code, elapsed_seconds=time.monotonic() - started)
        results.append(row)
        save(name + "/result.json", row)
        print(name, code, flush=True)
        assert code == 0, "failed phase retained; later phases unrun"
        if not required:
            receipt = json.loads((directory / "receipt.json").read_text())
            assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout",
                    "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
                    "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
            assert type(receipt["exit"]) is int and receipt["exit"] == 0
            assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
            assert type(receipt["elapsed_seconds"]) in (int, float)
            assert math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
            assert receipt["request_sha256"] == digest(directory / "request.json")
            assert receipt["helper_sha256"] == digest(helper)
            assert receipt["absence_proof"] == "ECHILD"
            assert receipt["unexpected_descendants"] == [] and receipt["cleanup_events"] == []
            assert receipt["cleanup_error"] is None and receipt["aborted"] is None
            expected = {"exit": 0, "wall_timeout": False, "absence_proof": "ECHILD", "descendants": 0, "success": True}
            assert (directory / "helper.stdout").read_text() == json.dumps(expected) + "\n"
            assert not (directory / "helper.stderr").read_bytes()
            for key in ("stdout", "stderr"):
                assert receipt[key + "_sha256"] == digest(directory / (key + ".txt"))
        return directory

    def authenticate(directory, original, selection, images):
        expected = {"COMPLETE", "bundle-index.tsv", "candidate.elf", "image-0000.bin",
                    "ledger.tsv", "metadata.li2meta", "plan-ledger.tsv", "report.tsv",
                    "selection.txt", "site-1.diagnostics.txt", "source.li2sparse", "target.tsv"}
        assert images in (1, 2)
        if images == 2:
            expected.add("image-0001.bin")
        paths = list(directory.iterdir())
        assert {p.name for p in paths} == expected
        assert all(stat.S_ISREG(p.lstat().st_mode) and p.stat().st_size <= 1024 * 1024
                   and stat.S_IMODE(p.stat().st_mode) == 0o600 for p in paths)
        index = directory / "bundle-index.tsv"
        assert (directory / "COMPLETE").read_text() == (
            "LI2TOOL-DIRECTORY 1\nindex_sha256 " + digest(index)
            + "\ncandidate_complete true\nqualification_complete false\n")
        rows = index.read_text().splitlines()
        assert rows[:4] == ["LI2BUNDLE\t1", "original_sha256\t" + digest(original),
                           "qualification_complete\tfalse",
                           "consumer_action\tRuntimeScan-while-gated-until-qualified"]
        wanted = sorted(expected - {"COMPLETE", "bundle-index.tsv"})
        assert rows[4:] == ["file\t" + name + "\t" + str((directory / name).stat().st_size)
                            + "\t" + digest(directory / name) for name in wanted]
        assert (directory / "selection.txt").read_bytes() == selection.read_bytes()
        return {name: digest(directory / name) for name in sorted(expected)}


    # Retain every prerequisite byte/hash consumed here; later stages may not
    # mutate the earlier campaign or silently replace its artifacts.
    prerequisite = {}
    def retain(path):
        assert path.is_relative_to(b1) and path.resolve(strict=True) == path
        assert stat.S_ISREG(path.lstat().st_mode)
        value = path.read_bytes()
        checksum = hashlib.sha256(value).hexdigest()
        assert prerequisite.get(str(path), checksum) == checksum
        prerequisite[str(path)] = checksum
        return value
    def prior_json(name):
        return json.loads(retain(b1 / name))
    def prior_index(directory, values):
        for name, checksum in values.items():
            relative = Path(name)
            assert not relative.is_absolute() and ".." not in relative.parts
            assert hashlib.sha256(retain(directory / relative)).hexdigest() == checksum
    def prior_receipt(row):
        name = row["name"]
        directory = b1 / name
        request = prior_json(name + "/request.json")
        assert row["request"] == request
        compiler = name in ("native-compile", "codec-compile")
        assert set(request) == {"argv", "cwd", "env", "stdout", "stderr", "cpu_seconds", "wall_seconds", "file_bytes"}
        assert request["cwd"] == str(repo)
        assert request["stdout"] == str(directory / "stdout.txt")
        assert request["stderr"] == str(directory / "stderr.txt")
        assert (request["cpu_seconds"], request["wall_seconds"], request["file_bytes"]) == (
            60 if compiler else 20, 90 if compiler else 30, (128 if compiler else 16) * 1024 * 1024)
        assert row["parent_timeout_seconds"] == (115 if compiler else 55)
        assert row["outer_argv"] == ["/usr/bin/timeout", "--signal=TERM", "--kill-after=10s",
            "100s" if compiler else "40s", "/usr/bin/python3.9", "-B", str(helper),
            "--request", str(directory / "request.json"), "--receipt", str(directory / "receipt.json")]
        assert row["outer_env"] == runtime_env
        receipt = prior_json(name + "/receipt.json")
        assert set(receipt) == {"request_sha256", "helper_sha256", "exit", "wall_timeout",
            "unexpected_descendants", "absence_proof", "stdout_sha256", "stderr_sha256",
            "elapsed_seconds", "cleanup_events", "cleanup_error", "aborted", "inputs_unchanged"}
        assert type(receipt["exit"]) is int and receipt["exit"] == 0
        assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True
        assert type(receipt["elapsed_seconds"]) in (int,float) and math.isfinite(receipt["elapsed_seconds"]) and receipt["elapsed_seconds"] >= 0
        assert receipt["request_sha256"] == hashlib.sha256(retain(directory / "request.json")).hexdigest()
        assert receipt["helper_sha256"] == digest(helper)
        assert receipt["absence_proof"] == "ECHILD"
        assert receipt["unexpected_descendants"] == receipt["cleanup_events"] == []
        assert receipt["cleanup_error"] is receipt["aborted"] is None
        expected = {"exit":0,"wall_timeout":False,"absence_proof":"ECHILD","descendants":0,"success":True}
        assert retain(directory / "helper.stdout") == (json.dumps(expected) + "\n").encode()
        assert retain(directory / "helper.stderr") == b""
        for stream in ("stdout", "stderr"):
            assert receipt[stream + "_sha256"] == hashlib.sha256(retain(directory / (stream + ".txt"))).hexdigest()

    # This is a distinct prerequisite check, not a relabelled B1 execution.
    old_source = prior_json("source.json")
    assert old_source == prior_json("source-after.json") == {"revision":revision,"files":sources}
    old_stages = ["required","comparison","native-compile","codec-compile","target","assemble","link","strip"]
    for stripped in ("unstripped", "stripped"):
        for hook in ("null", "journal"):
            old_stages += [prefix + stripped + "-" + hook for prefix in ("select-","prepare-","verify-")]
    old_stages += ["native","ordinary-original-unstripped","ordinary-original-stripped"]
    old_stages += ["ordinary-candidate-" + str(n) for n in range(4)]
    old_results = prior_json("results.json")
    assert len(old_results) == 27 and [r["name"] for r in old_results] == prior_json("stage-inventory.json") == old_stages
    for row in old_results:
        assert row == prior_json(row["name"] + "/result.json")
        assert type(row["exit"]) is int and row["exit"] == 0 and not row.get("parent_timeout",False)
        assert row == dict(prior_json(row["name"] + "/command.json"), exit=0,elapsed_seconds=row["elapsed_seconds"])
        assert math.isfinite(row["elapsed_seconds"]) and row["elapsed_seconds"] >= 0
        if row["name"] != "required":
            prior_receipt(row)
    gates = prior_json("required/gates/commands.json")
    assert gates["head"] == revision and gates["source_sha256"] == sources
    assert gates["tracked_diff_sha256"] == hashlib.sha256(b"").hexdigest()
    wanted = [("fmt",["cargo","fmt","--check"],180),
        ("clippy",["cargo","clippy","--workspace","--all-targets","--all-features","--","-D","warnings"],180),
        ("test",["cargo","test","--workspace"],360),
        ("check",["cargo","check","--workspace","--all-features","--all-targets"],180)]
    assert len(gates["records"]) == 4
    for row,(name,argv,wall) in zip(gates["records"],wanted):
        assert (row["name"],row["argv"],row["timeout_seconds"],row["exit"]) == (name,argv,wall,0)
        assert row["sha256"] == hashlib.sha256(retain(b1 / "required/gates" / (name+".log"))).hexdigest()
    expected_native = ("PASS kernel-exec MOV5/RET: 8 original + 16 rewritten traces; 72 full-state comparisons; "
                       "24 subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows\n")
    assert retain(b1 / "native/stdout.txt") == expected_native.encode()
    assert retain(b1 / "native/stderr.txt") == b""
    assert retain(b1 / "captures/complete.tsv") == ("status\tpassed\noriginal_traces\t8\nrewritten_traces\t16\n"
        "full_state_comparisons\t72\nsubject_call_ret_witnesses\t24\nhook_call_return_witnesses\t8\n"
        "recording_hook_rows\t4\nmanual_load_mappings\t0\npost_seed_state_repairs\t0\n").encode()
    old_captures = prior_json("capture-files.json")
    assert len(old_captures) == 1230
    prior_index(b1 / "captures",old_captures)
    old_candidates = prior_json("candidate-files-before.json")
    assert old_candidates == prior_json("candidate-files-after.json")
    assert set(old_candidates) == {a+"-"+b for a in ("unstripped","stripped") for b in ("null","journal")}
    for name,values in old_candidates.items():
        prior_index(b1 / (name+"-candidate"),values)
    for name,checksum in prior_json("originals.json").items():
        assert hashlib.sha256(retain(b1 / "subjects" / ("original-"+name))).hexdigest() == checksum
    binaries = prior_json("artifacts.json")
    assert set(binaries) == {"elf-exec-oracle","liteinst-rewrite","verify_elf_exec"}
    for name,row in binaries.items():
        assert hashlib.sha256(retain(b1 / "artifacts" / name)).hexdigest() == row["sha256"]
    for name in ("original-unstripped","original-stripped","candidate-0","candidate-1","candidate-2","candidate-3"):
        assert retain(b1 / ("ordinary-"+name) / "stdout.txt") == b"elf exec ok\n"
        assert retain(b1 / ("ordinary-"+name) / "stderr.txt") == b""
    driver, frontend = b1 / "artifacts/elf-exec-oracle", b1 / "artifacts/liteinst-rewrite"
    target_record = b1 / "target/stdout.txt"
    retain(target_record)
    save("b1-prerequisite-inputs.json",prerequisite)
    def load_pages(path, tactic, candidate):
        data = path.read_bytes()
        assert 64 <= len(data) <= 1024 * 1024
        assert data[:16] == b"\x7fELF" + bytes([2,1,1,0,0]) + bytes(7)
        kind, machine, version, entry, offset = struct.unpack_from("<HHIQQ",data,16)
        assert (kind,machine,version,entry) == (2,62,1,0x401000)
        size,count = struct.unpack_from("<HH",data,54)
        assert size == 56 and count == (9 + family[tactic]["images"] if candidate else 8)
        assert offset + size * count <= len(data)
        headers = [struct.unpack_from("<IIQQQQQQ",data,offset+size*i) for i in range(count)]
        loads = [p for p in headers if p[0] == 1]
        original = [(0x400000,4096,4),(0x401000,4096,5),(0x403000,4096,6),
                    (0x404000,4096,6),(0x406000,65536,6),(0x421000,4096,5)]
        assert [(p[3],p[6],p[1]) for p in loads[:6]] == original
        assert len(loads) == 6 + (1 + family[tactic]["images"] if candidate else 0)
        selected = {"B2":0x2afa9105,"T1":0x423bbe,"T2":0x572b9105,"T3":0x4421100}[tactic]
        victim = 0x54455e if tactic == "T2" else 0x6421100
        expected = {0x422000:4,selected & ~4095:5}
        if family[tactic]["images"] == 2:
            expected[victim & ~4095] = 5
        if candidate:
            assert {p[3]:p[1] for p in loads[6:]} == expected
            for p in loads[6:]:
                if p[3] == 0x422000:
                    assert p[6] == count * 56 + len(b"LI2TOOL-CANDIDATE-UNREADY-V1\0") + 64
                else:
                    assert 0 < p[6] <= 8192
        pages = set()
        for p in loads:
            assert p[3] == p[4] and p[2] % 4096 == p[3] % 4096 == 0
            assert p[5] == p[6] and p[5] > 0
            assert p[2]+p[5] <= len(data) and p[7] == 4096
            end_page = ((p[3] + p[6] + 4095) // 4096) * 4096
            owned = set(range(p[3],end_page,4096))
            assert not owned & pages
            pages.update(owned)
        assert 21 <= len(pages) <= 26
        return sorted(pages)

    def capture_inventory(tactic, originals, candidates):
        files = {"original-unstripped","original-stripped","runtime-target.tsv",
                 "complete.tsv","capture-inventory.tsv"}
        copies = ["original-unstripped","original-stripped"] + ["candidate-"+str(i) for i in range(4)]
        files.update(copies)
        files.update(name+".provider" for name in copies)
        directories = set()
        original_pages = [load_pages(p,tactic,False) for p in originals.values()]
        candidate_pages = [load_pages(p/"candidate.elf",tactic,True) for p in candidates]
        for strip_state in range(2):
            for head in range(len(family[tactic]["heads"])):
                for seed in range(2):
                    for variant in ("original","hook-0","hook-1"):
                        directory = f"strip-{strip_state}-head-{head}-seed-{seed}-{variant}"
                        directories.add(directory)
                        names = {"exec.auxv","exec.maps","terminal.auxv","terminal.maps",
                                 "exec.map-files","terminal.map-files","startup-pcs.bin",
                                 "before-seed.tsv","journal.bin","complete.tsv","transfers.tsv"}
                        pages = original_pages[strip_state] if variant == "original" else candidate_pages[2*strip_state+int(variant[-1])]
                        names.update(f"loaded-{address:x}.bin" for address in pages)
                        for stem in ["before-call","after-call"] + ["point-"+str(i) for i in range(family[tactic]["points"][seed][head])]:
                            names.update(stem+suffix for suffix in (".regs",".xstate",".data",".stack"))
                        if variant != "original" and head == 0:
                            names.update(("hook-call.tsv","hook-ret.tsv","hook-context.bin","hook-saved-xstate.bin"))
                        files.update(directory+"/"+name for name in names)
        assert len(directories) == 12 * len(family[tactic]["heads"])
        return files,directories

    def expected_controls(tactic):
        rows = [tactic+" unknown-entries Refused(7) no-artifact",
                tactic+" source-byte-tamper original-identity",
                tactic+" hook-byte-tamper-rebound-original hook-identity",
                tactic+" selected-placement-unavailable Refused(11) no-artifact"]
        if tactic in ("T2","T3"):
            rows.append(tactic+" one-image-budget Refused(11) no-artifact")
        rows.append(f"PASS adjacent tactic refusals: tactic={tactic} cases={len(rows)} qualification_complete=false")
        return "\n".join(rows)+"\n"

    try:
        codec = execute("codec-compile",[str(tool/"cargo"),"build","-p","liteinst-rewrite",
                        "--example","verify_elf_tactics","--example","check_elf_tactic_refusals",
                        "--offline","--locked","--message-format=json"],env,compiler=True)
        artifacts = raw / "artifacts"
        artifacts.mkdir()
        new_binaries = {}
        messages = [json.loads(line) for line in (codec/"stdout.txt").read_text().splitlines()]
        assert 1 <= len(messages) <= 256
        assert messages[-1] == {"reason":"build-finished","success":True}
        assert sum(row.get("reason") == "build-finished" for row in messages) == 1
        assert all(row.get("reason") in ("compiler-artifact","build-script-executed","build-finished") for row in messages)
        assert not any(line.startswith(("warning:","error:")) for line in (codec/"stderr.txt").read_text().splitlines())
        for name in ("verify_elf_tactics","check_elf_tactic_refusals"):
            selected = [row for row in messages if row.get("reason") == "compiler-artifact"
                        and row["target"]["name"] == name and row.get("executable")]
            assert len(selected) == 1
            item = selected[0]
            assert item["manifest_path"] == str(repo/"tools/elf-rewrite/Cargo.toml")
            assert item["target"]["kind"] == ["example"] and item["target"]["crate_types"] == ["bin"]
            assert item["profile"] == {"opt_level":"0","debuginfo":2,"debug_assertions":True,"overflow_checks":True,"test":False}
            assert item["features"] == [] and type(item["fresh"]) is bool
            assert item["filenames"] == [str(repo/"target/debug/examples"/name)]
            assert item["executable"] == item["filenames"][0]
            binary = artifacts/name
            shutil.copy2(item["executable"],binary)
            new_binaries[name] = {"artifact":item,"sha256":digest(binary)}
        save("artifacts.json",new_binaries)
        fixture = repo/"tests/fixtures/elf-exec-tactics"
        subjects = raw/"subjects"
        subjects.mkdir()
        summaries = {}
        for tactic,contract in family.items():
            subject_dir = subjects/tactic
            subject_dir.mkdir()
            object_file = subject_dir/"subject.o"
            original = subject_dir/"original-unstripped"
            stripped = subject_dir/"original-stripped"
            execute("assemble-"+tactic,["/usr/bin/gcc","-c","-nostdlib","-fno-pie","-Wa,--fatal-warnings",
                    "-Wa,--defsym,TACTIC="+str(contract["define"]),str(fixture/"subject.S"),"-o",str(object_file)],runtime_env)
            execute("link-"+tactic,["/usr/bin/ld","-m","elf_x86_64","-nostdlib","--build-id=none","-z","noexecstack",
                    "-T",str(fixture/"subject.ld"),str(object_file),"-o",str(original)],runtime_env)
            execute("strip-"+tactic,["/usr/bin/strip","--strip-all","-o",str(stripped),str(original)],runtime_env)
            originals = {"unstripped":original,"stripped":stripped}
            before = {name:digest(path) for name,path in originals.items()}
            save("originals-"+tactic+".json",before)
            candidates,authenticated = [],{}
            for strip_state,subject in originals.items():
                for hook in ("null","journal"):
                    name = tactic+"-"+strip_state+"-"+hook
                    selection = subject_dir/(strip_state+"-"+hook+".selection")
                    selected = execute("select-"+name,["/usr/bin/python3.9","-B",str(repo/"evaluation/elf-exec/render_tactics.py"),
                            str(subject),str(target_record),tactic,hook,str(selection)],runtime_env)
                    assert (selected/"stdout.txt").read_text() == f"selection prepared: sites=1 heads={len(contract['heads'])} tactic={tactic} hook={hook} qualification_complete=false\n"
                    assert not (selected/"stderr.txt").read_bytes()
                    output = raw/(name+"-candidate")
                    produced = execute("prepare-"+name,[str(frontend),"prepare",str(subject),str(selection),str(output)],runtime_env)
                    assert (produced/"stdout.txt").read_text() == "candidate_complete=true qualification_complete=false sites=1\n"
                    assert not (produced/"stderr.txt").read_bytes()
                    authenticated[name] = authenticate(output,subject,selection,contract["images"])
                    verified = execute("verify-"+name,[str(artifacts/"verify_elf_tactics"),str(subject),str(selection),tactic,str(output)],runtime_env)
                    assert (verified/"stdout.txt").read_text() == f"elf tactics artifact verified: tactic={tactic} metadata=1 sparse_pages=1 images={contract['images']} qualification_complete=false\n"
                    assert not (verified/"stderr.txt").read_bytes()
                    candidates.append(output)
            save("candidate-files-before-"+tactic+".json",authenticated)
            controls = execute("controls-"+tactic,[str(artifacts/"check_elf_tactic_refusals"),str(original),
                               str(subject_dir/"unstripped-null.selection"),tactic],runtime_env)
            assert (controls/"stdout.txt").read_text() == expected_controls(tactic)
            assert not (controls/"stderr.txt").read_bytes()
            # Freeze an independently derived complete filename inventory before
            # the first tracee; generated images may occupy one or two pages.
            capture_files,trace_directories = capture_inventory(tactic,originals,candidates)
            expected_inventory = "elf-exec-tactics-captures-v1\n"+"".join(name+"\n" for name in sorted(capture_files))
            with (raw/("expected-captures-"+tactic+".tsv")).open("x") as stream:
                stream.write(expected_inventory)
            captures = raw/("captures-"+tactic)
            native = execute("native-"+tactic,[str(driver),"run-tactics",tactic,str(original),str(stripped),*map(str,candidates),str(captures)],runtime_env)
            original_count = 4*len(contract["heads"])
            rewritten_count = 2*original_count
            assert (native/"stdout.txt").read_text() == (
                f"PASS kernel-exec {tactic}: {original_count} original + {rewritten_count} rewritten traces; "
                f"{contract['comparisons']} full-state comparisons; {3*original_count} subject CALL/RETs; 8 hook CALL/RETs; 4 journal rows\n")
            assert not (native/"stderr.txt").read_bytes()
            completion = (f"status\tpassed\ntactic\t{tactic}\noriginal_traces\t{original_count}\nrewritten_traces\t{rewritten_count}\n"
                f"full_state_comparisons\t{contract['comparisons']}\nsubject_call_ret_witnesses\t{3*original_count}\n"
                "hook_call_return_witnesses\t8\nrecording_hook_rows\t4\nmanual_load_mappings\t0\npost_seed_state_repairs\t0\n"
                f"capture_files\t{len(capture_files)}\n")
            assert (captures/"complete.tsv").read_text() == completion
            assert (captures/"capture-inventory.tsv").read_text() == expected_inventory
            copies = [("original-unstripped",original),("original-stripped",stripped)]
            copies += [("candidate-"+str(i),path/"candidate.elf") for i,path in enumerate(candidates)]
            for name,source in copies:
                copy = captures/name
                assert copy.read_bytes() == source.read_bytes()
                assert stat.S_IMODE(copy.stat().st_mode) == 0o500
                ordinary = execute("ordinary-"+tactic+"-"+name,[str(copy)],runtime_env)
                assert (ordinary/"stdout.txt").read_text() == "elf tactics ok\n"
                assert not (ordinary/"stderr.txt").read_bytes()
                assert copy.read_bytes() == source.read_bytes()
            after = {}
            for name,output in zip(authenticated,candidates):
                _,strip_state,hook = name.split("-")
                after[name] = authenticate(output,originals[strip_state],subject_dir/(strip_state+"-"+hook+".selection"),contract["images"])
            assert after == authenticated
            save("candidate-files-after-"+tactic+".json",after)
            captures_list = list(captures.rglob("*"))
            assert all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in captures_list)
            assert {str(p.relative_to(captures)) for p in captures_list if p.is_dir()} == trace_directories
            assert {str(p.relative_to(captures)) for p in captures_list if p.is_file()} == capture_files
            save("capture-files-"+tactic+".json",{str(p.relative_to(captures)):digest(p) for p in sorted(captures_list) if p.is_file()})
            assert before == {name:digest(path) for name,path in originals.items()}
            summaries[tactic] = {"original_traces":original_count,"rewritten_traces":rewritten_count,
                "comparisons":contract["comparisons"],"capture_files":len(capture_files),"ordinary_processes":6,
                "qualification_complete":False}
        assert [row["name"] for row in results] == stage_names
        assert sum(row["comparisons"] for row in summaries.values()) == 676
        save("summary.json",summaries)
    finally:
        save("results.json",results)
        save("source-after.json",{"revision":git("rev-parse","HEAD").decode().strip(),
             "files":{name:digest(repo/name) for name in sources}})
        save("b1-prerequisite-inputs-after.json",{name:digest(name) for name in prerequisite})
    assert all(digest(path) == checksum for path,checksum in prerequisite.items())
    assert all(record["sha256"] == digest(artifacts/name) for name,record in new_binaries.items())
    assert git("rev-parse","HEAD").decode().strip() == revision
    assert not git("diff","HEAD","--")
    assert all(digest(repo/name) == value for name,value in sources.items())


if __name__ == "__main__":
    main()
