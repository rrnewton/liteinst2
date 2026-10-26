"""Source, prerequisite and resource witnesses for the separate cost recorder."""

import contextlib
import copy
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import run
from parsing import InvalidEvidence


ROOT = run.ROOT
HERE = run.HERE
MAX_METADATA = 16384
HEX = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
LOG_LIMIT = 8 * 1024 * 1024
PUBLIC_ENV = dict(run.ENV, CARGO_TARGET_DIR="target", TMPDIR="private_run/tmp",
                  LANG="C.UTF-8", LC_ALL="C.UTF-8", RLIMIT_CORE=0)
PRIOR_TOOL_FIELDS = {
    "cargo": {"version", "launcher_sha256"},
    "rustc": {"version", "launcher_sha256"},
    "git": {"argv0", "version", "executable_sha256"},
    "python": {"version", "executable_sha256", "launcher_sha256"},
}


def require(value, code):
    if not value:
        raise InvalidEvidence(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise InvalidEvidence("nonfinite_json_number")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def metadata_git(*args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    return subprocess.check_output(
        [run.GIT, "--no-replace-objects", "-C", str(ROOT), "--work-tree=" + str(ROOT),
         "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "-c", "maintenance.autoDetach=false", "-c", "gc.autoDetach=false", *args],
        cwd=ROOT, env=env, stderr=subprocess.DEVNULL, timeout=10)


@contextlib.contextmanager
def bounded_git():
    # This serial recorder has no concurrent callers of run's helpers.
    original = run.git
    try:
        run.git = metadata_git
        yield
    finally:
        run.git = original


def tree_sources(revision):
    require(type(revision) is str and REVISION.fullmatch(revision), "invalid_source_revision")
    result = {}
    for entry in metadata_git("ls-tree", "-rz", revision).split(b"\0"):
        if not entry:
            continue
        descriptor, name = entry.split(b"\t", 1)
        mode, kind, blob = descriptor.decode().split()
        name = name.decode()
        if name.startswith("evaluation/admission/results/"):
            continue
        require(not name.startswith("/") and ".." not in Path(name).parts,
                "invalid_source_path")
        require(kind == "blob" and mode in ("100644", "100755", "120000"),
                "unsupported_source_mode")
        result[name] = {"mode": mode, "blob": blob}
    return result


def source_identity(expected_revision):
    with bounded_git():
        state = run.source_state()
        run.preflight(state, expected_revision,
                      metadata_git("ls-files", "--others", "--exclude-standard").decode().splitlines())
    require(state.get("head_sources_match") is True, "head_source_content_differs")
    state["source_git"] = tree_sources(state["revision"])
    require(set(state["source_git"]) == set(state["source_sha256"]), "source_inventory_differs")
    return state


def bounded_text(path, limit=MAX_METADATA, filesystem=None):
    with Path(path).open("rb") as stream:
        if filesystem is not None:
            # Linux x86_64 statfs fits in this initialized oversized buffer.
            info = ctypes.create_string_buffer(256)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
            libc.fstatfs.restype = ctypes.c_int
            require(libc.fstatfs(stream.fileno(), info) == 0, "metadata_filesystem_query_failed")
            actual = ctypes.c_long.from_buffer(info).value
            require(actual == filesystem, "metadata_filesystem_differs")
        data = stream.read(limit + 1)
    require(len(data) <= limit and b"\0" not in data, "metadata_limit_or_nul")
    return data.decode("ascii")


def cpu_list(text):
    require(type(text) is str and re.fullmatch(r"[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*", text),
            "invalid_cpu_list")
    values = set()
    for item in text.split(","):
        ends = item.split("-")
        low, high = int(ends[0]), int(ends[-1])
        require(0 <= low <= high <= 1048575 and high - low < 4096, "cpu_list_bound")
        current = set(range(low, high + 1))
        require(not values.intersection(current), "duplicate_cpu_list_member")
        values.update(current)
        require(len(values) <= 4096, "cpu_list_bound")
    return sorted(values)


def optional_atom(path):
    try:
        value = bounded_text(path).strip()
    except FileNotFoundError:
        return {"status": "interface_absent", "value": None}
    except PermissionError:
        return {"status": "unreadable", "value": None}
    require(re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", value), "invalid_optional_metadata")
    return {"status": "observed", "value": value}


def placement():
    """Observe the actual allocator-selected CPUs; never choose or widen them."""
    affinity = sorted(os.sched_getaffinity(0))
    require(len(affinity) == 2, "hook_cost_requires_two_logical_cpus")
    group_text = bounded_text("/proc/self/cgroup", filesystem=0x9FA0)
    require(group_text.endswith("\n"), "invalid_cgroup_record")
    lines = group_text.splitlines()
    require(len(lines) == 1 and lines[0].startswith("0::/"), "cgroup_v2_required")
    relative = lines[0][4:]
    require(".." not in Path(relative).parts and not Path(relative).is_absolute(),
            "invalid_cgroup_record")
    directory = Path("/sys/fs/cgroup") / relative
    effective = cpu_list(bounded_text(directory / "cpuset.cpus.effective",
                                     filesystem=0x63677270).strip())
    require(effective == affinity, "hard_cpuset_differs_from_affinity")
    topology = []
    for cpu in affinity:
        base = Path("/sys/devices/system/cpu") / f"cpu{cpu}"
        values = []
        for name in ("physical_package_id", "core_id"):
            text = bounded_text(base / "topology" / name, filesystem=0x62656572).strip()
            require(re.fullmatch(r"[0-9]{1,8}", text), "invalid_cpu_topology")
            values.append(int(text))
        siblings = cpu_list(bounded_text(base / "topology/thread_siblings_list",
                                        filesystem=0x62656572).strip())
        require(cpu in siblings, "cpu_missing_from_own_siblings")
        topology.append({"cpu": cpu, "package": values[0], "core": values[1],
                         "thread_siblings": siblings,
                         "governor": optional_atom(base / "cpufreq/scaling_governor")})
    require(len({(row["package"], row["core"]) for row in topology}) == 2,
            "hook_cost_requires_two_distinct_physical_cores")
    return {"affinity": affinity, "effective_cpuset": effective, "topology": topology,
            "hard_cpuset": "cgroup_v2_effective", "reserved_logical_cpus": 2,
            "selected_physical_cores": 2, "physical_core_exclusivity_claimed": False}


def atom_observation(value):
    require(type(value) is dict and set(value) == {"status", "value"}, "invalid_optional_observation")
    require(value["status"] in ("observed", "interface_absent", "unreadable"), "invalid_optional_status")
    if value["status"] == "observed":
        require(type(value["value"]) is str and re.fullmatch(r"[A-Za-z0-9_.+-]{1,80}", value["value"]),
                "invalid_optional_atom")
    else:
        require(value["value"] is None, "unexpected_optional_value")
    return copy.deepcopy(value)


def public_placement(value, cpus):
    require(type(cpus) is list and len(cpus) == 2
            and all(type(cpu) is int and 0 <= cpu <= 1048575 for cpu in cpus)
            and cpus == sorted(set(cpus)), "invalid_placement_cpu_list")
    keys = {"affinity", "effective_cpuset", "topology", "hard_cpuset", "reserved_logical_cpus",
            "selected_physical_cores", "physical_core_exclusivity_claimed"}
    require(type(value) is dict and set(value) == keys, "invalid_inner_placement")
    require(all(type(value[k]) is list and all(type(n) is int for n in value[k])
                for k in ("affinity", "effective_cpuset")), "invalid_inner_cpu_types")
    require(value["affinity"] == cpus and value["effective_cpuset"] == cpus
            and value["hard_cpuset"] == "cgroup_v2_effective"
            and type(value["reserved_logical_cpus"]) is int and value["reserved_logical_cpus"] == 2
            and type(value["selected_physical_cores"]) is int and value["selected_physical_cores"] == 2
            and value["physical_core_exclusivity_claimed"] is False, "invalid_inner_placement")
    require(type(value["topology"]) is list and len(value["topology"]) == 2, "invalid_inner_topology")
    for row, cpu in zip(value["topology"], cpus):
        require(type(row) is dict and set(row) == {"cpu", "package", "core", "thread_siblings", "governor"},
                "invalid_inner_topology")
        require(type(row["cpu"]) is int and row["cpu"] == cpu
                and all(type(row[k]) is int and 0 <= row[k] < 100000000 for k in ("package", "core")),
                "invalid_inner_topology")
        siblings = row["thread_siblings"]
        require(type(siblings) is list and 0 < len(siblings) <= 4096
                and all(type(n) is int and 0 <= n <= 1048575 for n in siblings)
                and siblings == sorted(set(siblings)) and cpu in siblings, "invalid_inner_siblings")
        atom_observation(row["governor"])
    require(len({(r["package"], r["core"]) for r in value["topology"]}) == 2, "inner_cpus_share_core")
    return copy.deepcopy(value)


def clock_metadata():
    info = time.get_clock_info("monotonic")
    require(info.monotonic and not info.adjustable, "monotonic_clock_required")
    require(math.isfinite(info.resolution) and info.resolution > 0, "invalid_clock_resolution")
    require(re.fullmatch(r"[A-Za-z0-9_(). ]{1,100}", info.implementation), "invalid_clock_metadata")
    return {"implementation": info.implementation, "resolution_seconds": info.resolution,
            "monotonic": True, "adjustable": False,
            "clocksource": optional_atom("/sys/devices/system/clocksource/clocksource0/current_clocksource"),
            "calibration_subtracted": False}


def executable_identity(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "executable_missing_or_symlink")
    mode = path.stat().st_mode
    require(mode & 0o111, "executable_not_executable")
    data = path.read_bytes()
    return {"sha256": sha(data), "bytes": len(data), "mode": "100755"}


def toolchain(env):
    result = {}
    for name in ("cargo", "rustc"):
        located = shutil.which(name, path=env["PATH"])
        require(located is not None, "toolchain_launcher_missing")
        result[name] = {"version": run.tool_version(name, env),
                        "launcher_sha256": sha(Path(located).read_bytes())}
    sysroot = subprocess.check_output(["rustc", "--print", "sysroot"], cwd=ROOT, env=env,
                                     stderr=subprocess.DEVNULL, timeout=10).decode().strip()
    require(Path(sysroot).is_absolute() and "\n" not in sysroot and "\0" not in sysroot,
            "invalid_toolchain_sysroot")
    for name in ("cargo", "rustc"):
        result[name]["executable_sha256"] = sha((Path(sysroot) / "bin" / name).read_bytes())
    result["git"] = {"argv0": run.GIT, "version": run.tool_version(run.GIT, env),
                     "executable_sha256": sha(Path(run.GIT).read_bytes())}
    result["python"] = {"version": sys.version.split()[0],
                        "executable_sha256": sha(Path(sys.executable).read_bytes()),
                        "launcher_sha256": sha(Path(shutil.which("python3", path=env["PATH"])).read_bytes())}
    return result


def hardware_relation(reference, observed, scoped_placement=None):
    """Bind count observations to placement without rewriting hardware facts."""
    require(type(reference) is dict and type(observed) is dict, "hardware_observation_missing")
    fields = ("affinity_cpu_count", "logical_cpus_visible")
    for hardware in (reference, observed):
        for key in fields:
            require(type(hardware.get(key)) is int and hardware[key] > 0,
                    "hardware_count_missing_or_invalid")
    require({k: v for k, v in reference.items() if k not in fields}
            == {k: v for k, v in observed.items() if k not in fields}, "correctness_hardware_differs")
    before = {key: reference[key] for key in fields}
    after = {key: observed[key] for key in fields}
    if scoped_placement is None:
        require(before == after, "unscoped_hardware_counts_differ")
        return {"mode": "unscoped_exact", "reference_counts": before, "observed_counts": after,
                "logical_count_relation": "unchanged", "placement_cpu_count": None}
    # This parser validates the proof's closed shape and exact topology. Its
    # native observations come from placement(); outer promotion additionally
    # binds these same CPU IDs to the allocator's actual assignment.
    require(type(scoped_placement) is dict, "invalid_inner_placement")
    placed = public_placement(scoped_placement, scoped_placement.get("affinity"))
    count = len(placed["affinity"])
    require(all(reference[key] >= count for key in fields), "hardware_count_scope_expands")
    require(observed["affinity_cpu_count"] == count, "hardware_affinity_placement_differs")
    require(observed["logical_cpus_visible"] in (reference["logical_cpus_visible"], count),
            "hardware_visible_count_not_bound")
    relation = ("unchanged" if observed["logical_cpus_visible"] == reference["logical_cpus_visible"]
                else "equals_hard_placement")
    return {"mode": "scoped_exact_placement", "reference_counts": before, "observed_counts": after,
            "logical_count_relation": relation, "placement_cpu_count": count}


def validate_correctness(record, source, corpus, corpus_digest, configuration, hardware, tools,
                         *, scoped_placement=None):
    """Validate a pinned prior receipt; do not reinterpret it as performance."""
    require(type(record) is dict and type(record.get("schema_version")) is int
            and record["schema_version"] == 1
            and record.get("experiment") == "admission-validation", "wrong_correctness_receipt")
    require(record.get("status") == "passed" and record.get("source_unchanged") is True
            and record.get("configuration_unchanged") is True, "correctness_not_qualified")
    before = record.get("source", {})
    require(before.get("tracked_clean") is True and before.get("head_sources_match") is True,
            "correctness_source_not_clean")
    require(before.get("source_sha256") == source["source_sha256"]
            and before.get("source_manifest_sha256") == source["source_manifest_sha256"],
            "correctness_source_content_differs")
    require(record.get("corpus_sha256") == corpus_digest
            and record.get("runner_sha256") == source["source_sha256"].get("evaluation/admission/run.py"),
            "correctness_recorder_differs")
    require(record.get("configuration") == configuration, "correctness_configuration_differs")
    require(record.get("environment") == PUBLIC_ENV, "correctness_environment_differs")
    require(record.get("inherited_location_variables") == list(run.LOCATION_VARIABLES),
            "correctness_location_contract_differs")
    require(type(record.get("log_limit_bytes_per_command")) is int
            and record["log_limit_bytes_per_command"] == LOG_LIMIT,
            "correctness_capture_limit_differs")
    hardware_relation(record.get("hardware"), hardware, scoped_placement)
    prior_tools = record.get("toolchain", {})
    require(type(prior_tools) is dict and set(prior_tools) == set(PRIOR_TOOL_FIELDS),
            "correctness_toolchain_missing")
    for name, fields in PRIOR_TOOL_FIELDS.items():
        observed = prior_tools[name]
        require(type(observed) is dict and set(observed) == fields,
                "correctness_toolchain_fields")
        for key, value in observed.items():
            require(type(value) is str and (HEX.fullmatch(value) if key.endswith("sha256")
                    else re.fullmatch(r"[A-Za-z0-9 /_.()+-]{1,120}", value)),
                    "correctness_toolchain_field_type")
            require(tools[name].get(key) == value, "correctness_toolchain_differs")
    commands = record.get("commands")
    require(type(commands) is list and len(commands) == len(run.COMMANDS), "correctness_command_inventory")
    for command, (name, argv, deadline) in zip(commands, run.COMMANDS):
        require(command.get("id") == name and command.get("argv") == argv
                and command.get("timeout_seconds") == deadline, "correctness_command_changed")
        require(command.get("environment_delta") == (
            {"LITEINST_EVALUATION": "1"} if name == "serial_launch" else {}),
            "correctness_command_environment_differs")
        require(command.get("status") == "passed" and type(command.get("exit_code")) is int
                and command["exit_code"] == 0 and command.get("termination") is None
                and command.get("cleanup_complete") is True
                and type(command.get("reaped_descendants")) is int
                and command["reaped_descendants"] == 0, "correctness_command_not_qualified")
        require(type(command.get("private_log_sha256")) is str
                and HEX.fullmatch(command["private_log_sha256"]), "correctness_capture_digest_missing")
        if name == "recorder_tests":
            require(command.get("tests_passed") == corpus["recorder_tests"]
                    and command.get("recorder_observations") == {
                        "tests_run": corpus["recorder_tests"], "exact_ok_terminal": True},
                    "correctness_recorder_count_differs")
        if name in corpus["harness_test_counts"]:
            require(command.get("evidence_status") == "complete", "correctness_harness_incomplete")
            rows = command.get("harnesses", [])
            expected = corpus["harness_test_counts"][name]
            require(len(rows) == len(expected)
                    and {row.get("id") for row in rows} == set(expected), "correctness_harness_inventory")
            for row in rows:
                spec = expected[row["id"]]
                require(row.get("status") == "complete"
                        and row.get("declared_outer_tests") == spec["tests"]
                        and row.get("expected_tests") == spec["tests"]
                        and row.get("expected_ignored") == spec["ignored"]
                        and row.get("outer") == {"result": "ok", "passed": spec["tests"] - spec["ignored"],
                            "failed": 0, "ignored": spec["ignored"], "measured": 0, "filtered": 0}
                        and row.get("unclassified_summaries") == [], "correctness_harness_differs")
    serial = commands[-1]
    identities = {
        "native_cases": ("test", [row["test"] for row in corpus["native_cases"]]),
        "dynamic_admission_fixtures": ("test", corpus["dynamic_admission_fixtures"]),
        "dynamic_matrix_cases": ("case_id", [row["case_id"] for row in corpus["dynamic_matrix_cases"]]),
        "native_validation_fixtures": ("test", [row["test"] for row in corpus["native_validation_fixtures"]]),
    }
    for field, (key, expected) in identities.items():
        rows = serial.get(field, [])
        require(len(rows) == len(expected) and {row.get(key) for row in rows} == set(expected),
                "correctness_named_inventory_differs")
        require(all(row.get("qualified_run") is True and row.get("command_succeeded") is True
                    and row.get("status") == "complete" and row.get("test_result") == "ok" for row in rows),
                "correctness_named_result_unqualified")
    return before["revision"]


def correctness_prerequisite(path, digest, source, corpus, configuration, hardware, tools,
                            *, scoped_placement=None):
    path = Path(path)
    require(path.parent == HERE / "results" and not path.is_symlink(), "invalid_correctness_receipt_path")
    require(HEX.fullmatch(digest), "invalid_correctness_receipt_digest")
    with path.open("rb") as stream:
        data = stream.read(16 * 1024 * 1024 + 1)
    require(len(data) <= 16 * 1024 * 1024 and sha(data) == digest, "correctness_receipt_digest_differs")
    record = strict_json(data)
    revision = validate_correctness(record, source, corpus, sha((HERE / "corpus.json").read_bytes()),
                                    configuration, hardware, tools, scoped_placement=scoped_placement)
    require(record.get("run_id") == path.stem and re.fullmatch(r"[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-[0-9a-f]{12}", path.stem),
            "correctness_run_identity")
    captures = replay_correctness(record, corpus, ROOT / "target/evaluation/admission" / path.stem)
    require(tree_sources(revision) == source["source_git"], "correctness_source_mode_or_blob_differs")
    metadata_git("merge-base", "--is-ancestor", revision, source["revision"])
    return {"receipt": path.name, "sha256": digest, "revision": revision,
            "policy": "same_source_blobs_modes_and_content_receipt_only_descendant_allowed",
            "qualified_correctness": True, "performance_evidence": False,
            "hardware": copy.deepcopy(record["hardware"]),
            "private_capture_sha256": captures, "evidence_replayed_with_unchanged_correctness_parser": True,
            "prior_actual_compiler_hashes_recorded": False}


def replay_correctness(record, corpus, private):
    """Reauthenticate all six capture bytes, then replay the existing parsers."""
    parsed, captures = [], {}
    for command, (name, _, _) in zip(record["commands"], run.COMMANDS):
        path = private / (name + ".log")
        require(not path.is_symlink(), "correctness_capture_symlink")
        with path.open("rb") as stream:
            data = stream.read(LOG_LIMIT + 1)
        require(len(data) <= LOG_LIMIT and sha(data) == command["private_log_sha256"], "correctness_capture_differs")
        captures[name] = sha(data)
        fresh = {key: copy.deepcopy(command[key]) for key in ("id", "status", "exit_code")}
        run.command_evidence(fresh, data.decode("utf-8", errors="replace"), corpus)
        parsed.append(fresh)
    replay = {"commands": parsed, "source_unchanged": True, "configuration_unchanged": True}
    run.qualify(replay)
    require(replay["status"] == "passed", "correctness_capture_replay_failed")
    for original, fresh in zip(record["commands"], parsed):
        for key, value in fresh.items():
            require(original.get(key) == value, "correctness_replayed_evidence_differs")
    return captures
