"""Closed finite-consumer observations; no process or native authority."""

import json
import re
import struct

from parsing import InvalidEvidence
from run import require, sha

LIMITS = {"epochs": 256, "source_fact_bytes": 64 * 1024 * 1024, "reports": 4096,
          "origins": 4096, "witnesses": 4096, "plan_history": 4096}
METRICS = {"charged_source_bytes", "retained_source_bytes", "retained_origins",
           "history_records", "generation_changes"}
FLAGS = {"identity_chain_exact", "cleanup_complete", "writer_cleaned",
         "archive_preserved", "artifact_unchanged"}
COUNTS = {"provider_calls", "full_state_checks", "journal_attempts", "journal_raw_waits",
          "journal_state_copies", "journal_failures"}
ERRORS = frozenset("""arguments artifact_path artifact_open artifact_metadata artifact_read
artifact_length artifact_changed runtime_launch runtime_return returned_event
missing_provider_input completion_binding full_syscall_state returned_state
archive_inventory archive_prefix runtime_terminal provider_count terminal_event
terminal_archive initial_identity initial_state initial_archive metrics_read
metric_bounds metric_regression physical_cleanup cleanup_archive caught_panic
journal_state journal_slots journal_wait journal_stop_identity journal_validated
journal_syscall_info journal_input journal_original journal_unused_state
journal_extra_wait journal_terminal_wait journal_held_wait journal_maps_summary
journal_copy_binding journal_entry_state journal_sequence journal_entry_stop
journal_return_state journal_bridge_stop journal_commit journal_terminal_input
journal_pre_exit journal_terminal_commit journal_fact_chain journal_chain""".split())
FIELDS = {"schema_version", "experiment", "status", "error", "returned_syscalls",
          "terminal_syscall", "terminal_code", "journal_fact_counts", "observed_metrics",
          "limits", "invocation_seconds", "cleanup_seconds"} | FLAGS | COUNTS
PROTOCOL = {"protocol": "liteinst-runtime-kernel-consumer", "version": 1}
MAX_ARTIFACT = 1024 * 1024
MAX_SUMMARY = 65536
MAX_CAPTURE = 8 * 1024 * 1024


def strict_json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "consumer_duplicate_json_field")
            result[key] = value
        return result

    def constant(_value):
        raise InvalidEvidence("consumer_nonfinite_json")

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError) as error:
        raise InvalidEvidence("consumer_invalid_json") from error


def natural(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def validate_summary(value, complete=False):
    require(type(value) is dict and set(value) == FIELDS, "consumer_summary_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["experiment"] == "runtime-kernel-consumer", "consumer_summary_identity")
    require(value["status"] in ("passed", "failed")
            and (value["error"] is None if value["status"] == "passed"
                 else type(value["error"]) is str and value["error"] in ERRORS),
            "consumer_summary_status")
    require(all(type(value[key]) is bool for key in FLAGS), "consumer_summary_flag")
    require(all(natural(value[key], {"provider_calls": 3, "full_state_checks": 2,
                "journal_attempts": 3, "journal_raw_waits": 27,
                "journal_state_copies": 24, "journal_failures": 3}[key]) for key in COUNTS),
            "consumer_summary_count")
    require(type(value["returned_syscalls"]) is list
            and all(type(n) is int for n in value["returned_syscalls"])
            and value["returned_syscalls"] in ([], [39], [39, 186])
            and value["full_state_checks"] == len(value["returned_syscalls"]),
            "consumer_return_order")
    require((value["terminal_syscall"] is None and value["terminal_code"] is None)
            or (type(value["terminal_syscall"]) is int and value["terminal_syscall"] == 231
                and type(value["terminal_code"]) is int and value["terminal_code"] == 7
                and value["returned_syscalls"] == [39, 186]), "consumer_terminal_kind")
    require(type(value["limits"]) is dict and value["limits"] == LIMITS
            and all(type(n) is int for n in value["limits"].values())
            and type(value["invocation_seconds"]) is int and value["invocation_seconds"] == 3
            and type(value["cleanup_seconds"]) is int and value["cleanup_seconds"] == 3,
            "consumer_limits_changed")
    attempts = value["journal_attempts"]
    facts = value["journal_fact_counts"]
    require(type(facts) is list and len(facts) == attempts
            and all(natural(n, 32) for n in facts)
            and value["journal_raw_waits"] <= attempts * 9
            and value["journal_state_copies"] <= attempts * 8
            and value["journal_failures"] <= attempts, "consumer_archive_shape")
    metrics = value["observed_metrics"]
    require(type(metrics) is list and len(metrics) <= 3, "consumer_metrics_shape")
    previous = None
    for row in metrics:
        require(type(row) is dict and set(row) == METRICS
                and all(natural(n, 2**63 - 1) for n in row.values())
                and row["retained_source_bytes"] <= row["charged_source_bytes"] <= LIMITS["source_fact_bytes"]
                and row["retained_origins"] <= LIMITS["origins"]
                and row["generation_changes"] == 0, "consumer_metrics_bounds")
        if previous is not None:
            require(all(row[key] >= previous[key] for key in METRICS), "consumer_metrics_refund")
        previous = row
    if complete or value["status"] == "passed":
        require(value["status"] == "passed" and value["provider_calls"] == 3
                and value["returned_syscalls"] == [39, 186] and value["terminal_syscall"] == 231
                and value["terminal_code"] == 7 and value["full_state_checks"] == 2
                and attempts == 3 and value["journal_raw_waits"] == 24
                and value["journal_state_copies"] == 15 and facts == [25, 25, 20]
                and value["journal_failures"] == 0 and len(metrics) == 3
                and all(value[key] for key in FLAGS), "consumer_incomplete_success")
    return value


def parse_summary(data, command_succeeded):
    require(type(command_succeeded) is bool and type(data) is bytes
            and len(data) <= (MAX_SUMMARY if command_succeeded else MAX_CAPTURE),
            "consumer_summary_size")
    # Failed-command diagnostics may precede the one typed row. They remain
    # private; no prose is copied into the public observation.
    lines = data.splitlines()
    candidates = [line for line in lines if line.startswith(b'{"schema_version":')]
    require(len(candidates) == 1, "consumer_summary_missing_or_duplicate")
    require(len(candidates[0]) <= MAX_SUMMARY, "consumer_summary_size")
    if command_succeeded:
        require(lines == candidates, "consumer_unclassified_output")
    value = validate_summary(strict_json(candidates[0]), command_succeeded)
    return {"summary": value, "command_succeeded": command_succeeded,
            "qualified_run": False}


def parse_protocol(data):
    require(type(data) is bytes and len(data) <= 1024, "consumer_protocol_size")
    value = strict_json(data)
    require(type(value) is dict and value == PROTOCOL and type(value["version"]) is int,
            "consumer_protocol_differs")
    return value


def elf_metadata(data):
    """Describe this finite static ET_EXEC artifact; no head or release proof."""
    require(type(data) is bytes and 64 <= len(data) <= MAX_ARTIFACT, "consumer_elf_size")
    require(data[:7] == b"\x7fELF\x02\x01\x01" and data[7] in (0, 3)
            and data[8:16] == bytes(8), "consumer_elf_ident")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, names = fields
    require((kind, machine, version, flags, ehsize, phsize, shsize) == (2, 62, 1, 0, 64, 56, 64)
            and 1 <= phnum <= 64 and 1 <= shnum <= 1024 and names < shnum,
            "consumer_elf_header")

    def span(offset, size):
        require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
                "consumer_elf_file_range")
        return data[offset:offset + size]

    span(phoff, phsize * phnum)
    span(shoff, shsize * shnum)
    segments, loads, stacks = [], [], []
    for index in range(phnum):
        ptype, permissions, offset, address, physical, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize)
        require(ptype not in (2, 3), "consumer_dynamic_elf")
        span(offset, filesz)
        require(memsz <= 2**64 - 1 - address, "consumer_elf_address_overflow")
        row = {"type": ptype, "flags": permissions, "offset": offset, "vaddr": address,
               "paddr": physical, "filesz": filesz, "memsz": memsz, "align": align}
        segments.append(row)
        if ptype == 1:
            require(filesz <= memsz and memsz > 0 and permissions in (4, 5, 6)
                    and align >= 4096 and align & (align - 1) == 0
                    and address % align == offset % align, "consumer_load_geometry")
            loads.append(row)
        if ptype == 0x6474e551:
            stacks.append(row)
    require(loads and len(stacks) == 1 and stacks[0]["flags"] == 6,
            "consumer_stack_policy")
    ordered = sorted(loads, key=lambda row: row["vaddr"])
    require(all(a["vaddr"] + a["memsz"] <= b["vaddr"] for a, b in zip(ordered, ordered[1:])),
            "consumer_load_overlap")
    executable = [row for row in loads if row["flags"] == 5]
    require(len([row for row in executable if row["vaddr"] <= entry < row["vaddr"] + row["filesz"]]) == 1,
            "consumer_entry_range")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize) for i in range(shnum)]
    symbols = []
    for row in sections:
        _name, stype, _flags, _address, offset, size, link, _info, _align, entsize = row
        if stype != 8:
            span(offset, size)
        require(not (stype in (4, 9, 11) and size), "consumer_load_relocation")
        if stype == 2:
            require(entsize == 24 and size % 24 == 0 and link < shnum
                    and sections[link][1] == 3, "consumer_symbol_table")
            strings = span(sections[link][4], sections[link][5])
            for at in range(offset, offset + size, 24):
                name, info, other, section, value, extent = struct.unpack_from("<IBBHQQ", data, at)
                require(name < len(strings) and b"\0" in strings[name:], "consumer_symbol_name")
                label = strings[name:strings.index(b"\0", name)]
                require(not label or section != 0, "consumer_undefined_symbol")
                if label == b"_start":
                    require(info & 15 == 2 and other == 0 and 0 < section < shnum
                            and value == entry, "consumer_start_symbol")
                    symbols.append((value, extent))
    require(len(symbols) == 1, "consumer_start_symbol")
    return {"sha256": sha(data), "bytes": len(data), "entry": entry,
            "program_headers": segments, "section_count": shnum,
            "executable_segments": len(executable),
            "executable_bytes_sha256": sha(b"".join(span(row["offset"], row["filesz"]) for row in executable)),
            "static_native64": True, "head_completeness": False}


def version_metadata(role, data):
    require(role in ("clang", "ld.lld") and type(data) is bytes and len(data) <= 65536,
            "consumer_version_shape")
    try:
        first = data.decode("utf-8").splitlines()[0]
    except (UnicodeError, IndexError) as error:
        raise InvalidEvidence("consumer_version_shape") from error
    pattern = r"(?:.* )?clang version (\d+\.\d+(?:\.\d+){0,2})(?: |$)" if role == "clang" else r"LLD (\d+\.\d+(?:\.\d+){0,2})(?: |$)"
    match = re.match(pattern, first)
    require(match is not None, "consumer_version_shape")
    return {"version": match[1], "version_output_sha256": sha(data)}
