"""Closed-profile, bounded regular-file perf reader; never a qualification gate.

decode(bytes, expected_cmdline=None) returns a compact JSON-safe summary and
private in-memory fields. expected_cmdline is the externally authenticated list
of raw argv bytes stored by perf, including its executable. decode performs no
input-file or process IO; module import loads sibling source by resolved path.
Private fields can contain filenames/argv; publish only summary, which has none.
"""
import sys

if sys.flags.optimize:
    raise SystemExit("assertions required")

import importlib.util
from pathlib import Path

_path = Path(__file__).resolve().with_name("perf_records.py")
_spec = importlib.util.spec_from_file_location("_closed_perf_records", _path)
if _spec is None or _spec.loader is None:
    raise RuntimeError("missing local record module")
R = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(R)

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000
ATTR_SIZES = (64, 72, 80, 96, 104, 112, 120, 128, 136, 144)
OPAQUE_FEATURES = {3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 20, 22, 25, 26, 28, 30, 31, 32, 33, 34}
FLAG_NAMES = (
    "disabled", "inherit", "pinned", "exclusive", "exclude_user", "exclude_kernel", "exclude_hv",
    "exclude_idle", "mmap", "comm", "freq", "inherit_stat", "enable_on_exec", "task", "watermark",
    "precise_ip_low", "precise_ip_high", "mmap_data", "sample_id_all", "exclude_host", "exclude_guest",
    "exclude_callchain_kernel", "exclude_callchain_user", "mmap2", "comm_exec", "use_clockid",
    "context_switch", "write_backward", "namespaces", "ksymbol", "bpf_event", "aux_output", "cgroup",
    "text_poke", "build_id", "inherit_thread", "remove_on_exec", "sigtrap", "defer_callchain", "defer_output",
)
REQUIRED_FLAGS = {0, 1, 2, 5, 6, 8, 9, 11, 12, 13, 18}
# Sideband/capability defaults and wakeup policy are explicit alternatives,
# never silently masked away. Records declaring unsupported sideband still refuse.
OPTIONAL_FLAGS = {14, 20, 23, 24, 29, 30}


def padded_string(c):
    at = c.base + c.pos
    n = c.u(4)
    R.require(n > 0 and n % 64 == 0, "feature_string_length", at)
    part = R.Cursor(c.take(n), at + 4)
    return R.string_tail(part, alignment=64)


def frame(data, out):
    c = R.Cursor(data)
    R.require(c.take(8) == b"PERFILE2", "magic_or_endianness", 0, unsupported=True)
    size, stride = c.u(), c.u()
    R.require(size == 104, "file_header_layout", 8, unsupported=True)
    attr_at, attr_len, data_at, data_len = c.u(), c.u(), c.u(), c.u()
    R.require(c.u() == 0 and c.u() == 0, "event_types_section", 56, unsupported=True)
    bits = c.u(32)
    R.require(stride - 16 in ATTR_SIZES, "attr_stride", 16, unsupported=True)
    R.require(attr_len > 0 and attr_len % stride == 0, "attr_table_length", 32)
    R.require(attr_len == stride, "single_event_profile", 32, unsupported=True)
    R.require(104 <= attr_at <= len(data) and attr_len <= len(data) - attr_at,
              "attr_table_bounds", 24)
    R.require(data_at == attr_at + attr_len and 0 < data_len <= len(data) - data_at,
              "data_bounds_or_empty", 40)
    out["header"] = {"size": size, "attr_stride": stride, "attrs_offset": attr_at,
                     "attrs_size": attr_len, "data_offset": data_at, "data_size": data_len,
                     "feature_bits": bits}
    expected_id_at = 104
    raw_attrs = []
    seen = set()
    for at in range(attr_at, data_at, stride):
        a = R.Cursor(data[at:at + stride], at)
        raw = a.take(stride - 16)
        ids_at, ids_len = a.u(), a.u()
        R.require(ids_at == expected_id_at and ids_len > 0 and ids_len % 8 == 0
                  and ids_len <= attr_at - ids_at, "id_array_layout", at + stride - 16)
        ids = [int.from_bytes(data[p:p + 8], "little") for p in range(ids_at, ids_at + ids_len, 8)]
        R.require(all(i > 0 and i not in seen for i in ids) and len(set(ids)) == len(ids),
                  "duplicate_or_zero_attr_id", ids_at)
        seen.update(ids)
        raw_attrs.append((at, raw, ids))
        expected_id_at += ids_len
    R.require(expected_id_at == attr_at, "unreferenced_id_bytes", expected_id_at)
    # Frame every data record before semantic decoding; never resynchronize.
    end = data_at + data_len
    pos = data_at
    while pos < end:
        R.require(len(out["inventory"]) < MAX_RECORDS, "record_count_cap", pos)
        r = R.Cursor(data[pos:min(pos + 8, end)], pos)
        kind, misc, n = r.u(4), r.u(2), r.u(2)
        R.require(8 <= n <= min(65535, end - pos), "record_frame_size", pos + 6)
        out["inventory"].append({"offset": pos, "type": kind, "misc": misc, "size": n,
                                 "sha256": R.digest(data[pos:pos + n])})
        pos += n
    out["walk_complete"] = True
    feature_ids = [i for i in range(256) if bits & (1 << i)]
    directory_end = end + 16 * len(feature_ids)
    R.require(directory_end <= len(data), "feature_directory_bounds", end)
    sections = []
    for index, feature in enumerate(feature_ids):
        d = R.Cursor(data[end + 16 * index:end + 16 * (index + 1)], end + 16 * index)
        at, n = d.u(), d.u()
        R.require(directory_end <= at <= len(data) and n <= len(data) - at,
                  "feature_bounds", d.base)
        sections.append((feature, at, n))
    # When every feature write failed, the original calloc directory can
    # remain as an aligned zero tail even though no feature bits survive.
    payload_at = sections[0][1] if sections else len(data)
    gap = payload_at - directory_end
    R.require(gap % 16 == 0 and gap <= 16 * (256 - len(feature_ids))
              and not any(data[directory_end:payload_at]), "feature_directory_gap", directory_end)
    cursor = payload_at
    for feature, at, n in sections:
        R.require(at == cursor, "feature_overlap_or_gap", at)
        cursor += n
        out["features"].append({"id": feature, "offset": at, "size": n,
                                "sha256": R.digest(data[at:at + n])})
    R.require(cursor == len(data), "unreferenced_file_tail", cursor)
    out["header"]["directory_zero_gap"] = gap
    out["file_conserved"] = True
    R.require(not bits & 1 and bits >> 35 == 0, "unknown_feature_id", 72, unsupported=True)
    R.require(len(raw_attrs) == 1, "single_event_profile", attr_at, unsupported=True)
    return raw_attrs[0]


def attribute(raw, at, ids, unresolved):
    c = R.Cursor(raw, at)
    kind, n, config, period, sample, read, flags = c.u(4), c.u(4), c.u(), c.u(), c.u(), c.u(), c.u()
    R.require(n == len(raw), "attr_declared_size", at + 4)
    if kind == 0:
        R.require(config & 0xffffffff == 1, "not_hardware_instructions", at, unsupported=True)
        encoding, meaning, pmu_type = "generic_hardware_instructions", "uapi_encoding_only", config >> 32
    elif kind == 4 or kind >= 6:
        # Direct-PMU config bits are opaque: their high half is not a PMU ID.
        # Dynamic type IDs do not establish CPU class or instruction semantics.
        encoding = "raw_pmu" if kind == 4 else "dynamic_pmu"
        meaning, pmu_type = "unresolved", kind
        unresolved.append("event_encoding_authority_unresolved")
        if kind >= 6:
            unresolved.append("dynamic_pmu_class_unresolved")
    else:
        raise R.Refusal("not_hardware_instructions", at, unsupported=True)
    R.require(period == 4096, "sample_period", at + 16)
    R.require(sample & R.SAMPLE_REQUIRED == R.SAMPLE_REQUIRED and not sample & ~(R.SAMPLE_REQUIRED | R.SAMPLE_OPTIONAL),
              "sample_fields", at + 24, unsupported=True)
    R.require(read in (7, 23), "read_format", at + 32, unsupported=True)
    required = sum(1 << i for i in REQUIRED_FLAGS)
    allowed = required | sum(1 << i for i in OPTIONAL_FLAGS)
    R.require(flags & required == required and not flags & ~allowed, "attr_flags", at + 40, unsupported=True)
    wakeup = c.u(4)
    c.zero(4)  # bp_type; type 5 and pointer-bearing probe semantics stay unsupported.
    configs = {}
    for name, offset in (("config1", 56), ("config2", 64), ("config3", 128), ("config4", 136)):
        if len(raw) >= offset + 8:
            # No callchain, registers, stack, AUX, clock or reserved extension.
            c.zero(offset - c.pos)
            value = c.u()
            if kind == 0:
                R.require(value == 0, "nonzero_reserved_or_padding", at + offset)
            configs[name] = value
        else:
            configs[name] = None  # Absent old-prefix field, not an observed zero.
    c.zero(len(raw) - c.pos)
    if not read & 16:
        unresolved.append("read_lost_accounting_absent")
    if not flags & (1 << 24):
        unresolved.append("comm_exec_tracking_absent")
    return {"type": kind, "size": n, "config": config, **configs, "raw_bytes": raw,
            "event_encoding": encoding, "event_meaning_authority": meaning, "pmu_type": pmu_type,
            "period": period, "sample_type": sample, "read_format": read, "flags_raw": flags,
            "flags": {name: bool(flags & (1 << i)) for i, name in enumerate(FLAG_NAMES)},
            "wakeup": wakeup, "ids": ids, "raw_sha256": R.digest(raw)}


def build_ids(c):
    entries = []
    while c.pos < len(c.data):
        at = c.base + c.pos
        header = c.take(8)
        kind, misc, n = int.from_bytes(header[:4], "little"), int.from_bytes(header[4:6], "little"), int.from_bytes(header[6:], "little")
        # Regular-file write_buildid zeroes type, sets SIZE, and aligns only
        # the filename allocation to 8; synthetic/pipe type 67 is another form.
        R.require(kind == 0 and misc in (0x8001, 0x8002, 0x8004, 0x8005)
                  and 37 <= n <= 36 + 4095 and (n - 36) % 8 == 0,
                  "build_id_record_header", at)
        b = R.Cursor(c.take(n - 8), at + 8)
        pid, union = b.u(4), b.take(24)
        length = union[20]
        R.require(1 <= length <= 20 and not any(union[21:]), "build_id_size_or_reserved", at + 32)
        R.require(not any(union[length:20]), "build_id_unused_bytes", at + 12 + length)
        allocated = len(b.data) - b.pos
        filename = R.string_tail(b, alignment=8)
        entries.append({"offset": at, "size": n, "misc": misc, "pid": pid,
                        "build_id": union[:length].hex(), "filename": filename,
                        "padding_size": allocated - len(filename) - 1})
    return entries


def features(data, out, raw, attr, expected_cmdline):
    known_ids = set(attr["ids"])
    have = set()
    pmus = {}
    for entry in out["features"]:
        feature, at, n = entry["id"], entry["offset"], entry["size"]
        have.add(feature)
        c = R.Cursor(data[at:at + n], at)
        if feature == 12:
            count, width = c.u(4), c.u(4)
            R.require(count == 1 and width == len(raw), "event_desc_count_or_width", at)
            R.require(c.take(width) == raw, "event_desc_attr_mismatch", at + 8)
            ids_n = c.u(4)
            name = padded_string(c)
            R.require(name == b"instructions:uDS", "event_desc_name", at)
            R.require(ids_n <= (len(c.data) - c.pos) // 8, "event_desc_id_bounds", c.base + c.pos)
            ids = [c.u() for _ in range(ids_n)]
            R.require(ids == attr["ids"], "event_desc_ids", at)
            entry.update(encoding="event_desc", name=name, ids=ids)
        elif feature == 11:
            count = c.u(4)
            R.require(count > 0 and count <= (len(c.data) - c.pos) // 68, "cmdline_count", at)
            argv = [padded_string(c) for _ in range(count)]
            if expected_cmdline is None:
                out["unresolved"].append("command_authority_not_supplied")
            else:
                R.require(argv == expected_cmdline, "cmdline_authority_mismatch", at)
            entry.update(encoding="cmdline", argv=argv)
        elif feature == 2:
            entry.update(encoding="canonical_regular_build_id", entries=build_ids(c))
            out["unresolved"].append("build_id_external_image_join_unresolved")
        elif feature == 16:
            count = c.u(4)
            R.require(count <= (len(c.data) - c.pos) // 72, "pmu_mapping_count", at)
            for _ in range(count):
                pmu = c.u(4)
                name = padded_string(c)
                R.require(pmu not in pmus and name, "pmu_mapping_identity", c.base + c.pos)
                pmus[pmu] = name
            entry.update(encoding="pmu_mapping", mappings=pmus.copy())
        elif feature == 17:
            R.require(c.u(4) == 0, "group_description_outside_profile", at, unsupported=True)
            entry["encoding"] = "empty_group_description"
        elif feature == 21:
            entry.update(encoding="sample_time_metadata", first=c.u(), last=c.u())
        elif feature in OPAQUE_FEATURES:
            entry["encoding"] = "opaque_descriptive_no_semantic_authority"
            c.take(n)
        else:
            raise R.Refusal("unsupported_feature_semantics", at, unsupported=True)
        c.done()
    for feature, label in ((2, "build_id"), (11, "cmdline"), (12, "event_desc")):
        if feature not in have:
            out["unresolved"].append("required_" + label + "_feature_absent")
    if attr["pmu_type"]:
        if attr["pmu_type"] not in pmus:
            out["unresolved"].append("explicit_pmu_type_unjoined")
        else:
            attr["pmu_name"] = pmus[attr["pmu_type"]]
            attr["pmu_mapping_authority"] = "descriptive_only"
    return known_ids


def _decode_file(data, expected_cmdline, record_decoder):
    """No IO, no APP attribution and no final accounting or success verdict.

    Invalid API arguments refuse normally. Unsupported semantics retain the
    complete framing inventory when framing succeeded and the decoded prefix.
    """
    out = {"source_bytes": data if type(data) is bytes and len(data) <= MAX_BYTES else None,
           "header": None, "attrs": [], "features": [], "inventory": [], "records": [],
           "unresolved": ["app_attribution_and_terminal_accounting_not_attempted"], "adverse": [],
           "walk_complete": False, "file_conserved": False, "error": None}
    status = "DECODED_UNQUALIFIED"
    try:
        R.require(type(data) is bytes, "bytes_required", 0)
        R.require(104 <= len(data) <= MAX_BYTES, "file_size_cap_or_short_header", 0)
        R.require(expected_cmdline is None or
                  (type(expected_cmdline) is list and len(expected_cmdline) > 0 and
                   all(type(a) is bytes and b"\0" not in a for a in expected_cmdline)),
                  "raw_cmdline_authority_required", 0)
        at, raw, ids = frame(data, out)
        attr = attribute(raw, at, ids, out["unresolved"])
        out["attrs"].append(attr)
        ids = features(data, out, raw, attr, expected_cmdline)
        for entry in out["inventory"]:
            at, n = entry["offset"], entry["size"]
            record, adverse, unresolved = record_decoder(data[at:at + n], at, attr, ids)
            out["records"].append(record)
            out["adverse"].extend(adverse)
            out["unresolved"].extend(unresolved)
    except R.Refusal as error:
        status = "UNSUPPORTED" if error.unsupported else "REFUSED"
        out["error"] = {"code": error.code, "offset": error.offset}
    counts = {}
    for entry in out["inventory"]:
        key = str(entry["type"])
        counts[key] = counts.get(key, 0) + 1
    period_sum = sum(r["period"] for r in out["records"] if r["type"] == 9)
    if status == "DECODED_UNQUALIFIED" and not any(r["type"] == 9 for r in out["records"]):
        out["unresolved"].append("no_samples_observed")
    out["unresolved"] = sorted(set(out["unresolved"]))
    out["adverse"] = sorted(set(out["adverse"]))
    out["summary"] = {
        "status": status, "file_bytes": len(data) if type(data) is bytes else None,
        "file_sha256": R.digest(data) if type(data) is bytes and len(data) <= MAX_BYTES else None,
        "file_conserved": out["file_conserved"], "record_walk_complete": out["walk_complete"],
        "semantic_decode_complete": status == "DECODED_UNQUALIFIED",
        "event_encoding": out["attrs"][0]["event_encoding"] if out["attrs"] else None,
        "event_meaning_authority": out["attrs"][0]["event_meaning_authority"] if out["attrs"] else "not_established",
        "record_count": len(out["inventory"]), "decoded_record_count": len(out["records"]),
        "record_bytes": sum(r["size"] for r in out["inventory"]), "type_counts": counts,
        "decoded_sample_period_sum": period_sum, "period_sum_scope": "decoded prefix only; no attribution",
        "feature_ids": [f["id"] for f in out["features"]], "error": out["error"],
        "adverse": out["adverse"], "unresolved": out["unresolved"],
        "authority": "syntax only; no APP, loss completeness, terminal, mapping, or accuracy qualification",
    }
    return out


def decode(data, expected_cmdline=None):
    """Strict host-user profile; status, predicates and output are unchanged."""
    return _decode_file(data, expected_cmdline, R.decode_record)


def decode_context_diagnostic(data, expected_cmdline=None):
    """Separate host-context syntax diagnostic, never function attribution.

    Private records retain raw context and IP, including zero/nonzero kernel
    IPs. Context does not certify counted execution privilege or function cost.
    On refusal only the fully decoded prefix has numeric period totals; missing
    records are not zero mass. No capture or terminal-counter verdict is made.
    """
    out = _decode_file(data, expected_cmdline, R.decode_record_context_diagnostic)
    summary = out["summary"]
    contexts = {name: {"records": 0, "period_sum": 0} for name in ("host_user", "host_kernel")}
    decoded = 0
    for record in out["records"]:
        if record["type"] == 9:
            assert record["attribution"] == "UNATTRIBUTED"
            bucket = contexts[record["sample_context"]]
            bucket["records"] += 1
            bucket["period_sum"] += record["period"]
            decoded += 1
    total = summary["decoded_sample_period_sum"]
    assert sum(bucket["records"] for bucket in contexts.values()) == decoded
    assert sum(bucket["period_sum"] for bucket in contexts.values()) == total
    complete = summary["semantic_decode_complete"] and out["walk_complete"] and out["file_conserved"]
    if complete:
        summary["status"] = "CONTEXT_DIAGNOSTIC_UNQUALIFIED"
    summary.update(
        profile="host-user-kernel-context-v1", sample_contexts=contexts,
        framed_sample_count=sum(row["type"] == 9 for row in out["inventory"]),
        decoded_sample_count=decoded, file_sample_period_sum=total if complete else None,
        attribution="NOT_ATTEMPTED", period_assignment="UNATTRIBUTED",
        unattributed_period_sum=total,
        period_sum_scope=("all decoded SAMPLE records in this file; no attribution" if complete else
                          "partial decoded SAMPLE prefix only; undecoded mass unresolved"),
        context_authority="sample context only; not counted privilege or function cost")
    return out
