"""Fabricated format controls only; no perf, PMU, capture or attribution evidence."""
import sys

if sys.flags.optimize:
    raise SystemExit("assertions required")

import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("_reader_under_test", HERE / "perf_data.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing local reader")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


def u32(n):
    return struct.pack("<I", n)


def u64(n):
    return struct.pack("<Q", n)


def record(kind, body=b"", misc=0):
    return struct.pack("<IHH", kind, misc, 8 + len(body)) + body


def string(value, alignment=8, extra=0):
    n = ((len(value) + 1 + extra + alignment - 1) // alignment) * alignment
    return value + bytes(n - len(value))


def text(value):
    value = string(value, 64)
    return u32(len(value)) + value


ARGV = [b"/fixture/perf", b"record", b"-e", b"instructions:uDS", b"--", b"/fixture/app", b""]


def attr(*, width=144, sample=0x10197, read=23, flags=None, config=1):
    if flags is None:
        flags = sum(1 << i for i in (0, 1, 2, 5, 6, 8, 9, 11, 12, 13, 18, 23, 24, 29, 30))
    return struct.pack("<IIQQQQQ", 0, width, config, 4096, sample, read, flags) + bytes(width - 48)


def suffix(*, sample=0x10197, pid=101, tid=101, time=100, event_id=7, stream_id=90, cpu=3):
    result = struct.pack("<IIQ", pid, tid, time)
    if sample & 64:
        result += u64(event_id)
    if sample & 512:
        result += u64(stream_id)
    return result + struct.pack("<IIQ", cpu, 0, event_id)


def sample(*, fields=0x10197, read=23, value=9000, enabled=20, running=20, lost=0, period=4096):
    body = struct.pack("<QQIIQ", 7, 0x401004, 101, 101, 80)
    if fields & 64:
        body += u64(7)
    if fields & 512:
        body += u64(90)
    body += struct.pack("<IIQQQQQ", 3, 0, period, value, enabled, running, 7)
    if read & 16:
        body += u64(lost)
    return record(9, body, 2)


def final_read(*, read=23, enabled=22, running=22):
    body = struct.pack("<IIQQQQ", 101, 101, 12345, enabled, running, 7)
    if read & 16:
        body += u64(0)
    return record(8, body + suffix(time=102))


def default_features(a):
    # Regular table writer: zero type, SIZE, filename allocation aligned to 8.
    # This byte grammar supplies no independent image identity.
    bid = record(0, u32(101) + bytes(range(20)) + bytes((20, 0, 0, 0)) + string(b"/fixture/app", 8), 0x8002)
    command = u32(len(ARGV)) + b"".join(text(x) for x in ARGV)
    desc = u32(1) + u32(len(a)) + a + u32(1) + text(b"instructions:uDS") + u64(7)
    return {2: bid, 11: command, 12: desc}


def file(records=None, *, a=None, features=None, gap=0):
    a = attr() if a is None else a
    records = [sample(), record(4, struct.pack("<IIIIQ", 101, 100, 101, 100, 101) + suffix(time=101)),
               final_read(), record(68), record(82)] if records is None else records
    features = default_features(a) if features is None else features
    ids = u64(7)
    at = 104 + len(ids)
    table = a + u64(104) + u64(len(ids))
    body = b"".join(records)
    data_at = at + len(table)
    ordered = sorted(features.items())
    directory_end = data_at + len(body) + 16 * len(ordered)
    pos = directory_end + gap
    directory, payload = b"", b""
    for key, value in ordered:
        directory += u64(pos) + u64(len(value))
        payload += value
        pos += len(value)
    bits = sum(1 << key for key, _ in ordered)
    header = b"PERFILE2" + struct.pack("<8Q", 104, len(a) + 16, at, len(table), data_at, len(body), 0, 0)
    return header + bits.to_bytes(32, "little") + ids + table + body + directory + bytes(gap) + payload


def set_value(data, offset, value, width=8):
    return data[:offset] + value.to_bytes(width, "little") + data[offset + width:]


class PerfDataTests(unittest.TestCase):
    def refused(self, data, code=None, *, argv=ARGV):
        out = P.decode(data, argv)
        self.assertIn(out["summary"]["status"], ("REFUSED", "UNSUPPORTED"))
        self.assertIsNotNone(out["summary"]["error"])
        if code:
            self.assertEqual(out["error"]["code"], code)
        return out

    def test_complete_file_conservation_and_read_after_exit(self):
        data = file(gap=32)
        out = P.decode(data, ARGV)
        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertTrue(out["summary"]["file_conserved"])
        self.assertEqual(out["summary"]["record_count"], 5)
        self.assertIs(out["source_bytes"], data)
        self.assertEqual(out["summary"]["record_bytes"], sum(x["size"] for x in out["records"]))
        self.assertEqual(out["header"]["directory_zero_gap"], 32)
        self.assertEqual([x["type"] for x in out["records"]], [9, 4, 8, 68, 82])
        self.assertEqual(out["records"][2]["read"], {"value": 12345, "enabled": 22, "running": 22, "id": 7, "lost": 0})
        self.assertIn("build_id_external_image_join_unresolved", out["unresolved"])
        self.assertNotIn("/fixture", json.dumps(out["summary"]))
        self.assertEqual(out["summary"]["decoded_sample_period_sum"], 4096)

    def test_sample_read_field_order_and_optional_ids(self):
        for fields in (0x10197, 0x101d7, 0x10397, 0x103d7):
            for read in (7, 23):
                with self.subTest(fields=fields, read=read):
                    out = P.decode(file([sample(fields=fields, read=read)], a=attr(sample=fields, read=read)), ARGV)
                    self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
                    row = out["records"][0]
                    self.assertEqual((row["identifier"], row["ip"], row["pid"], row["tid"], row["time"], row["cpu"], row["period"]),
                                     (7, 0x401004, 101, 101, 80, 3, 4096))
                    self.assertEqual(row["read"]["value"], 9000)
                    self.assertEqual("lost" in row["read"], bool(read & 16))
                    self.assertEqual(row.get("id", 7), 7)
                    self.assertEqual(row.get("stream_id", 90), 90)
        for at, value, width, error in ((8, 8, 8, "unknown_sample_id"), (44, 1, 4, "nonzero_reserved_or_padding"),
                                        (80, 8, 8, "unknown_read_id"), (72, 21, 8, "running_exceeds_enabled")):
            self.refused(file([set_value(sample(), at, value, width)]), error)
        self.refused(file([sample() + bytes(8)]), "record_frame_size")

    def test_lifecycle_payload_and_trailer_identities_remain_distinct(self):
        fork = record(7, struct.pack("<IIIIQ", 101, 100, 101, 100, 70) + suffix(pid=100, tid=100, time=69))
        synthetic = record(7, struct.pack("<IIIIQ", 101, 100, 102, 101, 0) + bytes(32), 0x2000)
        comm = record(3, struct.pack("<II", 101, 101) + string(b"app") + suffix(), 0x2000)
        out = P.decode(file([fork, synthetic, comm]), ARGV)
        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual((out["records"][0]["pid"], out["records"][0]["trailer"]["pid"]), (101, 100))
        self.assertEqual(out["records"][1]["trailer"]["identity_kind"], "zero_trailer_no_live_identity")
        self.assertEqual(out["records"][2]["comm"], b"app")
        self.refused(file([set_value(fork, len(fork) - 8, 8)]), "unknown_event_id")
        self.refused(file([record(3, struct.pack("<II", 101, 101) + b"abcdefgh" + suffix())]), "unterminated_string")

    def test_mappings_use_byte_offsets_and_exact_strings(self):
        base = struct.pack("<IIQQQ", 101, 101, 0x400000, 0x1000, 4096)
        mmap = record(1, base + string(b"/image") + suffix(), 2)
        mmap2 = record(10, base + struct.pack("<IIQQII", 8, 1, 999, 0, 5, 2) + string(b"/image") + bytes(32), 2)
        out = P.decode(file([mmap, mmap2]), ARGV)
        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual(out["records"][0]["pgoff"], 4096)
        self.assertEqual(out["records"][1]["inode"], 999)
        self.refused(file([set_value(mmap, 16, (1 << 64) - 1)]), "mapping_overflow")
        self.refused(file([set_value(mmap2, 4, 0x4002, 2)]), "mmap_build_id_outside_command_profile")
        self.refused(file([set_value(mmap, 47, 1, 1)]), "string_padding")

    def test_loss_throttle_zero_and_maximum_values_are_not_filtered(self):
        lost = record(2, u64(7) + u64(3) + suffix())
        lost_samples = record(13, u64(4) + suffix(pid=0xffffffff, tid=0xffffffff))
        throttle = record(5, u64(100) + u64(7) + u64(90) + suffix())
        out = P.decode(file([sample(value=(1 << 64) - 1, enabled=0, running=0, lost=2, period=0), lost, lost_samples, throttle]), ARGV)
        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual(len(out["records"]), 4)
        self.assertEqual(out["records"][0]["read"]["value"], (1 << 64) - 1)
        self.assertEqual(set(out["adverse"]), {"sample_read_lost_nonzero", "zero_sample_period", "lost_records_nonzero", "lost_samples_nonzero", "throttle_observation"})
        self.assertIn("lost_samples_task_scope_unresolved", out["unresolved"])
        self.refused(file([final_read(enabled=1, running=2)]), "running_exceeds_enabled")
        lower = P.decode(file([sample(enabled=2, running=1), final_read(enabled=3, running=2)]), ARGV)
        self.assertEqual(lower["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual(set(lower["adverse"]), {"sample_read_enabled_running_unequal", "read_enabled_running_unequal"})

    def test_unknown_records_and_extensions_retain_inventory_and_prefix(self):
        for kind in (22, 64, 70, 75, 80, 81, 0xffffffff):
            with self.subTest(kind=kind):
                out = self.refused(file([sample(), record(kind), final_read()]), "unsupported_record_type")
                self.assertEqual(out["summary"]["status"], "UNSUPPORTED")
                self.assertTrue(out["summary"]["record_walk_complete"])
                self.assertEqual(len(out["inventory"]), 3)
                self.assertEqual(len(out["records"]), 1)
                self.assertEqual(out["error"]["offset"], out["inventory"][1]["offset"])
                self.assertEqual(out["summary"]["decoded_sample_period_sum"], 4096)
        self.refused(file([set_value(record(82), 4, 1, 2)]), "synthetic_misc_extension")

    def test_file_envelope_sections_and_record_caps(self):
        data = file()
        for offset, value, width, error in ((8, 16, 8, "file_header_layout"), (16, 81, 8, "attr_stride"),
                                          (24, 103, 8, "attr_table_bounds"), (56, 1, 8, "event_types_section"),
                                          (48, 0, 8, "data_bounds_or_empty")):
            self.refused(set_value(data, offset, value, width), error)
        self.refused(b"2ELIFREP" + data[8:], "magic_or_endianness")
        self.refused(data[:-1], "feature_bounds")
        self.refused(data + b"x", "unreferenced_file_tail")
        self.refused(bytes(16 * 1024 * 1024 + 1), "file_size_cap_or_short_header")
        at_cap = P.decode(file([record(68)] * 100000), ARGV)
        self.assertEqual(at_cap["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual(at_cap["summary"]["record_count"], 100000)
        self.assertIn("no_samples_observed", at_cap["unresolved"])
        self.refused(file([record(68)] * 100001), "record_count_cap")
        self.refused(file([b"\0" * 7]), "truncated_field")
        self.refused(file([struct.pack("<IHH", 68, 0, 7)]), "record_frame_size")

    def test_attribute_profile_preserves_flags_and_pmu_identity(self):
        a = attr()
        for at, value, width, error in ((0, 1, 4, "not_hardware_instructions"), (4, 128, 4, "attr_declared_size"),
                                      (8, 2, 8, "not_hardware_instructions"), (16, 4097, 8, "sample_period"),
                                      (24, 0x1019f, 8, "sample_fields"), (32, 31, 8, "read_format"),
                                      (56, 1, 8, "nonzero_reserved_or_padding")):
            self.refused(file(a=set_value(a, at, value, width)), error)
        flags = int.from_bytes(a[40:48], "little")
        for bit in (0, 1, 2, 5, 6, 8, 9, 11, 12, 13, 18):
            self.refused(file(a=attr(flags=flags & ~(1 << bit))), "attr_flags")
        for bit in (3, 4, 7, 10, 15, 16, 17, 19, 21, 22, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38, 39, 63):
            self.refused(file(a=attr(flags=flags | (1 << bit))), "attr_flags")
        for width in (64, 72, 80, 96, 104, 112, 120, 128, 136, 144):
            out = P.decode(file(a=attr(width=width, config=(9 << 32) | 1)), ARGV)
            self.assertEqual(out["attrs"][0]["config"], (9 << 32) | 1)
            self.assertIn("explicit_pmu_type_unjoined", out["unresolved"])

    def test_raw_dynamic_encodings_retain_all_config_words_without_meaning(self):
        for kind in (4, 6, 17, 0xffffffff):
            for width in (64, 72, 80, 96, 104, 112, 120, 128, 136, 144):
                for config in (0, (0x12345678 << 32) | 1, (1 << 64) - 1):
                    with self.subTest(kind=kind, width=width, config=config):
                        a = set_value(attr(width=width, config=config), 0, kind, 4)
                        words = {"config1": (56, (1 << 64) - 1), "config2": (64, 0xabc),
                                 "config3": (128, 0x123456789abcdef0), "config4": (136, 0xfedcba9876543210)}
                        for offset, value in words.values():
                            if width >= offset + 8:
                                a = set_value(a, offset, value)
                        features = default_features(a)
                        features[16] = u32(2) + u32(kind) + text(b"cpu") + u32(0x12345678) + text(b"not_authority")
                        out = P.decode(file(a=a, features=features), ARGV)
                        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
                        observed = out["attrs"][0]
                        self.assertEqual((observed["type"], observed["config"], observed["raw_bytes"]), (kind, config, a))
                        for name, (offset, value) in words.items():
                            self.assertEqual(observed[name], value if width >= offset + 8 else None)
                        self.assertEqual((observed["pmu_type"], observed["pmu_name"]), (kind, b"cpu"))
                        self.assertEqual(observed["pmu_mapping_authority"], "descriptive_only")
                        self.assertEqual(out["summary"]["event_encoding"], "raw_pmu" if kind == 4 else "dynamic_pmu")
                        self.assertEqual(out["summary"]["event_meaning_authority"], "unresolved")
                        self.assertIn("event_encoding_authority_unresolved", out["unresolved"])
                        self.assertEqual(out["summary"]["record_count"], 5)
                        self.assertTrue(out["summary"]["file_conserved"])
        generic = P.decode(file(), ARGV)
        self.assertEqual(generic["summary"]["event_encoding"], "generic_hardware_instructions")
        self.assertEqual(generic["summary"]["event_meaning_authority"], "uapi_encoding_only")
        for offset in (56, 64, 128, 136):
            self.refused(file(a=set_value(attr(), offset, 1)), "nonzero_reserved_or_padding")

    def test_raw_dynamic_encodings_preserve_all_other_profile_refusals(self):
        for kind in (4, 17):
            a = set_value(attr(config=(1 << 64) - 1), 0, kind, 4)
            flags = int.from_bytes(a[40:48], "little")
            for bit in (0, 1, 2, 5, 6, 8, 9, 11, 12, 13, 18):
                self.refused(file(a=set_value(a, 40, flags & ~(1 << bit))), "attr_flags")
            for bit in (3, 4, 7, 10, 15, 16, 17, 19, 21, 22, 25, 26, 27, 28, 31, 32, 33, 34, 35, 36, 37, 38, 39, 63):
                self.refused(file(a=set_value(a, 40, flags | (1 << bit))), "attr_flags")
            for offset in (*range(52, 56), *range(72, 128)):
                self.refused(file(a=set_value(a, offset, 1, 1)), "nonzero_reserved_or_padding")
            for offset, value, width, code in ((4, 128, 4, "attr_declared_size"),
                                               (16, 4097, 8, "sample_period"),
                                               (24, 0x1019f, 8, "sample_fields"),
                                               (32, 31, 8, "read_format")):
                self.refused(file(a=set_value(a, offset, value, width)), code)
            features = default_features(a)
            self.refused(file(a=a, features={**features, 12: set_value(features[12], 8 + 56, 1)}),
                         "event_desc_attr_mismatch")
            self.refused(file(a=a, features={**features, 12: features[12].replace(b"instructions:uDS", b"instructions:uDX")}),
                         "event_desc_name")
        for kind in (1, 2, 3, 5):
            self.refused(file(a=set_value(attr(), 0, kind, 4)), "not_hardware_instructions")

    def test_feature_identity_joins_missing_authority_and_padding(self):
        a = attr()
        features = default_features(a)
        desc = features[12]
        # attr identity, event name and IDs are independently joined.
        for changed in (set_value(desc, 8 + 16, 4097), desc.replace(b"instructions:uDS", b"instructions:uDX"), set_value(desc, len(desc) - 8, 8)):
            self.refused(file(features={**features, 12: changed}))
        self.refused(file(), "cmdline_authority_mismatch", argv=ARGV[:-1])
        out = P.decode(file(), None)
        self.assertIn("command_authority_not_supplied", out["unresolved"])
        out = P.decode(file(features={}), ARGV)
        self.assertTrue(out["summary"]["file_conserved"])
        for name in ("cmdline", "event_desc", "build_id"):
            self.assertIn("required_" + name + "_feature_absent", out["unresolved"])
        for feature in (0, 35, 255):
            self.refused(file(features={**features, feature: b""}), "unknown_feature_id")
        self.refused(file(features={**features, 23: u64(0)}), "unsupported_feature_semantics")
        data = file(gap=16)
        end = int.from_bytes(data[40:48], "little") + int.from_bytes(data[48:56], "little")
        self.refused(set_value(data, end + 48, 1, 1), "feature_directory_gap")
        self.refused(set_value(data, end + 16, int.from_bytes(data[end:end + 8], "little")), "feature_overlap_or_gap")
        self.refused(set_value(data, 104, 0), "duplicate_or_zero_attr_id")
        self.refused(set_value(data, 112 + 144, 105), "id_array_layout")

    def test_build_id_bounded_prefix_never_claims_external_identity(self):
        a = attr()
        features = default_features(a)
        bid = features[2]
        for value in (0, 21, 255):
            self.refused(file(features={**features, 2: set_value(bid, 32, value, 1)}), "build_id_size_or_reserved")
        self.refused(file(features={**features, 2: set_value(bid, 33, 1, 1)}), "build_id_size_or_reserved")
        self.refused(file(features={**features, 2: set_value(bid, 6, 0, 2)}), "build_id_record_header")
        out = P.decode(file(), ARGV)
        build = next(x for x in out["features"] if x["id"] == 2)
        self.assertEqual(build["entries"][0]["build_id"], bytes(range(20)).hex())
        self.assertEqual(build["encoding"], "canonical_regular_build_id")
        self.assertIn("build_id_external_image_join_unresolved", out["unresolved"])

    def test_synthetic_maps_updates_and_time_conversion_exact_layouts(self):
        index = record(69, u64(1) + struct.pack("<4Q", 7, 0, (1 << 64) - 1, 101))
        threads = record(73, u64(1) + u64(101) + b"abcdefghijklmnop")
        cpus = [record(74, struct.pack("<HHHH", 0, 2, 3, 65535)),
                record(74, struct.pack("<HHHI", 1, 1, 4, 0x18) + bytes(6)),
                record(74, struct.pack("<HHH", 1, 1, 8) + bytes(4) + u64(0x18) + bytes(6)),
                record(74, struct.pack("<HBBHH", 2, 0, 0, 3, 6))]
        unit = record(78, u64(0) + u64(7) + string(b"instructions", extra=16))
        scale = record(78, u64(1) + u64(7) + struct.pack("<d", 1.0) + bytes(16))
        clock = record(79, struct.pack("<5QBB6x", 10, 100, 0, 5, (1 << 64) - 1, 1, 0))
        out = P.decode(file([index, threads, *cpus, unit, scale, clock]), ARGV)
        self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
        self.assertEqual(out["records"][1]["entries"][0]["comm"], b"abcdefghijklmnop")
        self.assertEqual(out["records"][-1]["shift"], 10)
        self.refused(file([set_value(index, 8, 2)]), "id_index_count_or_extension")
        self.refused(file([record(69, index[8:] + u64(1) + u64(0))]), "id_index_nonhost_extension")
        self.refused(file([set_value(cpus[0], 14, 3, 2)]), "duplicate_cpu")
        self.refused(file([set_value(clock, 8, 64)]), "time_conv_parameters")
        self.refused(file([set_value(clock, 48, 0, 1)]), "time_conv_capability")
        self.refused(file([record(79, clock[8:32])]), "time_conv_layout")
        self.refused(file([set_value(scale, 24, 0x4000000000000000)]), "nonunit_event_scale")
        self.refused(file([record(78, u64(1) + u64(7) + struct.pack("<d", 1.0))]), "truncated_field")

    def test_throttle_and_unthrottle_join_optional_stream_identity(self):
        for kind in (5, 6):
            for fields in (0x10197, 0x101d7, 0x10397, 0x103d7):
                for stream in (0, 90, (1 << 64) - 1):
                    raw = record(kind, u64(100) + u64(7) + u64(stream) + suffix(sample=fields, stream_id=stream))
                    out = P.decode(file([raw], a=attr(sample=fields)), ARGV)
                    self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
                    self.assertEqual(out["records"][0]["stream_id"], stream)
                    self.assertEqual(out["adverse"], ["throttle_observation"])
                    if fields & 512:
                        self.assertEqual(out["records"][0]["trailer"]["stream_id"], stream)
                        for changed in (set_value(raw, 24, stream ^ 1),
                                        set_value(raw, len(raw) - 24, stream ^ 1)):
                            refused = self.refused(file([changed, sample(fields=fields)], a=attr(sample=fields)),
                                                   "throttle_stream_id_mismatch")
                            self.assertEqual(refused["error"]["offset"], refused["inventory"][0]["offset"] + 24)
                            self.assertEqual(len(refused["inventory"]), 2)
                            self.assertEqual(refused["records"], [])

    def test_empty_feature_directory_tail_is_bounded_and_unresolved(self):
        for gap in (0, 16, 4096):
            data = file(features={}, gap=gap)
            out = P.decode(data, ARGV)
            self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
            self.assertTrue(out["summary"]["file_conserved"])
            self.assertEqual(out["header"]["directory_zero_gap"], gap)
            self.assertEqual(out["features"], [])
            self.assertEqual(len(out["records"]), 5)
            for name in ("build_id", "cmdline", "event_desc"):
                self.assertIn("required_" + name + "_feature_absent", out["unresolved"])
        for gap in (1, 15, 17, 4097, 4112):
            self.refused(file(features={}, gap=gap), "feature_directory_gap")
        for byte in (1, 255):
            data = file(features={}, gap=16)
            self.refused(data[:-1] + bytes((byte,)), "feature_directory_gap")

    def test_regular_build_id_writer_forms_and_exact_filename_allocation(self):
        a = attr()
        features = default_features(a)
        for misc in (0x8001, 0x8002, 0x8004, 0x8005):
            for length in (1, 19, 20):
                identifier = bytes(range(1, length + 1))
                union = identifier + bytes(20 - length) + bytes((length, 0, 0, 0))
                for name in (b"", b"1234567", b"12345678", b"/fixture/app", b"x" * 4087):
                    bid = record(0, u32(0xffffffff) + union + string(name, 8), misc)
                    out = P.decode(file(a=a, features={**features, 2: bid}), ARGV)
                    self.assertEqual(out["summary"]["status"], "DECODED_UNQUALIFIED")
                    build = next(x for x in out["features"] if x["id"] == 2)
                    row = build["entries"][0]
                    self.assertEqual((row["size"], row["misc"], row["pid"]), (len(bid), misc, 0xffffffff))
                    self.assertEqual((row["build_id"], row["filename"]), (identifier.hex(), name))
                    self.assertEqual(row["padding_size"], (-(len(name) + 1)) % 8)
                    self.assertEqual(build["encoding"], "canonical_regular_build_id")
                    self.assertIn("build_id_external_image_join_unresolved", out["unresolved"])
        out = P.decode(file(features={**features, 2: features[2] + features[2]}), ARGV)
        self.assertEqual(len(next(x for x in out["features"] if x["id"] == 2)["entries"]), 2)

    def test_regular_build_id_wrong_forms_padding_and_trailing_bytes_refuse(self):
        a = attr()
        features = default_features(a)
        bid = features[2]
        for kind in (1, 67, 0xffffffff):
            self.refused(file(features={**features, 2: set_value(bid, 0, kind, 4)}), "build_id_record_header")
        # The old v1-v3 fabricated positive was the wrong regular-file form.
        old_fixture = record(67, u32(101) + bytes(range(20)) + bytes((20, 0, 0, 0)) + string(b"/fixture/app", 64), 0x8002)
        self.refused(file(features={**features, 2: old_fixture}), "build_id_record_header")
        for misc in (0, 1, 2, 4, 5, 0x8000, 0x8003, 0x8006, 0x8007, 0x9002, 0xffff):
            self.refused(file(features={**features, 2: set_value(bid, 4, misc, 2)}), "build_id_record_header")
        for index in (33, 34, 35):
            self.refused(file(features={**features, 2: set_value(bid, index, 1, 1)}), "build_id_size_or_reserved")
        # A short declared ID requires the unused memset bytes to remain zero.
        self.refused(file(features={**features, 2: set_value(bid, 32, 1, 1)}), "build_id_unused_bytes")
        self.refused(file(features={**features, 2: set_value(bid, len(bid) - 1, 1, 1)}), "string_padding")
        for tail in (b"abcdefgh", b"/fixture/app" + bytes(52)):
            self.refused(file(features={**features, 2: record(0, bid[8:36] + tail, 0x8002)}))
        # No extra aligned zero allocation after the first NUL, and no unaligned allocation.
        extra = set_value(bid + bytes(8), 6, len(bid) + 8, 2)
        self.refused(file(features={**features, 2: extra}), "string_padding")
        short = set_value(bid[:-1], 6, len(bid) - 1, 2)
        self.refused(file(features={**features, 2: short}), "build_id_record_header")
        self.refused(file(features={**features, 2: bid[:-4]}), "truncated_field")
        over = record(0, bid[8:36] + string(b"x" * 4088, 8), 0x8002)
        self.refused(file(features={**features, 2: over}), "build_id_record_header")
        for tail in (b"x", bytes(8), bytes(44)):
            self.refused(file(features={**features, 2: bid + tail}))

    def test_api_types_and_local_import_optimization_refusal(self):
        for value in (None, "PERFILE2", bytearray(file())):
            self.refused(value, "bytes_required")
        for argv in ([], ["not raw"], [b"embedded\0nul"], True):
            self.refused(file(), "raw_cmdline_authority_required", argv=argv)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "perf_records.py").write_text("raise RuntimeError('path hijack')\n")
            for name in ("perf_data.py", "perf_records.py", "test_perf_data.py"):
                for invocation in ([sys.executable, "-O", str(HERE / name)],
                                   [sys.executable, "-O", "-c", "import runpy,sys;runpy.run_path(sys.argv[1])", str(HERE / name)]):
                    run = subprocess.run(invocation, cwd=root, capture_output=True, timeout=5, check=False)
                    self.assertEqual((run.returncode, run.stdout, run.stderr), (1, b"", b"assertions required\n"))
            code = ("import importlib.util,sys;"
                    "s=importlib.util.spec_from_file_location('x',sys.argv[1]);"
                    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                    "print(m.R.__file__)")
            run = subprocess.run([sys.executable, "-B", "-c", code, str(HERE / "perf_data.py")],
                                 cwd=root, capture_output=True, timeout=5, check=False)
            self.assertEqual((run.returncode, run.stderr), (0, b""))
            self.assertEqual(run.stdout, (str(HERE / "perf_records.py") + "\n").encode())


if __name__ == "__main__":
    unittest.main()
