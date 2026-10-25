"""Fixed positive and negative byte/ownership puzzles; no processes or mappings."""
import copy
import json
from pathlib import Path
import struct
from bootstrap_validate import Invalid, PAGE
from common import indirect_definition, relocation_writes, structure
from ownership import generated_owner, module_bias, source_owner


def calibrate(here):
    inputs = json.loads((here / "inputs.json").read_text())
    cases = json.loads((here / "cases.json").read_text())["cases"]
    accepted, refused = [], []
    def yes(name, call):
        call()
        accepted.append(name)
    def no(name, call):
        try:
            call()
        except (Invalid, AssertionError, ValueError, KeyError, TypeError, struct.error):
            refused.append(name)
        else:
            raise AssertionError("required refusal accepted: " + name)
    for case in cases:
        original = Path(case["original"]["path"]).read_bytes()
        old = Path(case["historical_original_backend_output"]["path"]).read_bytes()
        yes("original-relocation-" + case["id"], lambda original=original: relocation_writes(original, [(case["pc"] // PAGE * PAGE, PAGE)]))
        yes("old-structure-only-" + case["id"], lambda: structure(case, original, old,
            Path(inputs["old_loader_bin"]["path"]).read_bytes(), Path(inputs["old_loader_elf"]["path"]).read_bytes(),
            inputs["interpreter"], "original"))
    case = cases[0]
    original = Path(case["original"]["path"]).read_bytes()
    row = relocation_writes(original, [(case["pc"] // PAGE * PAGE, PAGE)])[0]
    def changed_record(offset, fmt, value):
        data = bytearray(original)
        struct.pack_into(fmt, data, row["table_file_offset"] + offset, value)
        return bytes(data)
    no("relocation-writes-selected-code", lambda: relocation_writes(changed_record(0, "<Q", case["pc"]), [(case["pc"] // PAGE * PAGE, PAGE)]))
    no("unknown-relocation-width", lambda: relocation_writes(changed_record(8, "<Q", (1 << 32) | 99), []))
    no("wrong-referenced-symbol", lambda: relocation_writes(changed_record(8, "<Q", (2 << 32) | 7), []))
    no("wrong-addend", lambda: relocation_writes(changed_record(16, "<q", 1), []))
    no("eight-byte-write-crosses-owner", lambda: relocation_writes(changed_record(0, "<Q", row["target"] + 7), []))
    no("explicit-generated-dependency-write", lambda: relocation_writes(original, [(row["target"], 8)]))
    dso = Path(cases[2]["original"]["path"]).read_bytes()
    yes("exact-original-indirect-definition", lambda: indirect_definition(dso))
    bad = bytearray(dso); bad[0x1007] = 0x90
    no("changed-indirect-native-body", lambda: indirect_definition(bytes(bad)))
    backing = [0, 42, 123]
    path = "/fixture/module"
    bias = 0x70000000
    headers = [(1, 4, 0, 0, 0, PAGE, PAGE, PAGE), (1, 5, PAGE, PAGE, 0, PAGE, PAGE, PAGE),
               (1, 5, 5 * PAGE, 0x200000, 0, PAGE, PAGE, PAGE)]
    def vma(a, z, perms, off, name=path):
        return dict(lo=bias + a, hi=bias + z, perms=perms, offset=off, major=0, minor=42, inode=123, path=name)
    head = vma(0, PAGE, "r--p", 0)
    source = vma(PAGE, 2 * PAGE, "r-xp", PAGE)
    gap = vma(2 * PAGE, 0x200000, "---p", 2 * PAGE)
    yes("checked-module-bias", lambda: module_bias([head], path, backing, headers))
    assert module_bias([head], path, backing, headers) == bias
    yes("complete-original-source", lambda: source_owner([source], bias + PAGE, PAGE, path, backing))
    yes("unoccupied-generated-page", lambda: generated_owner([], bias + 3 * PAGE, PAGE, path, backing, bias, headers))
    yes("exact-same-module-PROT_NONE-gap", lambda: generated_owner([gap], bias + 3 * PAGE, PAGE, path, backing, bias, headers))
    def change(name, field, value):
        altered = dict(gap); altered[field] = value
        no(name, lambda: generated_owner([altered], bias + 3 * PAGE, PAGE, path, backing, bias, headers))
    change("wrong-module-path", "path", "/other/module")
    change("wrong-mount-device", "minor", 43)
    change("wrong-file-inode", "inode", 124)
    change("readable-reservation", "perms", "r--p")
    change("writable-reservation", "perms", "rw-p")
    change("wrong-file-offset", "offset", 3 * PAGE)
    change("partial-reservation", "hi", bias + 3 * PAGE + PAGE // 2)
    change("reservation-outside-module", "lo", bias - PAGE)
    no("duplicate-reservation-owner", lambda: generated_owner([gap, gap], bias + 3 * PAGE, PAGE, path, backing, bias, headers))
    no("reservation-overlaps-real-LOAD", lambda: generated_owner([gap], bias + 3 * PAGE, PAGE, path, backing, bias,
       headers + [(1, 4, 3 * PAGE, 3 * PAGE, 0, PAGE, PAGE, PAGE)]))
    bad_source = dict(source); bad_source["offset"] = 2 * PAGE
    no("wrong-original-source-offset", lambda: source_owner([bad_source], bias + PAGE, PAGE, path, backing))
    no("ambiguous-module-bias", lambda: module_bias([head, head], path, backing, headers))
    assert len(accepted) == 17 and len(refused) == 19
    assert len(set(accepted)) == 17 and len(set(refused)) == 19
    return dict(accepted=accepted, refused=refused, acceptances=17, refusals=19,
                application_executions=0, mappings=0, old_artifacts_are_structural_controls_only=True)
