"""Finite common-program admission; authenticates file bytes, never runs code.

The historical ABI parser and common-input profile are unchanged dependencies.
The caller's source-byte loader authenticates all module owners before import.
This module does not provide general ELF-loader or runtime admission authority.
"""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python forbidden")
sys.dont_write_bytecode = True
import struct
from bootstrap_validate import Elf, LOADER, PAGE, need, sha, up, validate_rewrite
from frozen_profile import elf, fixture_loader_contract, metadata_offset
from old_audit import authenticate_case, validate_rpc
from sparse_geometry import describe

MAX_FILE = 16 * 1024 * 1024


def intersects(a, n, b, m):
    need(type(a) is type(n) is type(b) is type(m) is int, "integer intervals")
    need(0 <= a < 1 << 64 and 0 <= b < 1 << 64, "interval address")
    need(0 < n <= (1 << 64) - a and 0 < m <= (1 << 64) - b, "interval extent")
    return a < b + m and b < a + n


def dynamic_tags(data, headers):
    dynamic = [p for p in headers if p[0] == 2]
    need(len(dynamic) == 1, "one dynamic table")
    p = dynamic[0]
    need(0 < p[5] <= 256 * 16 and p[5] % 16 == 0, "bounded dynamic records")
    offset = metadata_offset(data, headers, p[3], p[5])
    need(offset == p[2], "dynamic file ownership")
    result = {}
    terminated = False
    for at in range(offset, offset + p[5], 16):
        tag, value = struct.unpack_from("<qQ", data, at)
        if terminated:
            need((tag, value) == (0, 0), "zero dynamic tail")
        elif tag == 0:
            need(value == 0, "zero DT_NULL value")
            terminated = True
        else:
            need(tag not in result, "unique dynamic tag")
            result[tag] = value
    need(terminated, "dynamic terminator")
    return result


def relocation_writes(data, forbidden):
    """The fixed cohort has one RELA/JMPREL record per file.

    Every decoded record, complete table, symbol entry and write is checked.
    No unknown kind gets a guessed width. The full original hash and existing
    profile remain mandatory independent premises at the outer boundary.
    """
    headers, _ = elf(data)
    tags = dynamic_tags(data, headers)
    need(not any(t in tags for t in (17, 18, 19, 35, 36, 37)), "no REL or RELR in fixed cohort")
    tables = []
    if any(t in tags for t in (7, 8, 9)):
        need(all(t in tags for t in (7, 8, 9)) and tags[9] == 24, "complete RELA triplet")
        tables.append(("RELA", tags[7], tags[8]))
    if any(t in tags for t in (2, 20, 23)):
        need(all(t in tags for t in (2, 20, 23)) and tags[20] == 7, "complete RELA JMPREL triplet")
        tables.append(("JMPREL", tags[23], tags[2]))
    need(len(tables) == 1, "one fixed relocation table")
    name, address, size = tables[0]
    need(size == 24, "one fixed relocation record")
    table_offset = metadata_offset(data, headers, address, size)
    owners = [p for p in headers if p[0] == 1 and p[3] <= address and address + size <= p[3] + p[5]]
    need(len(owners) == 1 and owners[0][1] == 4, "relocations wholly owned R-only metadata")
    target, info, addend = struct.unpack_from("<QQq", data, table_offset)
    symbol, kind = info >> 32, info & 0xffffffff
    need((name == "JMPREL" and kind == 7 and symbol == 1 and addend == 0) or
         (name == "RELA" and kind == 1 and symbol == 1 and addend == 0), "exact known relocation semantics")
    need(tags.get(11) == 24 and 6 in tags, "fixed dynamic symbol size")
    # Include symbol zero and the entire referenced entry, not just its first
    # address; a table crossing into executable storage is not admitted.
    symbol_size = (symbol + 1) * 24
    symbol_offset = metadata_offset(data, headers, tags[6], symbol_size)
    symbol_owners = [p for p in headers if p[0] == 1 and p[3] <= tags[6] and tags[6] + symbol_size <= p[3] + p[5]]
    need(len(symbol_owners) == 1 and symbol_owners[0][1] == 4, "whole referenced symbol range R-only")
    name_offset, symbol_info, other, section, value, symbol_bytes = struct.unpack_from("<IBBHQQ", data, symbol_offset + symbol * 24)
    need(5 in tags and 10 in tags and 0 < tags[10] <= 65536, "bounded strings")
    strings_offset = metadata_offset(data, headers, tags[5], tags[10])
    strings = data[strings_offset:strings_offset + tags[10]]
    need(name_offset < len(strings), "referenced symbol string bound")
    stop = strings.find(b"\0", name_offset)
    need(stop >= 0, "referenced symbol terminator")
    symbol_name = strings[name_offset:stop]
    if name == "JMPREL":
        need(symbol_name == b"fixture_indirect" and section == 0 and value == 0 and
             symbol_info == 0x12 and other == 0 and symbol_bytes == 0, "one original external function")
    else:
        need(symbol_name == b"fixture_value" and section != 0 and
             symbol_info == 0x12 and other == 0 and symbol_bytes == 6, "one original defined function")
        value_offset = metadata_offset(data, headers, value, symbol_bytes)
        value_owners = [p for p in headers if p[0] == 1 and p[3] <= value and value + symbol_bytes <= p[3] + p[5]]
        need(len(value_owners) == 1 and value_owners[0][1] == 5 and
             data[value_offset:value_offset + 6] == bytes.fromhex("b82a000000c3"), "exact original function definition")
    need(data[symbol_offset:symbol_offset + 24] == bytes(24), "literal null symbol")
    width = 8
    target_offset = metadata_offset(data, headers, target, width)
    target_owners = [p for p in headers if p[0] == 1 and p[3] <= target and target + width <= p[3] + p[5]]
    need(len(target_owners) == 1 and target_owners[0][1] == 6, "whole relocation write in RW non-code storage")
    for start, length in forbidden:
        need(not intersects(target, width, start, length), "relocation cannot overwrite remapped/generated code")
    need(not intersects(target, width, address, size), "relocation table cannot overwrite itself")
    return [dict(table=name, table_address=address, table_file_offset=table_offset,
                 table_bytes=size, record=0, target=target, target_file_offset=target_offset,
                 width=width, kind=kind, symbol=symbol, symbol_name=symbol_name.decode("ascii"),
                 symbol_value=value, symbol_size=symbol_bytes, addend=addend)]


def indirect_definition(data):
    """Exact second defined DSO symbol, independently of the function pointer."""
    headers, _ = elf(data)
    tags = dynamic_tags(data, headers)
    need(tags.get(11) == 24 and 6 in tags and 5 in tags and 10 in tags, "DSO symbol/string tags")
    at = metadata_offset(data, headers, tags[6], 3 * 24)
    owners = [p for p in headers if p[0] == 1 and p[3] <= tags[6] and tags[6] + 72 <= p[3] + p[5]]
    need(len(owners) == 1 and owners[0][1] == 4, "complete three-symbol inventory in R metadata")
    name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", data, at + 48)
    strings = metadata_offset(data, headers, tags[5], tags[10])
    need(name + len(b"fixture_indirect\0") <= tags[10], "indirect name in exact strings")
    need(data[strings + name:strings + name + 17] == b"fixture_indirect\0", "indirect symbol name")
    need(info == 0x12 and other == 0 and section != 0 and size == 9, "indirect function symbol")
    code = metadata_offset(data, headers, value, size)
    need(data[code:code + size] == bytes.fromhex("488b05f22f0000ffe0"), "exact indirect body")
    owners = [p for p in headers if p[0] == 1 and p[3] <= value and value + size <= p[3] + p[5]]
    need(len(owners) == 1 and owners[0][1] == 5, "indirect function RX owner")
    return value


def runtime_page_geometry(original, output, ledger):
    """Build only a file-offset view; no synthesized bytes or executable maps."""
    headers, _ = elf(original)
    original_loads = []
    effective = []
    source = ledger["source_page"]
    rows = ledger["rows"]
    need(len(rows) == 2 and all(r["length"] == PAGE for r in rows), "fixed one generated plus one source page")
    need(rows[-1]["address"] == source, "source mapping last")
    matched = 0
    for p in headers:
        if p[0] != 1:
            continue
        _, flags, offset, address, _, size, memory, align = p
        need(flags in (4, 5, 6) and 0 < size == memory and align == PAGE, "finite original file pages")
        row = dict(vaddr=address, offset=offset, file_size=size, memory_size=memory, flags=flags)
        original_loads.append(row)
        if address // PAGE * PAGE == source:
            need(flags == 5 and up(address + size) == source + PAGE, "one source RX page")
            effective.append(dict(vaddr=source, offset=rows[-1]["offset"], file_size=PAGE, memory_size=PAGE, flags=5))
            matched += 1
        else:
            effective.append(dict(row))
    need(matched == 1 and len(original_loads) == 4, "exact original source owner")
    generated = rows[0]
    effective.append(dict(vaddr=generated["address"], offset=generated["offset"], file_size=PAGE, memory_size=PAGE, flags=5))
    def pages(records):
        spans = []
        for r in records:
            a = r["vaddr"] // PAGE * PAGE
            z = up(r["vaddr"] + r["memory_size"])
            need(all(z <= x or y <= a for x, y in spans), "effective pages disjoint")
            spans.append((a, z))
            need(r["offset"] + r["file_size"] <= len(output), "actual complete backing")
        return spans, sum((z - a) // PAGE for a, z in spans)
    old_spans, old_count = pages(original_loads)
    new_spans, new_count = pages(effective)
    need((old_count, new_count) == (5, 6), "fixed body-oracle page inventory")
    minimum = min(a for a, _ in old_spans)
    maximum = max(z for _, z in new_spans)
    need(min(a for a, _ in new_spans) == minimum and 0 < maximum - minimum <= 1024 * 1024, "unchanged manual mapper bound")
    need(not (minimum <= LOADER < maximum), "bootstrap outside declared manual-body view")
    return dict(original_loads=original_loads, output_loads=effective, min_vaddr=minimum,
                max_vaddr=maximum, original_file_pages=old_count, rewritten_file_pages=new_count,
                mapped_bootstrap=False, loader_admission=False)


def runtime_body_geometry(original, output, ledger):
    """Build only a file-offset view; no synthesized bytes or executable maps."""
    headers, _ = elf(original)
    original_loads = []
    effective = []
    source = ledger["source_page"]
    rows = ledger["rows"]
    need(len(rows) == 2 and all(r["length"] == PAGE for r in rows), "fixed one generated plus one source page")
    need(rows[-1]["address"] == source, "source mapping last")
    matched = 0
    for p in headers:
        if p[0] != 1:
            continue
        _, flags, offset, address, _, size, memory, align = p
        need(flags in (4, 5, 6) and 0 < size == memory and align == PAGE, "finite original file pages")
        row = dict(vaddr=address, offset=offset, file_size=size, memory_size=memory, flags=flags)
        original_loads.append(row)
        if address // PAGE * PAGE == source:
            need(flags == 5 and up(address + size) == source + PAGE, "one source RX page")
            effective.append(dict(vaddr=source, offset=rows[-1]["offset"], file_size=PAGE, memory_size=PAGE, flags=5))
            matched += 1
        else:
            effective.append(dict(row))
    need(matched == 1 and len(original_loads) == 4, "exact original source owner")
    generated = rows[0]
    effective.append(dict(vaddr=generated["address"], offset=generated["offset"], file_size=PAGE, memory_size=PAGE, flags=5))
    def pages(records):
        spans = []
        for r in records:
            a = r["vaddr"] // PAGE * PAGE
            z = up(r["vaddr"] + r["memory_size"])
            need(all(z <= x or y <= a for x, y in spans), "effective pages disjoint")
            spans.append((a, z))
            need(r["offset"] + r["file_size"] <= len(output), "actual complete backing")
        return spans, sum((z - a) // PAGE for a, z in spans)
    old_spans, old_count = pages(original_loads)
    new_spans, new_count = pages(effective)
    need((old_count, new_count) == (5, 6), "fixed body-oracle page inventory")
    minimum = min(a for a, _ in old_spans)
    if struct.unpack_from("<H", original, 16)[0] == 3:
        # Keep the complete old compact predicate and implementation in use.
        value = runtime_page_geometry(original, output, ledger)
        value["body_ownership"] = describe("compact", value["min_vaddr"], value["max_vaddr"],
                                           source, generated["address"], generated["offset"])
        return value
    need(struct.unpack_from("<H", original, 16)[0] == 2, "exact EXEC type for sparse view")
    maximum = max(z for _, z in old_spans)
    need(old_spans == [(0x400000, 0x401000), (0x401000, 0x402000),
                       (0x402000, 0x403000), (0x403000, 0x405000)], "exact original EXEC cluster")
    need(new_spans[:-1] == old_spans and new_spans[-1] == (0x10000, 0x11000), "exact sparse effective page union")
    need(rows[-1]["offset"] == 0x4000, "exact appended EXEC source backing")
    ownership = describe("sparse-exec", minimum, maximum, source, generated["address"], generated["offset"])
    return dict(original_loads=original_loads, output_loads=effective, min_vaddr=minimum,
                max_vaddr=maximum, original_file_pages=old_count, rewritten_file_pages=new_count,
                mapped_bootstrap=False, loader_admission=False, body_ownership=ownership)


def structure(case, original, output, prefix, loader_elf, interpreter, variant):
    """Pure semantic checks; variant is explicit for old structural calibrations.

    Only a caller with fresh corrected-backend provenance may admit a new
    corrected output. Old-variant calibration never grants runtime authority.
    """
    need(variant in ("original", "corrected"), "separate reference variant")
    need(64 <= len(original) <= MAX_FILE and 64 <= len(output) <= MAX_FILE, "unchanged fixed file bound")
    profile = fixture_loader_contract(original, case["name"], interpreter, case["init"])
    pc, offset = case["pc"], case["file_offset"]
    body = b"\xb8" + case["value"].to_bytes(4, "little") + b"\xc3"
    need(original[offset:offset + 6] == body, "literal original MOV/RET heads")
    mode = "dso" if case["name"] == "libcarrierfixture.so" else "kernel"
    ledger = validate_rewrite(original, output, prefix, loader_elf, mode, pc, variant,
                              profile["fixture_note"]["bytes_sha256"])
    need(ledger["site_file_offset"] == offset, "exact original virtual/file selected coordinate")
    forbidden = [(ledger["source_page"], PAGE)]
    forbidden += [(r["address"], r["length"]) for r in ledger["rows"][:-1]]
    forbidden.append((ledger["loader"]["vaddr"], ledger["loader"]["memsz"]))
    writes = relocation_writes(original, forbidden)
    geometry = runtime_body_geometry(original, output, ledger)
    source_offset = ledger["rows"][-1]["offset"]
    image_row = ledger["rows"][0]
    image_offset = image_row["offset"] + ledger["target"] - image_row["address"]
    patched_offset = source_offset + pc - ledger["source_page"]
    need(output[patched_offset:patched_offset + 5][0] == 0xe9, "actual appended-source E9")
    need(output[patched_offset + 5] == 0xc3, "unchanged original RET")
    return dict(variant=variant, role="shared-object-init" if mode == "dso" else "executable-entry",
                original_sha256=sha(original), output_sha256=sha(output), original_profile=profile,
                ledger=ledger, relocation_writes=writes, geometry=geometry, source_pc=pc,
                source_file_offset=offset, patched_source_file_offset=patched_offset,
                patched_source_page_file_offset=source_offset, patched_source_page_sha256=sha(output[source_offset:source_offset + PAGE]),
                source_patch_hex=output[patched_offset:patched_offset + 5].hex(), image_pc=ledger["target"],
                image_file_offset=image_offset, image_bytes=10, image_sha256=sha(output[image_offset:image_offset + 10]),
                original_heads=[pc, pc + 5], restored_boundary=ledger["target"],
                declared_hook_events=0, native_admitted=False, qualification_complete=False)


def corrected(case, original, output, rpc, old_rpc, prefix, loader_elf, interpreter,
              old_output, old_prefix, old_loader_elf):
    """One fixed-site output: actual input/RPC identities and old body parity."""
    need(sha(original) == case["input_sha256"], "exact common original")
    need(sha(old_output) == case["historical_original_backend_output"]["sha256"], "old artifact identity")
    need(rpc == old_rpc and sha(rpc) == case["frozen_rpc"]["sha256"], "literal unchanged frontend RPC")
    # Uses the unchanged original-site/RPC parser, independently of emitted
    # debug statistics. It requires one exact passthru selected patch.
    original_elf = Elf(original)
    from old_audit import elf64
    validate_rpc(rpc, case, original, elf64(original))
    need(original_elf.storage(case["pc"], 5) == case["file_offset"], "independent selected translation")
    result = structure(case, original, output, prefix, loader_elf, interpreter, "corrected")
    historical = structure(case, original, old_output, old_prefix, old_loader_elf, interpreter, "original")
    need(result["image_pc"] == historical["image_pc"], "unchanged exact B1 target")
    a, b = result["patched_source_page_file_offset"], historical["patched_source_page_file_offset"]
    need(output[a:a + PAGE] == old_output[b:b + PAGE], "complete source-page parity with old artifact")
    a, b = result["image_file_offset"], historical["image_file_offset"]
    need(output[a:a + 10] == old_output[b:b + 10], "complete passthru image parity with old artifact")
    result["rpc_sha256"] = sha(rpc)
    result["historical_output_sha256"] = sha(old_output)
    result["old_body_parity"] = True
    return result
