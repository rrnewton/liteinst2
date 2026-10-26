"""Pure MAP_FIXED admission for the closed, single-threaded common fixtures."""
from bootstrap_validate import PAGE, need, up
from common import intersects
from mapping_identity import require_mapping_identity


def module_bias(rows, path, backing, original_headers):
    first = min((p for p in original_headers if p[0] == 1), key=lambda p: p[3])
    need(first[2] == 0 and first[3] % PAGE == 0 and first[1] == 4, "one original R ELF-header page")
    candidates = [m for m in rows if m["path"] == path and m["offset"] == 0 and
                  m["perms"] == "r--p" and m["hi"] - m["lo"] >= PAGE]
    need(len(candidates) == 1, "unique live header VMA")
    row = candidates[0]
    require_mapping_identity(tuple(backing), row["major"], row["minor"], row["inode"])
    bias = row["lo"] - first[3]
    need(0 <= bias < 1 << 47 and bias % PAGE == 0, "checked module bias")
    return bias


def source_owner(rows, address, original_offset, path, backing):
    overlapping = [m for m in rows if intersects(address, PAGE, m["lo"], m["hi"] - m["lo"])]
    need(len(overlapping) == 1, "source full-page unique ownership")
    m = overlapping[0]
    need(m["lo"] <= address and address + PAGE <= m["hi"] and m["perms"] == "r-xp", "original source is fully RX")
    need(m["path"] == path and m["offset"] + address - m["lo"] == original_offset, "exact original source file offset/path")
    require_mapping_identity(tuple(backing), m["major"], m["minor"], m["inode"])
    return dict(kind="original_source", vmas=overlapping)


def generated_owner(rows, address, length, path, backing, bias, output_headers):
    need(length == PAGE and address % PAGE == 0, "one generated page")
    occupied = [m for m in rows if intersects(address, length, m["lo"], m["hi"] - m["lo"])]
    if not occupied:
        return dict(kind="unoccupied", vmas=[])
    need(len(occupied) == 1, "one complete same-module reservation owner")
    m = occupied[0]
    need(m["lo"] <= address and address + length <= m["hi"] and m["perms"] == "---p", "complete PROT_NONE reservation")
    need(m["path"] == path, "same actual module, not a matching basename")
    require_mapping_identity(tuple(backing), m["major"], m["minor"], m["inode"])
    loads = [p for p in output_headers if p[0] == 1]
    first = min(loads, key=lambda p: p[3])
    lower = min(p[3] // PAGE * PAGE for p in loads)
    upper = max(up(p[3] + p[6]) for p in loads)
    need(bias + lower <= m["lo"] < m["hi"] <= bias + upper, "reservation is inside exact module envelope")
    need(all(not intersects(address, length, bias + p[3] // PAGE * PAGE,
                            up(p[3] + p[6]) - p[3] // PAGE * PAGE) for p in loads), "reservation does not replace any LOAD")
    expected_offset = first[2] // PAGE * PAGE + address - (bias + first[3] // PAGE * PAGE)
    need(m["offset"] + address - m["lo"] == expected_offset, "exact linear file offset in loader reservation")
    return dict(kind="same_module_PROT_NONE_reservation", vmas=occupied)
