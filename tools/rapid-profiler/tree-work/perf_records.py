"""Bounded layouts for the closed single-event regular-file perf profile.

This module supplies syntax, not task attribution or terminal-counter authority.
"""
import sys

if sys.flags.optimize:
    raise SystemExit("assertions required")

import hashlib
import struct

U64 = (1 << 64) - 1
SAMPLE_REQUIRED = sum(1 << n for n in (0, 1, 2, 4, 7, 8, 16))
SAMPLE_OPTIONAL = (1 << 6) | (1 << 9)
READ_REQUIRED = 7


class Refusal(Exception):
    def __init__(self, code, offset, *, unsupported=False):
        super().__init__(code)
        self.code, self.offset, self.unsupported = code, offset, unsupported


def require(ok, code, offset, *, unsupported=False):
    if not ok:
        raise Refusal(code, offset, unsupported=unsupported)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def align8(n):
    return (n + 7) & ~7


class Cursor:
    def __init__(self, data, offset=0):
        self.data, self.base, self.pos = data, offset, 0

    def take(self, n):
        require(type(n) is int and 0 <= n <= len(self.data) - self.pos,
                "truncated_field", self.base + self.pos)
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value

    def u(self, n=8):
        return int.from_bytes(self.take(n), "little")

    def zero(self, n):
        at = self.base + self.pos
        require(not any(self.take(n)), "nonzero_reserved_or_padding", at)

    def done(self):
        require(self.pos == len(self.data), "unconsumed_record_bytes", self.base + self.pos)


def string_tail(c, *, alignment=8, allocation_extra=0):
    """A NUL string consuming its complete zero-padded allocation."""
    at = c.base + c.pos
    tail = c.take(len(c.data) - c.pos)
    end = tail.find(b"\0")
    require(end >= 0, "unterminated_string", at)
    expected = ((end + 1 + allocation_extra + alignment - 1) // alignment) * alignment
    require(len(tail) == expected and not any(tail[end + 1:]), "string_padding", at)
    return tail[:end]


def trailer_size(sample_type):
    return 8 * sum(bool(sample_type & (1 << n)) for n in (1, 2, 6, 9, 7, 16))


def identity(c, sample_type, ids, *, synthetic_allowed=False):
    fields = {}
    if sample_type & (1 << 1):
        fields["pid"], fields["tid"] = c.u(4), c.u(4)
    if sample_type & (1 << 2):
        fields["time"] = c.u()
    if sample_type & (1 << 6):
        fields["id"] = c.u()
    if sample_type & (1 << 9):
        fields["stream_id"] = c.u()
    if sample_type & (1 << 7):
        fields["cpu"] = c.u(4)
        c.zero(4)
    if sample_type & (1 << 16):
        fields["identifier"] = c.u()
    zero = not any(fields.values())
    if synthetic_allowed and zero:
        fields["identity_kind"] = "zero_trailer_no_live_identity"
    else:
        for name in ("id", "identifier"):
            if name in fields:
                require(fields[name] in ids, "unknown_event_id", c.base)
        if "id" in fields and "identifier" in fields:
            require(fields["id"] == fields["identifier"], "identity_id_mismatch", c.base)
        fields["identity_kind"] = "event_id_only_not_task_authority"
    return fields


def read_values(c, read_format, ids):
    at = c.base + c.pos
    result = {"value": c.u(), "enabled": c.u(), "running": c.u(), "id": c.u()}
    if read_format & 16:
        result["lost"] = c.u()
    require(result["id"] in ids, "unknown_read_id", at)
    require(result["running"] <= result["enabled"], "running_exceeds_enabled", at)
    return result


def cpu_map(c):
    at = c.base + c.pos
    start = c.pos
    tag = c.u(2)
    result = {"encoding": tag}
    if tag == 0:
        n = c.u(2)
        require(n <= (len(c.data) - c.pos) // 2, "cpu_count_bounds", at)
        values = [c.u(2) for _ in range(n)]
        require(len(set(values)) == n, "duplicate_cpu", at)
        result["cpus"] = values
    elif tag == 1:
        n, width = c.u(2), c.u(2)
        require(width in (4, 8), "cpu_mask_width", at, unsupported=True)
        if width == 8:
            c.zero(4)
        require(n <= (len(c.data) - c.pos) // width, "cpu_mask_count_bounds", at)
        result.update(width=width, masks=[c.u(width) for _ in range(n)])
    elif tag == 2:
        any_cpu = c.u(1)
        c.zero(1)
        low, high = c.u(2), c.u(2)
        require(any_cpu in (0, 1) and low <= high, "cpu_range", at)
        result.update(any_cpu=any_cpu, low=low, high=high)
    else:
        raise Refusal("cpu_map_encoding", at, unsupported=True)
    c.zero(align8(c.pos - start) - (c.pos - start))
    return result


def _sample_payload(c, offset, sample_type, read_format, ids, result, adverse, unresolved):
    # precise_ip=0 does not promise exact attribution even if this bit appears.
    result.update(identifier=c.u(), ip=c.u(), pid=c.u(4), tid=c.u(4), time=c.u())
    if sample_type & (1 << 6):
        result["id"] = c.u()
    if sample_type & (1 << 9):
        result["stream_id"] = c.u()
    result["cpu"] = c.u(4)
    c.zero(4)
    result["period"] = c.u()
    result["read"] = read_values(c, read_format, ids)
    require(result["identifier"] in ids, "unknown_sample_id", offset + 8)
    require(result.get("id", result["identifier"]) == result["identifier"] == result["read"]["id"],
            "sample_read_id_mismatch", offset)
    require(result["pid"] > 0 and result["tid"] > 0, "sample_task_domain", offset)
    if result["read"]["enabled"] != result["read"]["running"]:
        adverse.append("sample_read_enabled_running_unequal")
    if result["read"].get("lost", 0):
        adverse.append("sample_read_lost_nonzero")
    if result["period"] == 0:
        adverse.append("zero_sample_period")
    c.done()
    return result, adverse, unresolved


def decode_record(raw, offset, attr, ids):
    c = Cursor(raw, offset)
    kind, misc, size = c.u(4), c.u(2), c.u(2)
    require(size == len(raw), "record_size_mismatch", offset + 6)
    sample_type, read_format = attr["sample_type"], attr["read_format"]
    result = {"offset": offset, "type": kind, "misc": misc, "size": size}
    adverse, unresolved = [], []
    if kind == 9:
        require(misc & ~0x4007 == 0, "sample_misc_extension", offset + 4, unsupported=True)
        require(misc & 7 == 2, "sample_not_host_user", offset + 4)
        return _sample_payload(c, offset, sample_type, read_format, ids, result, adverse, unresolved)

    kernel = {1, 2, 3, 4, 5, 6, 7, 8, 10, 13}
    if kind in kernel:
        s = trailer_size(sample_type)
        require(size >= 8 + s, "trailer_bounds", offset)
        body = Cursor(raw[8:size - s], offset + 8)
        tail = Cursor(raw[size - s:], offset + size - s)
        # Synthetic metadata has zero trailers; it never proves a live task/event.
        result["trailer"] = identity(tail, sample_type, ids, synthetic_allowed=kind in (1, 3, 7, 10))
        tail.done()
        allowed = {1: 0x3007, 2: 0, 3: 0x2007, 4: 0, 5: 0, 6: 0, 7: 0x2000,
                   8: 0, 10: 0x7007, 13: 0x8000}[kind]
        require(misc & ~allowed == 0, "record_misc_extension", offset + 4, unsupported=True)
        if kind in (1, 10):
            result.update(pid=body.u(4), tid=body.u(4), address=body.u(), length=body.u(), pgoff=body.u())
            require(result["length"] <= U64 - result["address"] and result["length"] <= U64 - result["pgoff"],
                    "mapping_overflow", offset)
            if kind == 10:
                require(not misc & 0x4000, "mmap_build_id_outside_command_profile", offset + 4, unsupported=True)
                result.update(major=body.u(4), minor=body.u(4), inode=body.u(), inode_generation=body.u(),
                              prot=body.u(4), flags=body.u(4))
            require(len(body.data) - body.pos <= 4096, "mapping_filename_bound", body.base + body.pos)
            result["filename"] = string_tail(body)
            if misc & 0x1000:
                adverse.append("mapping_snapshot_timeout")
        elif kind == 3:
            result.update(pid=body.u(4), tid=body.u(4))
            require(len(body.data) - body.pos <= 16, "comm_bound", body.base + body.pos)
            result["comm"] = string_tail(body)
        elif kind in (4, 7):
            result.update(pid=body.u(4), ppid=body.u(4), tid=body.u(4), ptid=body.u(4), time=body.u())
        elif kind == 8:
            result.update(pid=body.u(4), tid=body.u(4), read=read_values(body, read_format, ids))
            require(result["read"]["id"] == result["trailer"]["identifier"], "read_trailer_id_mismatch", offset)
            if result["read"]["enabled"] != result["read"]["running"]:
                adverse.append("read_enabled_running_unequal")
            if result["read"].get("lost", 0):
                adverse.append("read_lost_nonzero")
        elif kind == 2:
            result.update(id=body.u(), lost=body.u())
            require(result["id"] in ids and result["id"] == result["trailer"]["identifier"],
                    "lost_event_id_mismatch", offset)
            if result["lost"]:
                adverse.append("lost_records_nonzero")
        elif kind == 13:
            result["lost"] = body.u()
            if result["lost"]:
                adverse.append("lost_samples_nonzero")
            unresolved.append("lost_samples_task_scope_unresolved")
        else:
            result.update(time=body.u(), id=body.u(), stream_id=body.u())
            require(result["id"] in ids and result["id"] == result["trailer"]["identifier"],
                    "throttle_event_id_mismatch", offset)
            if "stream_id" in result["trailer"]:
                require(result["stream_id"] == result["trailer"]["stream_id"],
                        "throttle_stream_id_mismatch", offset + 24)
            adverse.append("throttle_observation")
        body.done()
        return result, adverse, unresolved

    require(kind in (68, 69, 73, 74, 78, 79, 82), "unsupported_record_type", offset, unsupported=True)
    require(misc == 0, "synthetic_misc_extension", offset + 4, unsupported=True)
    if kind in (68, 82):
        pass
    elif kind == 69:
        n = c.u()
        remaining = len(raw) - c.pos
        require(n > 0 and remaining in (32 * n, 48 * n), "id_index_count_or_extension", offset + 8)
        extended = remaining == 48 * n
        entries = []
        seen = set()
        for _ in range(n):
            entry = {name: c.u() for name in ("id", "idx", "cpu", "tid")}
            require(entry["id"] in ids and entry["id"] not in seen, "id_index_identity", c.base + c.pos - 32)
            seen.add(entry["id"])
            entries.append(entry)
        if extended:
            for entry in entries:
                entry.update(machine_pid=c.u(), vcpu=c.u())
            raise Refusal("id_index_nonhost_extension", offset, unsupported=True)
        result["entries"] = entries
    elif kind == 73:
        n = c.u()
        require(n <= (len(raw) - c.pos) // 24 and len(raw) - c.pos == n * 24,
                "thread_map_count", offset + 8)
        result["entries"] = [{"pid": c.u(), "comm": c.take(16)} for _ in range(n)]
    elif kind == 74:
        result["map"] = cpu_map(c)
    elif kind == 78:
        update, event_id = c.u(), c.u()
        require(event_id in ids, "event_update_id", offset + 16)
        result.update(update=update, id=event_id)
        if update in (0, 2):
            # LP64 sizeof(perf_record_event_update)=40, payload starts24.
            result["text"] = string_tail(c, allocation_extra=16)
        elif update == 1:
            value = c.take(8)
            result["scale_bits"] = value.hex()
            c.zero(16)
            require(value == struct.pack("<d", 1.0), "nonunit_event_scale", offset + 24, unsupported=True)
        elif update == 3:
            result["map"] = cpu_map(c)
        else:
            raise Refusal("event_update_type", offset + 8, unsupported=True)
        if update == 2:
            raise Refusal("regular_file_name_update", offset, unsupported=True)
    else:
        require(size == 56, "time_conv_layout", offset + 6, unsupported=True)
        result.update({name: c.u() for name in ("shift", "mult", "zero", "cycles", "mask")})
        result.update(cap_zero=c.u(1), cap_short=c.u(1))
        c.zero(6)
        require(result["cap_zero"] == 1 and result["cap_short"] in (0, 1), "time_conv_capability", offset + 48)
        require(result["shift"] < 64 and result["mult"] > 0, "time_conv_parameters", offset + 8)
    c.done()
    return result, adverse, unresolved


def decode_record_context_diagnostic(raw, offset, attr, ids):
    """Host SAMPLE context only. Every period remains UNATTRIBUTED."""
    c = Cursor(raw, offset)
    kind, misc, size = c.u(4), c.u(2), c.u(2)
    require(size == len(raw), "record_size_mismatch", offset + 6)
    if kind != 9:
        return decode_record(raw, offset, attr, ids)
    sample_type, read_format = attr["sample_type"], attr["read_format"]
    result = {"offset": offset, "type": kind, "misc": misc, "size": size}
    adverse, unresolved = [], []
    require(misc & ~0x4007 == 0, "sample_misc_extension", offset + 4, unsupported=True)
    require((misc & 7) in (1, 2), "unsupported_sample_context", offset + 4, unsupported=True)
    result, adverse, unresolved = _sample_payload(
        c, offset, sample_type, read_format, ids, result, adverse, unresolved)
    result["sample_context"] = "host_kernel" if misc & 7 == 1 else "host_user"
    result["attribution"] = "UNATTRIBUTED"
    if misc & 7 == 1:
        unresolved.append("kernel_sample_context_not_user_attribution")
    return result, adverse, unresolved
