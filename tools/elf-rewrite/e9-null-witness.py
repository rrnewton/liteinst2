#!/usr/bin/env python3
"""Read actual E9 bytes into finite, prospective null-hook completion witnesses.

No producer, decoder process, mapper, tracee, state search or native execution.
The sibling structural reader is reused only after its exact source hash check.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

if sys.flags.optimize:
    raise SystemExit('optimized Python disables witness checks')
ADAPTER = '5904a13ec1fcb8b6801dcff12ac1fe5a1154b884555bbd9fbc24521f9bc6949f'
TABLE = '74afc406acb8eb7742695afdf0e610a7e77afbaa6fb1498463a9e8ae85901fcd'
SEED = 'df1678dc0d0a5eede05d76d592048d5065d983fa44ba42c6d5dd7da9d297c2e3'
ORIGINALS = {'987b20efe393a0a2ca0293cd5601ba323b3f8292c9f1b5fab8a22b3124d3cff8',
             '1c7c66c58376c98df1dc3e5fd76d3c22a82ad7e96ef7aee1543a7c5b90a6f529'}
LOADS = [(0, 0x400000, 0x8b0, 0x8b0, 4), (0x1000, 0x401000, 0xa51, 0xa51, 5),
         (0x2000, 0x402000, 0xe1c, 0xe1c, 4), (0x3e00, 0x403e00, 0x20358, 0x20390, 6)]
MAX_FILE, PAGE, MAX_PAGES, MAX_PREFIX = 16 * 1024 * 1024, 4096, 2048, 32
LOW_END, ARRAY, FRAME = 1 << 47, 0x600000000000, 0x600000100008
CALL_WORDS = [0x401878, 0x401886, 0x401902, 0x401927, 0x401935, 0x401942]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def load_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            assert key not in value, 'duplicate JSON key'
            value[key] = item
        return value
    def invalid(text):
        raise AssertionError('non-JSON number: ' + text)
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class Bound:
    """Held no-follow regular descriptor plus whole path/byte recheck."""
    def __init__(self, row):
        assert row.keys() == {'path', 'sha256', 'bytes'}
        p = Path(row['path'])
        assert p.is_absolute() and os.fsencode(p.resolve(strict=True)) == os.fsencode(p)
        assert type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_FILE
        assert type(row['sha256']) is str and len(row['sha256']) == 64
        self.path, self.record = p, row
        self.fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        s = os.fstat(self.fd)
        assert stat.S_ISREG(s.st_mode) and s.st_size == row['bytes']
        self.owner = identity(s)
        self.data = self.read()
        assert len(self.data) == row['bytes'] and sha(self.data) == row['sha256']
        self.stable()

    def read(self):
        out = bytearray()
        while len(out) <= MAX_FILE:
            part = os.pread(self.fd, min(65536, MAX_FILE + 1 - len(out)), len(out))
            if not part:
                return bytes(out)
            out.extend(part)
        raise AssertionError('input exceeds fixed byte limit')

    def stable(self):
        assert identity(os.fstat(self.fd)) == self.owner
        assert identity(os.stat(self.path, follow_symlinks=False)) == self.owner
        assert self.read() == self.data, 'whole input drift'
        assert identity(os.fstat(self.fd)) == self.owner


def inventory(raw, original, adapter):
    assert sha(raw) == TABLE and sha(original) in ORIGINALS
    rows = [line.split('\t') for line in raw.decode().splitlines()]
    assert len(rows) == 88 and all(len(r) == 14 for r in rows)
    image = adapter['elf'](original, 2)
    assert [(p[2], p[3], p[5], p[6], p[1]) for p in image['rows'] if p[0] == 1] == LOADS
    heads = []
    for ordinal, r in enumerate(rows[1:], 1):
        sid, pc, length, offset = int(r[0]), int(r[1], 16), int(r[2]), int(r[3])
        code = bytes.fromhex(r[5])
        assert sid == ordinal and length == len(code)
        assert adapter['owner'](image, pc, length, True) == offset
        assert original[offset:offset + length] == code
        heads.append(dict(id=sid, pc=pc, length=length, file_offset=offset, function=r[4],
                          code=code, mnemonic=r[6], flow=r[7],
                          target=None if r[8] == 'none' else int(r[8], 16),
                          jump=r[11] == 'true', heap=r[12] == 'true'))
    assert [h['pc'] + h['length'] for h in heads if h['flow'] == 'Call'] == CALL_WORDS
    assert (len(heads), sum(h['jump'] for h in heads), sum(h['heap'] for h in heads)) == (87, 9, 1)
    return heads, image


def target_join(raw, selection):
    """Bind the full record to the exact compact selection projection."""
    lines = raw.decode().splitlines()
    assert raw.endswith(b'\n') and lines[0] == 'LI2TARGET\t1'
    fields, components = {}, []
    for line in lines[1:]:
        r = line.split('\t')
        if r[0] == 'component':
            assert len(r) == 4
            components.append(tuple(map(int, r[1:])))
        else:
            assert len(r) == 2 and r[0] not in fields
            fields[r[0]] = r[1]
    assert fields.keys() == {'os', 'isa', 'cet', 'page_bytes', 'bias_domain', 'format',
                             'allocation_bytes', 'image_bytes', 'xcr0_mask', 'qualification_complete'}
    assert [fields[k] for k in ('os', 'isa', 'cet', 'page_bytes', 'bias_domain', 'qualification_complete')] == [
        'linux', 'x86-64-legacy-evex', 'unqualified', '4096', '1', 'false']
    allocation, extent, mask = (int(fields[k]) for k in ('allocation_bytes', 'image_bytes', 'xcr0_mask'))
    assert 512 <= extent <= allocation <= 16384 and 0 <= mask < 1 << 64
    if fields['format'] == 'fxsave64':
        assert (allocation, extent, mask, components) == (512, 512, 3, [])
        compact = 'target fxsave64'
    else:
        assert fields['format'] == 'xsave64-standard' and mask & 3 == 3
        assert extent >= 576 and allocation == (extent + 63) // 64 * 64
        previous, end, found = 0, 576, 3
        for feature, offset, size in components:
            assert feature > previous and feature >= 4 and feature & (feature - 1) == 0
            assert feature & mask and offset >= end and size > 0 and offset + size <= extent
            previous, end, found = feature, offset + size, found | feature
        assert found == mask and end == extent
        compact = 'target xsave64 ' + str(mask) + ''.join(f' {f}:{o}:{s}' for f, o, s in components)
    actual = [line for line in selection.decode().splitlines() if line.startswith('target ')]
    assert actual == [compact], 'full target/compact selection mismatch'
    return dict(fields=fields, components=components, compact=compact)


class View:
    """Declared controlled page image, not evidence the loader ran."""
    def __init__(self, candidate, image, maps, recording_hook=None):
        self.pages, self.records, self.order = {}, {}, []
        for index, p in enumerate(image['rows']):
            if p[0] != 1:
                continue
            _, flags, off, va, _, fs, ms, _ = p
            assert flags in (4, 5, 6) and off % PAGE == va % PAGE
            assert 0 < ms and va + ms < LOW_END
            start, stop = va // PAGE * PAGE, (va + ms + PAGE - 1) // PAGE * PAGE
            row = dict(kind='PT_LOAD', ph_index=index, offset=off, va=va, file_bytes=fs,
                       memory_bytes=ms, flags=flags)
            self.order.append(row)
            for page in range(start, stop, PAGE):
                assert page not in self.pages, 'overlapping LOAD pages'
                at = off // PAGE * PAGE + page - start
                content = bytearray(PAGE)
                count = min(PAGE, max(0, len(candidate) - at)) if page < (va + fs + PAGE - 1) // PAGE * PAGE else 0
                content[:count] = candidate[at:at + count]
                zero = max(0, va + fs - page) if ms > fs else PAGE
                zero = min(PAGE, zero)
                content[zero:] = bytes(PAGE - zero)
                self.put(page, bytes(content), flags, len(self.order) - 1, at, count, zero)
        for mapping in maps:  # The reused reader authenticated this actual loader order.
            row = dict(mapping)
            assert row['va'] >= 0 and row['va'] + row['length'] < LOW_END
            if recording_hook is not None and row['prot'] not in (1,5):
                assert row['prot'] == 3, 'only the admitted readable/writable non-executable hook LOAD'
                owners=[p for p in recording_hook['loads'] if p['flags']==6
                        and p['start']//PAGE*PAGE <= row['va']
                        and row['va']+row['length'] <= (p['end']+PAGE-1)//PAGE*PAGE]
                assert len(owners)==1 and row['kind']=='trampoline'
            else:
                assert row['prot'] in (1, 5), 'null code mappings must be immutable/readable'
            self.order.append(row)
            flags = 4 | (1 if row['prot'] & 4 else 0) | (2 if recording_hook is not None and row['prot'] & 2 else 0)
            for page in range(row['va'], row['va'] + row['length'], PAGE):
                assert (page in self.pages) == (row['kind'] == 'refactoring')
                if row['kind'] == 'refactoring':
                    assert self.records[page]['flags'] == 5
                at = row['offset'] + page - row['va']
                content = candidate[at:at + PAGE]
                assert len(content) == PAGE
                self.put(page, content, flags, len(self.order) - 1, at, PAGE, PAGE)
        assert len(self.pages) <= MAX_PAGES

    def put(self, page, content, flags, order, offset, count, zero):
        for lo, hi in [(ARRAY - PAGE, ARRAY + 2 * PAGE), (FRAME - 32776 - PAGE, FRAME + 32760 + PAGE)]:
            assert page + PAGE <= lo or page >= hi, 'image collides with owned seed regions'
        self.pages[page] = content
        self.records[page] = dict(va=page, flags=flags, owner_order=order, file_offset=offset,
                                  copied_bytes=count, zero_from=zero, sha256=sha(content))
        assert len(self.pages) <= MAX_PAGES, 'fixed virtual image bound'

    def read(self, pc, size):
        if not (0 < size <= 32 and 0 <= pc < LOW_END - size):
            return None
        out = bytearray()
        for at in range(pc, pc + size):
            page = at // PAGE * PAGE
            if page not in self.pages or self.records[page]['flags'] != 5:
                return None
            out.append(self.pages[page][at - page])
        return bytes(out)

    def trampoline(self, pc, size):
        row = self.records.get(pc // PAGE * PAGE)
        if row is None:
            return False
        owner = self.order[row['owner_order']]
        return owner['kind'] == 'trampoline' and owner['va'] <= pc and pc + size <= owner['va'] + owner['length']


def jump(view, pc):
    """Only the pinned stateless source gateways; no scan for a matching state."""
    first = view.read(pc, 1)
    if first == b'\xeb':
        b = view.read(pc, 2)
        return None if b is None else (b, pc + 2 + struct.unpack('<b', b[1:])[0])
    prefix = b''
    for byte in (0x48, 0x26, 0x36, 0x3e):
        if view.read(pc + len(prefix), 1) != bytes([byte]):
            break
        prefix += bytes([byte])
    b = view.read(pc + len(prefix), 5)
    if b is None or b[0] != 0xe9:
        return None
    return prefix + b, pc + len(prefix) + 5 + struct.unpack_from('<i', b, 1)[0]


def relative(opcode, pc, target):
    delta = target - (pc + len(opcode) + 4)
    if not -(1 << 31) <= delta < 1 << 31:
        return None
    return opcode + struct.pack('<i', delta)


def operation(head, body):
    """Expected bytes from the closed original and pinned relocateInstr rules."""
    old = head['code']
    if body == head['pc']:
        return [old]
    if head['flow'] == 'Call':
        word = head['pc'] + head['length']
        assert old[0] == 0xe8 and len(old) == 5 and word < 1 << 31
        tail = relative(b'\xe9', body + 5, head['target'])
        return None if tail is None else [b'\x68' + struct.pack('<i', word), tail]
    if head['flow'] == 'ConditionalBranch':
        assert old[0] in (0x72, 0x73, 0x75, 0x76) and len(old) == 2
        code = relative(bytes([0x0f, old[0] + 0x10]), body, head['target'])
        return None if code is None else [code]
    if head['flow'] == 'UnconditionalBranch':
        assert old[0] == 0xeb and len(old) == 2
        code = relative(b'\xe9', body, head['target'])
        return None if code is None else [code]
    assert head['flow'] in ('Next', 'Return')
    return [old]  # The hash-pinned corpus has no RIP-relative data operand.


def route(view, start, target):
    steps, visited, pc = [], set(), start
    for _ in range(MAX_PREFIX + 1):
        if pc == target:
            return steps
        if pc in visited or len(steps) == MAX_PREFIX:
            return None
        visited.add(pc)
        edge = jump(view, pc)
        if edge is None:
            return None
        code, to = edge
        steps.append(dict(pc=pc, next=to, bytes=code.hex()))
        pc = to
    return None


def derive(head, view, outcome, bypass):
    record = {k: v for k, v in head.items() if k != 'code'}
    record.update(original_bytes=head['code'].hex(), status='REQUIRED_UNRESOLVED', prefix=[],
                  body=None, operation=[], continuation=None, reason=None)
    if outcome is not None and outcome['tactic'] is None:
        record['reason'] = 'selected_site_refused'
        return record
    pc, visited = head['pc'], set()
    for _ in range(MAX_PREFIX + 1):
        if pc in visited:
            record['reason'] = 'gateway_cycle'
            return record
        visited.add(pc)
        expected = operation(head, pc)
        code = None if expected is None else b''.join(expected)
        body_owner = pc == head['pc'] or (code is not None and view.trampoline(pc, len(code) + 5))
        if body_owner and code is not None and view.read(pc, len(code)) == code:
            if outcome is not None and pc != outcome['low']:
                record['reason'] = 'selected_body_differs_from_actual_trampoline_entry'
                return record
            continuation = None
            if pc != head['pc']:
                at = pc + len(code)
                raw = view.read(at, 5)
                if raw is None or raw[0] != 0xe9:
                    record['reason'] = 'missing_exact_continue'
                    return record
                to = at + 5 + struct.unpack_from('<i', raw, 1)[0]
                logical = head['pc'] + head['length']
                bypass_steps = []
                if to != logical:
                    bypass_steps = route(view, logical, to)
                    if (logical, to) not in bypass or bypass_steps is None:
                        record['reason'] = 'unowned_continue_bypass'
                        return record
                continuation = dict(pc=at, next=to, bytes=raw.hex(), logical_fallthrough=logical,
                                    bypass_steps=bypass_steps, executed_for_completion=False)
                if outcome is not None and at + 5 != outcome['high']:
                    record['reason'] = 'selected_extent_not_exact_null_template'
                    return record
            parts, at = [], pc
            for raw in expected:
                parts.append(dict(pc=at, bytes=raw.hex()))
                at += len(raw)
            record.update(status='BYTE_WITNESS_COMPLETE', body=pc, operation=parts, continuation=continuation)
            return record
        if len(record['prefix']) == MAX_PREFIX:
            record['reason'] = 'fixed_prefix_bound'
            return record
        edge = jump(view, pc)
        if edge is None:
            record['reason'] = 'unsupported_actual_instruction_shape'
            return record
        raw, to = edge
        record['prefix'].append(dict(pc=pc, next=to, bytes=raw.hex()))
        pc = to
    raise AssertionError('unreachable bound')


RECORDING_PROFILE = 'bounded-journal-v1'
E9_BEFORE = bytes.fromhex('488da42400c0ffff415341525041514150515256570f90c09f50')
E9_AFTER = bytes.fromhex('58047f9e5f5e5a594158415958415a415b488da42400400000')


def recording_hook_info(adapter, envelope, blobs):
    hook = envelope['hook']
    assert hook is not None and hook['symbol'] == 'li2_e9_record'
    data = blobs['hook_elf']
    image = adapter['elf'](data, 3)
    assert adapter['dynamic_symbol'](data, 'li2_e9_record') == hook['entry']
    # Recover the size from the same complete dynsym, not a RET scan or a
    # caller-provided extent. The existing structural reader owns all reserves.
    shoff = struct.unpack_from('<Q', data, 40)[0]
    width, count = struct.unpack_from('<HH', data, 58)
    assert width == 64 and 1 <= count <= 4096 and shoff + width*count <= len(data)
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*width) for i in range(count)]
    tables = [s for s in sections if s[1] == 11]
    assert len(tables) == 1
    table = tables[0]
    assert table[9] == 24 and table[5] % 24 == 0 and table[5]//24 <= 4096
    assert table[4]+table[5] <= len(data) and table[6] < count
    strings = sections[table[6]]
    assert strings[1] == 3 and strings[4]+strings[5] <= len(data)
    names = data[strings[4]:strings[4]+strings[5]]
    matches = []
    for at in range(table[4], table[4]+table[5], 24):
        name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', data, at)
        assert name < len(names) and b'\0' in names[name:]
        if names[name:].split(b'\0',1)[0] == b'li2_e9_record':
            assert info == 0x12 and section != 0 and value == hook['entry'] and 0 < size <= 4096
            offset = adapter['owner'](image,value,size,True)
            matches.append((value,size,data[offset:offset+size]))
    assert len(matches) == 1
    value,size,code = matches[0]
    return dict(entry=hook['base']+value, bytes=code.hex(),
                loads=[dict(start=hook['base']+p[3], end=hook['base']+p[3]+p[6], flags=p[1])
                       for p in image['rows'] if p[0] == 1])


def clean_prefix(entry, logical, hook):
    result = E9_BEFORE + relative(b'\x48\x8d\x3d', entry+len(E9_BEFORE), logical)
    result += relative(b'\xe8', entry+len(result), hook)
    result += E9_AFTER
    assert len(result) == 63
    return result


def derive_recording(head, view, outcome, bypass, hook):
    if outcome is None:
        result = derive(head,view,None,bypass)
        result['clean'] = None
        return result
    record = {k:v for k,v in head.items() if k != 'code'}
    record.update(original_bytes=head['code'].hex(), status='REQUIRED_UNRESOLVED', prefix=[],
                  body=None,operation=[],continuation=None,reason=None,clean=None)
    if outcome['tactic'] is None:
        record['reason'] = 'selected_site_refused'; return record
    entry = outcome['low']
    prefix = route(view,head['pc'],entry)
    if prefix is None:
        record['reason'] = 'no_complete_gateway'; return record
    clean = clean_prefix(entry,head['pc'],hook['entry'])
    body = entry+len(clean)
    if not view.trampoline(entry,len(clean)) or b''.join(view.read(entry+i,1) or b'' for i in range(len(clean))) != clean:
        record['reason'] = 'exact_clean_template_mismatch'; return record
    operation_parts = operation(head,body)
    if operation_parts is None:
        record['reason'] = 'operation_out_of_range'; return record
    code = b''.join(operation_parts)
    if view.read(body,len(code)) != code:
        record['reason'] = 'whole_relocated_operation_mismatch'; return record
    at = body+len(code)
    raw = view.read(at,5)
    if raw is None or raw[0] != 0xe9 or at+5 != outcome['high']:
        record['reason'] = 'exact_recording_extent_or_continue_mismatch'; return record
    to = at+5+struct.unpack_from('<i',raw,1)[0]
    logical = head['pc']+head['length']
    bypass_steps=[]
    if to != logical:
        bypass_steps=route(view,logical,to)
        if (logical,to) not in bypass or bypass_steps is None:
            record['reason']='unowned_continue_bypass'; return record
    parts=[]; pc=body
    for part in operation_parts:
        parts.append(dict(pc=pc,bytes=part.hex())); pc+=len(part)
    # CALL is the final five bytes before the literal restore suffix.
    return_pc=body-len(E9_AFTER)
    record.update(status='BYTE_WITNESS_COMPLETE',prefix=prefix,body=body,operation=parts,
                  clean=dict(entry=entry,hook=hook['entry'],return_pc=return_pc,bytes=clean.hex()),
                  continuation=dict(pc=at,next=to,bytes=raw.hex(),logical_fallthrough=logical,
                                    bypass_steps=bypass_steps,executed_for_completion=False))
    return record


def cases(heads):
    result = []
    for case in range(176):
        index, state = (case // 2 if case < 174 else 0), case & 1
        h = heads[index]
        r = dict(case=case, head_id=index + 1, state=state, seed=[0x1234567887654320, 0xfedcba9801234567][state],
                 rflags=[0x202, 0xad7][state], fault=case >= 174, status=h['status'],
                 prefix=h['prefix'], operation=[], completion=None, required=True)
        if h['status'] == 'BYTE_WITNESS_COMPLETE':
            next_pc = h['pc'] + h['length']
            taken = {'Jb': state == 1, 'Jae': state == 0, 'Jbe': state == 1, 'Jne': state == 0}.get(h['mnemonic'], False)
            logical = h['target'] if taken or h['flow'] in ('Call', 'UnconditionalBranch') else 0x401878 if h['flow'] == 'Return' else next_pc
            last = h['operation'][-1]
            physical = logical if taken or h['flow'] in ('Call', 'UnconditionalBranch', 'Return') else last['pc'] + len(bytes.fromhex(last['bytes']))
            if case >= 174:
                r['operation'] = [dict(h['operation'][0], next=h['body'])]
                r['completion'] = dict(kind='fault', physical_pc=h['body'], logical_pc=h['pc'],
                                       signal=11, code=2, address=ARRAY + [8, 24][state])
            else:
                r['operation'] = [dict(step, next=(h['operation'][i + 1]['pc'] if i + 1 < len(h['operation']) else physical))
                                  for i, step in enumerate(h['operation'])]
                r['completion'] = dict(kind='original-boundary', physical_pc=physical, logical_pc=logical,
                                       call_return_word=next_pc if h['flow'] == 'Call' else None)
        result.append(r)
    assert len(result) == 176
    return result


def read_witness(adapter, envelope, blobs, table, target, record=False):
    site_wire, structural = adapter['validate'](envelope, blobs)
    if record:
        assert envelope['hook'] is not None and structural['policy']['instrumentation']=='real-hook'
        hook=recording_hook_info(adapter,envelope,blobs)
    else:
        assert envelope['hook'] is None and structural['policy']['instrumentation'] == 'null'
        hook=None
    assert structural['policy']['selection_style'] in ('jump-site', 'heap-write')
    heads, old = inventory(table, blobs['original'], adapter)
    target_record = target_join(target, blobs['selection'])
    sites, _ = adapter['selection'](blobs['selection'], blobs['original'], blobs['policy'])
    expected = [dict(site=h['id'], pc=h['pc'], length=h['length'], file_offset=h['file_offset']) for h in heads
                if h['jump' if structural['policy']['selection_style'] == 'jump-site' else 'heap']]
    assert sites == expected, 'complete original static selection, including zero-visit sites'
    outcomes, maps, bypass = adapter['debug'](blobs['producer_stderr'], sites)
    new = adapter['elf'](blobs['candidate'], 2)
    view, original_view = View(blobs['candidate'], new, maps, hook), View(blobs['original'], old, [])
    assert len(original_view.pages) == 37
    by_pc = {row['pc']: row for row in outcomes}
    witnesses = [derive_recording(h,view,by_pc.get(h['pc']),bypass,hook) if record else derive(h, view, by_pc.get(h['pc']), bypass) for h in heads]
    unresolved = [dict(head_id=h['id'], pc=h['pc'], reason=h['reason']) for h in witnesses if h['status'] != 'BYTE_WITNESS_COMPLETE']
    global_issues = []
    classified = [line.split('\t')[4] for line in site_wire.decode().splitlines()[7:]]
    assert len(classified) == len(sites)
    if any(kind != 'trampoline' for kind in classified):
        global_issues.append('every_requested_site_must_be_a_nontrap_trampoline')
    if not unresolved:
        consumed_bypass = Counter((h['continuation']['logical_fallthrough'], h['continuation']['next']) for h in witnesses
                                  if h['continuation'] and h['continuation']['bypass_steps'])
        if consumed_bypass != Counter(bypass):
            global_issues.append('unaccounted_actual_bypass_record')
        allowed = set(range(0x400000 + 24, 0x400000 + 32))
        changed_ph = [i for i, (a, b) in enumerate(zip(old['rows'], new['rows'])) if a != b]
        assert len(changed_ph) == 1
        at = 0x400000 + old['phoff'] + changed_ph[0] * 56
        allowed.update(range(at, at + 56))
        for h in witnesses:
            for edge in h['prefix']:
                # An observed gateway never grants write ownership of a new
                # original region. Only the three complete kernel ranges are
                # in this finite selection; unrelated text remains exact.
                for address in range(edge['pc'], edge['pc'] + len(bytes.fromhex(edge['bytes']))):
                    if any(source['pc'] <= address < source['pc'] + source['length'] for source in heads):
                        allowed.add(address)
        for page, before in original_view.pages.items():
            assert page in view.pages and view.records[page]['flags'] == original_view.records[page]['flags']
            if any(a != b and page + i not in allowed for i, (a, b) in enumerate(zip(before, view.pages[page]))):
                global_issues.append(f'unowned_original_page_change:{page:#x}')
    ready = not unresolved and not global_issues
    report = dict(schema=1, format='LI2COMMONE9-1', scope='STRUCTURAL_E9_NULL_COMPLETION_WITNESSES_ONLY',
                  status='COMPLETE_BYTE_WITNESSES' if ready else 'REQUIRED_UNRESOLVED',
                  witness_complete=ready, native_admission=False, qualification_complete=False,
                  actual_runtime=None, lane=envelope['lane'], source_seed_sha256=SEED,
                  original_sha256=sha(blobs['original']), candidate_sha256=sha(blobs['candidate']),
                  instructions_sha256=sha(table), target_sha256=sha(target), selection_sha256=sha(blobs['selection']),
                  target=target_record, structural=structural, selected_site_wire_sha256=sha(site_wire),
                  mapping_order=view.order, final_pages=[view.records[p] for p in sorted(view.records)],
                  heads=witnesses, cases=cases(witnesses), required_heads=87, required_cases=176,
                  unresolved_heads=unresolved, global_issues=global_issues,
                  limits=dict(input_bytes=MAX_FILE, mapped_pages=MAX_PAGES, prefix_edges=MAX_PREFIX,
                              operation_edges=2, existing_native_seconds=15, existing_native_stops=20000),
                  boundaries=dict(raw_rip_must_match_before_logical_label=True, compare_flags_excluding_only_TF_RF=True,
                                  canonical_xsave_and_complete_data_and_fixed_stack_required=True,
                                  fixed_application_stack=[FRAME - 128, FRAME + 32760],
                                  native_state_comparison_performed=False, loader_execution_proved=False))
    if record:
        report['scope']='STRUCTURAL_E9_RECORDING_COMPLETION_WITNESSES_ONLY'
        report['recording_profile']=RECORDING_PROFILE
        report['recording_hook']=hook
        assert sum(h['clean'] is not None for h in witnesses)==len(sites) if ready else True
    return report, site_wire


def native_projection(report, json_bytes):
    """Fixed TSV projection; no additional admission or semantic inference."""
    rows = [['LI2COMMONE9NATIVE', 1], ['status', report['status']],
            ['witness_json_sha256', sha(json_bytes)],
            ['scope', report['scope']]]
    for key in ('original_sha256', 'instructions_sha256', 'target_sha256',
                'selection_sha256', 'candidate_sha256', 'source_seed_sha256'):
        rows.append([key, report[key]])
    rows += [['native_admission', 'false'], ['qualification_complete', 'false']]
    if not report['witness_complete']:
        rows.append(['required', 87, 174, 2, 'UNRESOLVED'])
    else:
        for role, item in sorted(report['inputs'].items()):
            rows.append(['file', role, os.fsencode(item['path']).hex(), item['bytes'],
                         item['sha256'], *item['owner']])
        for order, item in enumerate(report['mapping_order']):
            if item['kind'] == 'PT_LOAD':
                rows.append(['load', order, item['ph_index'], item['offset'], item['va'],
                             item['file_bytes'], item['memory_bytes'], item['flags']])
            else:
                rows.append(['mapping', order, item['kind'], item['va'], item['length'],
                             item['prot'], item['offset']])
        for item in report['final_pages']:
            rows.append(['page', *[item[k] for k in ('va', 'flags', 'owner_order',
                         'file_offset', 'copied_bytes', 'zero_from', 'sha256')]])
        if report.get('recording_profile')==RECORDING_PROFILE:
            hook=report['recording_hook']
            rows.append(['recording-hook',hook['entry'],hook['bytes']])
            for load in hook['loads']:
                rows.append(['hook-load',load['start'],load['end'],load['flags']])
        for head in report['heads']:
            rows.append(['head', head['id'], head['pc'], head['body'], head['original_bytes']])
            for edge in head['prefix']:
                rows.append(['walk', head['id'], edge['pc'], edge['next'], edge['bytes']])
            if head.get('clean') is not None:
                clean=head['clean']
                rows.append(['clean',head['id'],clean['entry'],clean['hook'],clean['return_pc'],clean['bytes']])
            for edge in head['operation']:
                rows.append(['op', head['id'], edge['pc'], edge['bytes']])
            continuation = head['continuation']
            if continuation is not None:
                rows.append(['continue', head['id'], continuation['pc'], continuation['next'],
                             continuation['bytes'], continuation['logical_fallthrough']])
                for edge in continuation['bypass_steps']:
                    rows.append(['bypass', head['id'], edge['pc'], edge['next'], edge['bytes']])
        for case in report['cases']:
            rows.append(['case', case['case'], case['head_id'], case['state'], case['seed'],
                         case['rflags'], str(case['fault']).lower()])
            for edge in case['operation']:
                rows.append(['step', case['case'], edge['pc'], edge['next'], edge['bytes']])
            done = case['completion']
            rows.append(['done', case['case'], done['kind'], done['physical_pc'], done['logical_pc'],
                         *[done.get(k, 'none') if done.get(k) is not None else 'none'
                           for k in ('signal', 'code', 'address', 'call_return_word')]])
        rows.append(['complete', 87, 174, 2])
    assert all('\t' not in str(v) and '\n' not in str(v) and '\r' not in str(v)
               for row in rows for v in row)
    return ''.join('\t'.join(map(str, row)) + '\n' for row in rows).encode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('inputs', type=Path)
    parser.add_argument('new_output', type=Path)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--structural-reader', type=Path,
                        help='optional canonical path to the same exact pinned e9-sites.py')
    parser.add_argument('--recording-profile', choices=[RECORDING_PROFILE])
    args = parser.parse_args()
    record=args.recording_profile is not None
    # Reading the small caller record is itself bound, including its path owner.
    given = Bound(dict(path=str(args.inputs), sha256=args.inputs_sha256, bytes=args.inputs.stat().st_size))
    value = load_json(given.data)
    if record:
        assert value.keys()=={'schema','structural_envelope','instructions','target','recording_profile'} and value['recording_profile']==RECORDING_PROFILE
        assert type(value['schema']) is int and value['schema']==1
    else:
        assert value.keys() == {'schema', 'structural_envelope', 'instructions', 'target'} and type(value['schema']) is int and value['schema'] == 1
    held = {role: Bound(value[role]) for role in ('structural_envelope', 'instructions', 'target')}
    own_path = Path(__file__).resolve()
    own_bytes = own_path.read_bytes()
    own_source = Bound(dict(path=str(own_path), sha256=sha(own_bytes), bytes=len(own_bytes)))
    source_path = args.structural_reader if args.structural_reader is not None else own_path.with_name('e9-sites.py')
    source = Bound(dict(path=str(source_path), sha256=ADAPTER, bytes=35452))
    namespace = {'__name__': '_pinned_e9_sites_reader_', '__file__': str(source_path)}
    exec(compile(source.data, str(source_path), 'exec'), namespace)  # Exact existing reader; main() is not called.
    envelope = namespace['loads'](held['structural_envelope'].data)
    if record:
        assert type(envelope['files']) is dict and len(envelope['files'])==18 and 'hook_elf' in envelope['files']
    else:
        assert type(envelope['files']) is dict and len(envelope['files']) == 17
    products = {role: Bound(row) for role, row in envelope['files'].items()}
    report, site_wire = read_witness(namespace, envelope, {k: v.data for k, v in products.items()},
                                     held['instructions'].data, held['target'].data, record)
    all_inputs = {'inputs': given, 'structural_reader': source, 'witness_reader': own_source, **held,
                  **{'producer/' + k: v for k, v in products.items()}}
    for bound in all_inputs.values():
        bound.stable()
    report['inputs'] = {role: dict(bound.record, owner=bound.owner) for role, bound in all_inputs.items()}
    report['reader_source_sha256'] = sha(own_source.data)
    args.new_output.mkdir(parents=False, exist_ok=False)
    json_bytes = canonical(report)
    output = {'witness.json': json_bytes, 'sites.tsv': site_wire,
              'native.tsv': native_projection(report, json_bytes)}
    for name, data in output.items():
        with (args.new_output / name).open('xb') as stream:
            stream.write(data)
    index = {name: dict(bytes=len(data), sha256=sha(data)) for name, data in output.items()}
    with (args.new_output / 'files.json').open('xb') as stream:
        stream.write(canonical(index))
    print(f"E9 {'recording' if record else 'null'} witnesses: 87 required heads; 176 required cases; {report['status']}")
    return 0 if report['witness_complete'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
