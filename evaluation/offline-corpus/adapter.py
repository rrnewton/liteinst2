#!/usr/bin/env python3
"""Closed instruction-table preparation and byte witnesses; no subject execution."""
import csv
import io
import json
import struct
from pathlib import Path
from corpus import BASE, HOOK, instructions, sha

CAP = 16 * 1024 * 1024

def read(path):
    p = Path(path)
    assert p.is_file() and not p.is_symlink()
    with p.open('rb') as f:
        data = f.read(CAP + 1)
    assert len(data) <= CAP
    return data

def elf(data):
    assert 64 <= len(data) <= CAP and data[:16] == b'\x7fELF\x02\x01\x01' + bytes(9)
    assert struct.unpack_from('<HHI', data, 16) == (2, 62, 1)
    entry, off = struct.unpack_from('<QQ', data, 24)
    eh, width, count = struct.unpack_from('<HHH', data, 52)
    assert eh == 64 and width == 56 and 1 <= count <= 128 and off + count * width <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ', data, off + i * width) for i in range(count)]
    loads = [p for p in rows if p[0] == 1]
    for p in loads:
        assert p[1] in (4, 5, 6) and 0 < p[5] <= p[6] and p[2] + p[5] <= len(data)
        assert p[2] % 4096 == p[3] % 4096 and p[7] == 4096
    for i, p in enumerate(loads):
        assert all(p[3] + p[6] <= q[3] or q[3] + q[6] <= p[3] for q in loads[:i])
    assert not any(p[0] in (2, 3) for p in rows), 'no dynamic segment or interpreter'
    assert len([p for p in rows if p[0] == 0x6474e551 and p[1] == 6]) == 1
    return entry, rows

def owned(data, rows, pc, length, flags=5):
    found = [p for p in rows if p[0] == 1 and p[3] <= pc and pc + length <= p[3] + p[5]]
    assert len(found) == 1 and found[0][1] == flags
    at = found[0][2] + pc - found[0][3]
    return at, data[at:at + length]

def prepare(name, original, target, provenance):
    entry, rows = elf(original)
    assert entry == 0x401000
    loads = [p for p in rows if p[0] == 1]
    assert [(p[3], p[5], p[6], p[1]) for p in loads] == [
        (0x400000, 4096, 4096, 4), (0x401000, 12288, 12288, 5),
        (0x404000, 335872, 335872, 6)]
    assert len([p for p in rows if p[0] == 4]) == 1, 'original PT_NOTE retained for E9'
    heads = instructions(name)
    code = b''.join(h['code'] for h in heads)
    assert owned(original, rows, BASE, len(code))[1] == code
    assert owned(original, rows, HOOK, 1)[1] == b'\xc3'
    assert all(h['target'] is None or h['target'] in {v['pc'] for v in heads} for h in heads)
    selected = [h for h in heads if h['target'] is not None]
    assert 0 < len(selected) <= 32
    # The unchanged public renderer validates the complete target grammar before
    # this call. The complete record is retained, never replaced with fxsave.
    assert target.startswith('target xsave64 ') and target.endswith('\n') and target.count('\n') == 1
    common = ['LI2TOOL 1', 'original ' + sha(original), target.rstrip(),
              'domain 1', 'carrier 0x480000',
              'limits 1048576 32 32 131072 128 2097152 1048576 128 16777216',
              f'hook 1 {HOOK} 1 {sha(bytes([0xc3]))}']
    leaders = {BASE}
    end = BASE + len(code)
    for h in heads:
        if h['target'] is not None:
            leaders.update((h['target'], h['pc'] + len(h['code'])))
        if h['code'] == b'\xc3':
            leaders.add(h['pc'] + 1)
    for sid, h in enumerate(selected, 1):
        pc, size = h['pc'], len(h['code'])
        start = max(x for x in leaders if x <= pc)
        finish = min(x for x in leaders | {end} if x > pc)
        offset = owned(original, rows, pc, size)[0]
        address = 0x500000 + (sid - 1) * 4096
        common += [f'site {sid} {pc} {size} {offset} {BASE} {len(code)} {BASE} {len(code)} {start} {finish-start} 1 observe original-decode',
                   f'entries {sid} complete {provenance} ' + ' '.join(f'{v["pc"]}:0' for v in heads),
                   f'resumes {sid} none', f'search {sid} B1 0 {size} 1 none 0 0',
                   f'allocation {sid} selected {address} 1 4096 {address}:4096',
                   f'allocation {sid} victim none 0 4096 {address}:4096']
    return ('\n'.join(common) + '\n').encode(), heads, selected

def relative(op, pc, target):
    return op + struct.pack('<i', target - pc - len(op) - 4)

def branch_bytes(head, pc):
    old = head['code']
    assert old[0] == 0xe9 and len(old) == 5 or old[0] == 0x0f and len(old) == 6
    return relative(old[:-4], pc, head['target'])

def core_witness(original, selection, directory, selected):
    d = Path(directory); marker = read(d / 'COMPLETE').decode().splitlines()
    index = read(d / 'bundle-index.tsv')
    assert marker == ['LI2TOOL-DIRECTORY 1', 'index_sha256 ' + sha(index),
                      'candidate_complete true', 'qualification_complete false']
    lines = index.decode().splitlines()
    assert lines[:4] == ['LI2BUNDLE\t1', 'original_sha256\t' + sha(original),
                         'qualification_complete\tfalse', 'consumer_action\tRuntimeScan-while-gated-until-qualified']
    files = {}
    for line in lines[4:]:
        tag, name, count, digest = line.split('\t')
        assert tag == 'file' and Path(name).name == name and name not in files
        files[name] = read(d / name)
        assert len(files[name]) == int(count) and sha(files[name]) == digest
    assert {p.name for p in d.iterdir()} == set(files) | {'bundle-index.tsv', 'COMPLETE'}
    assert files['selection.txt'] == selection
    report = files['report.tsv'].decode().splitlines()
    assert report[:5] == ['LI2REPORT\t1', 'original_sha256\t' + sha(original),
                          'selection_sha256\t' + sha(selection), 'candidate_complete\ttrue', 'qualification_complete\tfalse']
    rows = list(csv.DictReader(io.StringIO('\n'.join(report[5:]) + '\n'), delimiter='\t'))
    assert len(rows) == len(selected)
    candidate = files['candidate.elf']; entry, segments = elf(candidate)
    assert entry == elf(original)[0] and len(candidate) >= len(original)
    ledger = [r.split('\t') for r in files['plan-ledger.tsv'].decode().splitlines()]
    assert ledger[:3] == [['LI2LEDGER', '1'], ['original_sha256', sha(original)], ['selection_sha256', sha(selection)]]
    assert not any(r[0] in ('entry-router-required', 'live-store-span') for r in ledger)
    steps = [r for r in ledger if r[0] == 'step']
    images = [r for r in ledger if r[0] == 'image']
    assert len(steps) == len(images) == len(selected)
    overlay = bytearray(original)
    for sid, (head, row) in enumerate(zip(selected, rows), 1):
        assert int(row['site']) == sid and int(row['pc']) == head['pc']
        assert int(row['length']) == len(head['code']) and row['candidate_emitted'] == 'true'
        assert row['core_tactic'] == 'B1' and row['refusal_code'] == 'none'
        step = [r for r in steps if r[1] == str(sid)]
        assert step == [['step', str(sid), '0', 'relocation', str(head['pc']), str(head['pc']), str(head['pc']), str(head['pc'] + len(head['code']))]]
        image = [r for r in images if r[2] == str(sid)]
        assert len(image) == 1
        _, image_id, _, at, count, digest, filename = image[0]
        at = int(at); code = files[filename]
        assert at == 0x500000 + (sid - 1) * 4096 and len(code) == int(count) <= 4096 and sha(code) == digest
        assert owned(candidate, segments, at, len(code))[1] == code
        original_at = int(row['file_offset'])
        assert original_at == owned(original, elf(original)[1], head['pc'], len(head['code']))[0]
        patch = relative(b'\xe9', head['pc'], at)
        assert owned(candidate, segments, head['pc'], 5)[1] == patch
        overlay[original_at:original_at + 5] = patch
        boundaries = [r for r in ledger if r[:3] == ['restored-boundary', image_id, str(head['pc'])]]
        assert len(boundaries) == 1
        body = int(boundaries[0][3]); expected = branch_bytes(head, body)
        restored_extent = len(expected) + (5 if head['code'][0] == 0x0f else 0)
        assert at <= body and body + restored_extent <= at + len(code), 'whole restored branch and continuation belong to selected image'
        assert owned(candidate, segments, body, len(expected))[1] == expected, 'exact branch condition and target'
        # The taken branch and, for Jcc, the original fall-through remain exact.
        if head['code'][0] == 0x0f:
            tail = relative(b'\xe9', body + len(expected), head['pc'] + len(head['code']))
            assert owned(candidate, segments, body + len(expected), 5)[1] == tail
    overlay[32:40] = candidate[32:40]; overlay[56:58] = candidate[56:58]
    assert candidate[:len(original)] == overlay, 'all nonselected original bytes including I/O/hook/data/stack'
    return dict(selected=len(selected), full_original_overlay=True, relocated_branch_bytes=True,
                architectural_full_state=False, qualification_complete=False)

def core_refusal(original, selection, directory, selected):
    d=Path(directory); index=read(d/'bundle-index.tsv')
    assert read(d/'COMPLETE').decode().splitlines()==['LI2TOOL-DIRECTORY 1',
        'index_sha256 '+sha(index),'candidate_complete false','qualification_complete false']
    lines=index.decode().splitlines()
    assert lines[:4]==['LI2BUNDLE\t1','original_sha256\t'+sha(original),
        'qualification_complete\tfalse','consumer_action\tRuntimeScan-while-gated-until-qualified']
    names=set()
    for line in lines[4:]:
        tag,name,count,digest=line.split('\t')
        assert tag=='file' and Path(name).name==name and name not in names
        value=read(d/name);assert len(value)==int(count) and sha(value)==digest;names.add(name)
    assert {p.name for p in d.iterdir()}==names|{'bundle-index.tsv','COMPLETE'}
    assert 'candidate.elf' not in names and read(d/'selection.txt')==selection
    report=read(d/'report.tsv').decode().splitlines()
    assert report[:5]==['LI2REPORT\t1','original_sha256\t'+sha(original),
        'selection_sha256\t'+sha(selection),'candidate_complete\tfalse','qualification_complete\tfalse']
    rows=list(csv.DictReader(io.StringIO('\n'.join(report[5:])+'\n'),delimiter='\t'))
    assert [(int(r['site']),int(r['pc']),int(r['length'])) for r in rows]==[
        (i,h['pc'],len(h['code'])) for i,h in enumerate(selected,1)]
    assert all(r['candidate_emitted']=='false' for r in rows)
    assert any(r['refusal_code']!='none' for r in rows)

def e9_witness(original, candidate, binding, selected):
    # binding is the complete output of unchanged e9-sites.py, after its strict
    # RPC, source-byte, loader, mapping, debug, statistics, and receipt checks.
    assert binding['candidate_sha256'] == sha(candidate)
    assert binding['selected_sites'] == len(selected)
    outcomes = {r['pc']: r for r in binding['outcomes']}
    assert set(outcomes) == {h['pc'] for h in selected}
    segments = elf(original)[1]
    maps = binding['ownership']['mappings']
    def view(pc, count):
        matches = [m for m in maps if m['va'] <= pc and pc + count <= m['va'] + m['length']]
        assert len(matches) <= 1
        if matches:
            m = matches[0]; assert m['prot'] & 4 and not m['prot'] & 2
            start = m['offset'] + pc - m['va']
            return candidate[start:start + count]
        start = owned(original, segments, pc, count)[0]
        return candidate[start:start + count]
    for h in selected:
        row = outcomes[h['pc']]
        assert row['tactic'] == 'B1', 'this finite long-branch corpus requires actual B1, no reduced-site fallback'
        low, high = row['low'], row['high']
        assert view(h['pc'], 5) == relative(b'\xe9', h['pc'], low)
        op = branch_bytes(h, low)
        assert view(low, len(op)) == op
        assert high == low + len(op) + 5
        tail = view(low + len(op), 5)
        assert tail[0] == 0xe9
        destination = low + len(op) + 5 + struct.unpack_from('<i', tail, 1)[0]
        logical = h['pc'] + len(h['code'])
        # E9's continuation may bypass an already rewritten next source head.
        # Authenticate the complete fixed stateless chain; no state repair.
        seen = set(); cursor = logical
        for _ in range(4):
            if cursor == destination:
                break
            assert cursor not in seen and cursor in outcomes
            seen.add(cursor); gateway = view(cursor, 5)
            assert gateway[0] == 0xe9
            cursor += 5 + struct.unpack_from('<i', gateway, 1)[0]
        assert cursor == destination
    return dict(selected=len(selected), exact_null_extents=True, relocated_branch_bytes=True,
                architectural_full_state=False, qualification_complete=False)
