"""Bounded receipt parsing and constant rows; no decoding, placement or execution."""
import hashlib
import json
import re

M = 1024**2


def complete(directory, read):
    raw = read(directory/'COMPLETE', cap=M); lines = raw.decode().splitlines()
    assert raw.endswith(b'\n') and lines[0] in ('LI2FULL-PROGRAM-MATERIALS\t1', 'LI2FULL-PROGRAM-POLICY\t1', 'LI2DISASSEMBLY-DIRECTORY\t1')
    fields, files, inputs = {}, {}, {}
    for line in lines[1:]:
        row = line.split('\t')
        if row[0] in ('file', 'input'):
            assert len(row) == 4 and row[2].isdigit() and re.fullmatch('[0-9a-f]{64}', row[3])
            target = files if row[0] == 'file' else inputs
            assert row[1] not in target and re.fullmatch('[A-Za-z0-9_.-]+', row[1]) and row[1] not in ('.', '..', 'COMPLETE')
            target[row[1]] = dict(bytes=int(row[2]), sha256=row[3])
        else:
            assert len(row) == 2 and row[0] not in fields; fields[row[0]] = row[1]
    assert {p.name for p in directory.iterdir()} == set(files) | {'COMPLETE'}
    assert all(p.is_file() and not p.is_symlink() for p in directory.iterdir())
    for name, expected in files.items(): read(directory/name, expected, cap=64*M)
    assert fields['qualification_complete'] == 'false'
    return dict(header=lines[0], fields=fields, files=files, inputs=inputs)


STACK_PROFILE = 'jumps-gpr-stack64-v1'


def stack_counts(sites):
    assert all(len(row) == 9 and row[8] in ('jump', 'push-r64', 'pop-r64') for row in sites)
    return dict(selection_profile=STACK_PROFILE, complete_site_count=len(sites),
                jump_count=sum(row[8] == 'jump' for row in sites),
                push_r64_count=sum(row[8] == 'push-r64' for row in sites),
                pop_r64_count=sum(row[8] == 'pop-r64' for row in sites))


def stack_complete(fields, sites):
    assert all(fields.get(key) == str(value) for key, value in stack_counts(sites).items())


def _stack_inventory(raw, original_sha, ledger_sha):
    lines = raw.decode().splitlines()
    assert raw.endswith(b'\n') and lines[0] == 'LI2DISASSEMBLY-INVENTORY\t1'
    header = 'id\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length\tclass'
    index = lines.index(header)
    fields = {}
    for line in lines[1:index]:
        row = line.split('\t'); assert len(row) == 2 and row[0] not in fields
        fields[row[0]] = row[1]
    assert set(fields) == {'profile', 'selection_status', 'original_sha256', 'ledger_sha256',
                           'complete_head_count', 'complete_site_count', 'jump_count',
                           'push_r64_count', 'pop_r64_count', 'qualification_complete'}
    assert fields['profile'] == STACK_PROFILE and fields['selection_status'] == 'classified-unbound'
    assert fields['original_sha256'] == original_sha and fields['ledger_sha256'] == ledger_sha
    assert fields['qualification_complete'] == 'false'
    for key in ('complete_head_count', 'complete_site_count', 'jump_count', 'push_r64_count', 'pop_r64_count'):
        assert re.fullmatch(r'0|[1-9][0-9]*', fields[key])
    rows = []
    for line in lines[index+1:]:
        row = line.split('\t')
        assert len(row) == 9 and all(re.fullmatch(r'0|[1-9][0-9]*', v) for v in row[:8])
        rows.append([*map(int, row[:8]), row[8]])
    counts = stack_counts(rows)
    assert all(fields[key] == str(value) for key, value in counts.items() if key != 'selection_profile')
    assert int(fields['complete_head_count']) >= len(rows)
    assert [row[0] for row in rows] == list(range(1, len(rows)+1))
    assert all(1 <= row[2] <= 15 and row[5] > 0 and row[7] > 0
               and row[4] <= row[6] <= row[1] < row[1]+row[2] <= row[6]+row[7] <= row[4]+row[5] for row in rows)
    assert all(a[1] < b[1] for a, b in zip(rows, rows[1:]))
    assert len({row[3] for row in rows}) == len(rows)
    # Do not cap or truncate this unbound denominator: later material/policy
    # refusal must still retain every requested row, even above whole limits.
    return rows


def inventory(raw, original_sha, ledger_sha, *, selection_profile=None):
    if selection_profile is not None:
        assert selection_profile == STACK_PROFILE
        return _stack_inventory(raw, original_sha, ledger_sha)
    lines = raw.decode().splitlines(); assert raw.endswith(b'\n') and lines[0] == 'LI2DISASSEMBLY-INVENTORY\t1'
    header = 'id\tpc\tlength\tfile_offset\tregion_pc\tregion_length\tblock_pc\tblock_length'
    index = lines.index(header); fields = dict(line.split('\t') for line in lines[1:index])
    assert fields['original_sha256'] == original_sha and fields['ledger_sha256'] == ledger_sha and fields['qualification_complete'] == 'false'
    assert fields['profile'] == 'elf-disassembly-null-jumps-shared-4096-v1'
    rows = [list(map(int, line.split('\t'))) for line in lines[index+1:]]
    assert len(rows) == int(fields['complete_jump_count']) and all(len(row) == 8 and all(n >= 0 for n in row) and 1 <= row[2] <= 15 for row in rows)
    assert len({row[0] for row in rows}) == len(rows) and len({row[1] for row in rows}) == len(rows) and len({row[3] for row in rows}) == len(rows)
    return rows


def uniform_rows(sites):
    rows = []
    for site in sites:
        rows.extend([f'search {site[0]} preferred 64 256 64 none 256 4096',
                     f'allocation {site[0]} selected none 1 4096 16777216:520093696',
                     f'allocation {site[0]} victim none 1 4096 16777216:520093696'])
    assert len(rows) == 3*len(sites)
    return ('\n'.join(rows)+'\n').encode()


def rpc(raw, original, sites):
    def unique(pairs):
        result = {}
        for k, v in pairs: assert k not in result; result[k] = v
        return result
    assert len(raw) <= 16*M and raw.endswith(b'\n')
    rows = [json.loads(line, object_pairs_hook=unique) for line in raw.splitlines()]
    assert 3 < len(rows) <= 32768 and 0 < len(sites) <= 4096
    for i, row in enumerate(rows): assert set(row) == {'jsonrpc', 'method', 'params', 'id'} and row['jsonrpc'] == '2.0' and type(row['id']) is int and row['id'] == i
    assert rows[0]['method'] == 'binary' and rows[0]['params'] == dict(filename=str(original), mode='exe')
    assert rows[1]['method'] == 'trampoline' and rows[1]['params'] == dict(name='passthru', template=['$instruction', '$continue'])
    assert rows[-1]['method'] == 'emit' and rows[-1]['params'] == dict(filename='a.out', format='binary', mapping_size=4096)
    number = lambda v: v if type(v) is int else int(v, 16)
    heads, patches = {}, []
    for row in rows[2:-1]:
        p = row['params']
        if row['method'] == 'instruction':
            assert set(p) == {'address', 'length', 'offset'}
            pc, length, offset = map(number, (p['address'], p['length'], p['offset']))
            assert offset not in heads and 1 <= length <= 15 and pc >= 0 and offset >= 0
            heads[offset] = (pc, length)
        else:
            assert row['method'] == 'patch' and set(p) == {'trampoline', 'offset'} and p['trampoline'] == 'passthru'
            offset = number(p['offset']); assert offset in heads
            patches.append((offset, *heads[offset]))
    expected = [(s[3], s[1], s[2]) for s in reversed(sites)]
    assert patches == expected and len(set(patches)) == len(sites) and len(heads) <= 16384
    return dict(messages=len(rows), instruction_contexts=len(heads), requested=len(sites), ordered_patches=patches)


def li2_report(raw, sites, original_sha, complete):
    lines = raw.decode().splitlines(); assert raw.endswith(b'\n') and lines[0] == 'LI2REPORT\t1'
    index = next(i for i, line in enumerate(lines) if line.startswith('site\tpc\t'))
    fields = dict(line.split('\t') for line in lines[1:index]); names = lines[index].split('\t')
    assert fields['original_sha256'] == original_sha and fields['candidate_complete'] == str(complete).lower()
    records = [dict(zip(names, line.split('\t'))) for line in lines[index+1:]]
    assert all(len(line.split('\t')) == len(names) for line in lines[index+1:]) and len(records) == len(sites)
    for record, site in zip(records, sites):
        assert [int(record[k]) for k in ('site', 'pc', 'length', 'file_offset')] == [site[0], site[1], site[2], site[3]]
        assert record['candidate_emitted'] in ('true', 'false')
    emitted = sum(row['candidate_emitted'] == 'true' for row in records)
    assert emitted == (len(sites) if complete else 0)
    return dict(requested=len(sites), emitted=emitted, strict_full=complete, rows=records)


def e9_statistics(raw, info, original, size, output_size):
    n = info['requested']
    def one(pattern):
        found = re.findall(pattern, raw, re.MULTILINE); assert len(found) == 1; return found[0]
    total = tuple(map(int, one(rb'^num_patched + = ([0-9]+) / ([0-9]+) \((?:[0-9]+\.[0-9]{2}|~100\.00)%\)$')))
    assert total[1] == n and 0 <= total[0] <= n
    if total[0] == n: assert one(rb'^num_patched + = ([0-9]+) / ([0-9]+) \(100\.00%\)$') == (str(n).encode(), str(n).encode())
    tactics = {}
    for name in ('B1', 'B2', 'T1', 'T2', 'T3'):
        count, denominator = map(int, one(rb'^num_patched_'+name.encode()+rb' + = ([0-9]+) / ([0-9]+) \([0-9]+\.[0-9]{2}%\)$'))
        assert denominator == n; tactics[name] = count
    address = rb'(?:\[absolute\] )?-?0x[0-9a-f]+'
    success = list(re.finditer(rb'debug: patched instruction 0x([0-9a-f]+) \[size=([0-9]+), tactic=(B1|B2|T1|T2|T3), trampoline='+address+rb'\.\.'+address+rb'\]', raw))
    failure = list(re.finditer(rb'debug: failed to patch instruction at address 0x([0-9a-f]+) \(([0-9]+)\)', raw))
    assert raw.count(b'debug: patched instruction ') == len(success) == total[0] == sum(tactics.values())
    assert raw.count(b'debug: failed to patch instruction') == len(failure) == n-total[0]
    assert {k: sum(m[3].decode() == k for m in success) for k in tactics} == tactics
    events = [(m.start(), int(m[1], 16), int(m[2]), m[3].decode()) for m in success]
    events += [(m.start(), int(m[1], 16), int(m[2]), 'FAILED') for m in failure]
    outcomes = [(pc, length, tactic) for _, pc, length, tactic in sorted(events)]
    assert [(pc, length) for pc, length, _ in outcomes] == [(pc, length) for _, pc, length in info['ordered_patches']]
    assert one(rb'^input_binary + = (.+)$') == str(original).encode() and one(rb'^input_mode + = (.+)$') == b'EXECUTABLE'
    assert int(one(rb'^input_file_size + = ([0-9]+)$')) == size
    assert int(one(rb'^output_file_size + = ([0-9]+) \([0-9]+\.[0-9]{2}%\)$')) == output_size
    return dict(requested=n, successful=total[0], failed=n-total[0], strict_full=total[0] == n, tactics=tactics, ordered_outcomes=outcomes)
