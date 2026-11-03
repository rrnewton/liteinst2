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
    if fields.get('ledger_storage') == 'read-chunks256-v1':
        assert sum(files.get(name, {}).get('bytes', 0) for name in ('plan-ledger.tsv', 'ledger.tsv', 'read-chunks.tsv')) <= 128*M
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


GROUPED_PROFILE = 'jumps-gpr-stack64-block-observation-v1'
GROUPED_UPSTREAM_PROFILE = 'jumps-gpr-stack64-block-upstream-v1'
GROUPED_MIN5_PROFILE = 'jumps-gpr-stack64-block-min5-upstream-v1'
GROUPED_MIN5_ALPHABET_PROFILE = 'jumps-gpr-stack64-block-min5-alphabet-upstream-v1'
GROUPED_PHYSICAL_PROFILE = 'jumps-gpr-stack64-block-physical-min5-alphabet-upstream-v1'
GROUPED_SUFFIX60_PROFILE = 'jumps-gpr-stack64-block-physical-min5-alphabet-suffix60-upstream-v1'
# (upstream physical search, immutable min5 seal, grouping version, explicit placement)
# Storage is independent; legacy descriptors preserve their exact text contracts.
GROUPED_DESCRIPTORS = {
    GROUPED_PROFILE: (False, False, '1', None),
    GROUPED_UPSTREAM_PROFILE: (True, False, '1', None),
    GROUPED_MIN5_PROFILE: (True, True, '2', None),
    GROUPED_MIN5_ALPHABET_PROFILE: (True, True, '3', 'entry-alphabet-v1'),
    GROUPED_PHYSICAL_PROFILE: (True, False, '4', 'entry-alphabet-v1'),
    GROUPED_SUFFIX60_PROFILE: (True, False, '5', 'entry-alphabet-v1'),
}
GROUPED_PROFILES = tuple(GROUPED_DESCRIPTORS)
GROUPED_MEMBERS = ('grouping-policy.tsv', 'selection.txt', 'binding-policy.tsv',
                   'plan-ledger.tsv', 'ledger.tsv', 'report.tsv', 'disassembly.txt')


def grouped_binding_bytes(selection, original, domain, grouping, *, profile=GROUPED_PROFILE):
    assert profile in GROUPED_PROFILES
    rows = [('planner_profile', profile),
            ('singleton_planner_profile', 'whole-program-packed-overlapping-neighbors-4096'),
            ('address_binding', 'fixed-exec-zero-bias-indexed-jump32-v1'),
            ('required_object_type', 'ET_EXEC'), ('required_load_bias', '0'),
            ('fixed_binding_qualification', 'unresolved-runtime-loader-obligation'),
            ('selection_sha256', selection), ('source_sha256', original),
            ('mapping', str(domain)), ('generation', '1'), ('domain', str(domain)),
            ('field_encoding', 'original-indexed-jump-signed32-v1'),
            ('grouped_profile', profile), ('grouping_policy_sha256', grouping)]
    if profile == GROUPED_SUFFIX60_PROFILE: rows.append(('group_routed_suffix', 'single-byte60-v1'))
    return ('LI2FIXED-EXEC-BINDING\t1\n'+''.join(k+'\t'+v+'\n' for k, v in rows)).encode()


def grouped_source_heads(raw, original, sites, numeric, *, encoded_bytes=None):
    """Interpret already source-pinned head lengths, without decoding code."""
    source = raw.decode().splitlines()
    assert source[0] == 'LI2DISASM 1' and source.count('original '+original) == 1
    heads = {}
    for line in source:
        if line.startswith('head '):
            match = re.fullmatch(r'head ([0-9]+) ([0-9a-f]+)', line); assert match
            pc, encoded = numeric(match[1]), match[2]
            assert pc not in heads and len(encoded) % 2 == 0 and 1 <= len(encoded)//2 <= 15
            heads[pc] = len(encoded)//2
            if encoded_bytes is not None: encoded_bytes[pc] = bytes.fromhex(encoded)
    assert len(heads) <= 16384 and all(heads[s[1]] == s[2] for s in sites)
    return heads


def grouped_min5_seals(policy, units, sites, heads, numeric):
    """Check exact original geometry; refused seals are not semantic proofs."""
    seals = {}
    for row in policy:
        if row[0] != 'window-seal': continue
        assert len(row) == 7
        unit = numeric(row[1])
        assert unit < len(units) and unit not in seals and len(units[unit]) > 1
        population = units[unit]
        start, selected_end = population[0][1], population[-1][1]+population[-1][2]
        if row[2] == 'ready':
            assert row[4:] == ['-', '-', '-']
            assert all(s[6:8] == population[0][6:8] for s in population)
            block_start, block_length = population[0][6:8]
            end = start; visited = []
            while end < selected_end or end-start < 5:
                assert end in heads
                visited.append(end)
                end += heads[end]
                assert end <= block_start+block_length and end-start <= 256
            assert start >= block_start and end >= selected_end
            assert visited == sorted(pc for pc in heads if start <= pc < end)
            assert all(site[1] in visited for site in population)
            assert numeric(row[3]) == end
            floor = max(block_start, max(0, start-64))
            # The immutable full manifest includes accepted and straddling rows.
            for left in (start, floor):
                assert population == [s for s in sites if s[1] < end and left < s[1]+s[2]]
                assert all(left <= s[1] < s[1]+s[2] <= end for s in population)
        else:
            assert row[2] == 'refused' and row[3] == '-'
            assert numeric(row[4]) > 0 and row[5] not in ('', '-', 'none', 'atomic-selection', 'carrier')
            assert re.fullmatch(r'(?:[0-9a-f]{2})*', row[6])
        seals[unit] = row
    assert set(seals) == {unit for unit, population in enumerate(units) if len(population) > 1}
    return seals


def grouped_physical_seals(policy, units, sites, heads, encoded, numeric):
    """Policy4 geometry only. Typed qualification and current reads stay in Rust."""
    tags = {'unit-preflight', 'window-domain', 'window-source', 'physical-window'}
    extra = {unit: [] for unit, population in enumerate(units) if len(population) > 1}
    for row in policy:
        if row[0] not in tags: continue
        assert len(row) > 1
        unit = numeric(row[1]); assert unit in extra
        extra[unit].append(row)
    def refusal(code, stage, detail):
        assert numeric(code) > 0 and stage not in ('', '-', 'none', 'atomic-selection', 'carrier')
        assert re.fullmatch(r'(?:[0-9a-f]{2})*', detail)
        bytes.fromhex(detail).decode('utf-8')
    for unit, rows in extra.items():
        assert rows
        if rows[0][0] == 'unit-preflight':
            assert len(rows) == 1 and len(rows[0]) == 6 and rows[0][2] == 'refused'
            refusal(*rows[0][3:]); continue
        population = units[unit]
        start, last = population[0][1], population[-1][1]
        selected_end = last + population[-1][2]
        block, block_len = population[0][6:8]; block_end = block + block_len
        assert 0 <= block <= start <= last < selected_end <= block_end <= 2**64-1
        assert all(s[6:8] == [block, block_len] for s in population)
        floor = max(block, max(0, start-64))
        domain = sorted((pc for pc in heads if floor <= pc <= start),
                        key=lambda pc: (pc != start, pc % 64 > 56, start-pc))
        total, sealed = len(domain), min(len(domain), 64)
        assert 1 <= total <= 65 and domain[0] == start
        assert rows[0] == ['window-domain', str(unit), str(total), str(sealed), str(total-sealed)]
        assert len(rows) == sealed+2 and len(rows[1]) == 5 and rows[1][:2] == ['window-source', str(unit)]
        examined, ready_ends = set(), [selected_end]
        for ordinal, pc in enumerate(domain[:sealed]):
            row = rows[ordinal+2]
            assert len(row) == 9 and row[:4] == ['physical-window', str(unit), str(ordinal), str(pc)]
            # Mirror only lengths and the collector's bounds/stop geometry, not
            # instruction qualification. Include a cap-crossing/start instruction.
            cursor, valid, visited = pc, True, []
            while cursor < block_end:
                assert cursor in heads
                visited.append(cursor)
                examined.add(cursor)
                cursor += heads[cursor]
                if cursor > block_end or cursor-pc > 256:
                    valid = False; break
                if cursor-pc >= 5 and cursor > last: break
            valid = valid and cursor-pc >= 5 and cursor > last
            if row[4] == 'ready':
                assert valid and row[5:] == [str(cursor), '-', '-', '-']
                assert visited == sorted(head for head in heads if pc <= head < cursor)
                assert all(site[1] in visited for site in population)
                ready_ends.append(cursor)
                assert population == [s for s in sites if s[1] < cursor and pc < s[1]+s[2]]
                assert all(pc <= s[1] < s[1]+s[2] <= cursor for s in population)
            else:
                assert row[4] == 'refused' and row[5] == '-' and row[7] == 'core'
                refusal(*row[6:])
        end = max(ready_ends)
        assert population == [s for s in sites if s[1] < end and floor < s[1]+s[2]]
        assert all(floor <= s[1] < s[1]+s[2] <= end for s in population)
        left, right = min(examined), max(pc+heads[pc] for pc in examined)
        assert 0 < right-left <= 335
        data, cursor = bytearray(), left
        while cursor < right:
            assert cursor in encoded and len(encoded[cursor]) == heads[cursor]
            data.extend(encoded[cursor]); cursor += heads[cursor]
        assert cursor == right
        assert rows[1] == ['window-source', str(unit), str(left), str(right), hashlib.sha256(data).hexdigest()]
    return extra


def grouped_physical_ordinal(rows, physical, end):
    found = [int(row[2]) for row in rows if row[0] == 'physical-window'
             and row[3:6] == [str(physical), 'ready', str(end)]]
    assert len(found) == 1
    return found[0]


def grouped_linkage(info, members, sites, original, domain, report, *, source_ledger, profile=GROUPED_PROFILE, ledger_storage="inline"):
    """Join a full policy partition to unique local plans and final site outcomes.

    All members are pinned by COMPLETE first. This parses text records only;
    portable/embedded binary checks use the producer's existing Rust format API.
    Accepted units are local-plan evidence, never candidate-emission authority.
    """
    assert profile in GROUPED_PROFILES
    upstream, min5, policy_version, placement = GROUPED_DESCRIPTORS[profile]
    suffix60 = profile == GROUPED_SUFFIX60_PROFILE
    physical_windows = profile in (GROUPED_PHYSICAL_PROFILE, GROUPED_SUFFIX60_PROFILE)
    assert ledger_storage in ('inline', CHUNK_STORAGE)
    compact = ledger_storage == CHUNK_STORAGE
    required = set(GROUPED_MEMBERS) | (set(CHUNK_MEMBERS) if compact else set())
    assert set(members) == required and 0 < len(sites) <= 4096
    for name, raw in members.items():
        assert raw.endswith(b'\n') and len(raw) <= 64*M
        assert info['files'][name] == dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    # Output self-pins do not prove which independently frozen input was read.
    assert info['files']['disassembly.txt'] == {k: source_ledger[k] for k in ('bytes', 'sha256')}
    storage_result = chunk_storage(info, members, original) if compact else None
    fields = info['fields']; stack_complete(fields, sites)
    expected_fields = dict(profile=profile, planner_profile=profile,
        grouped_profile=profile, singleton_planner_profile='whole-program-packed-overlapping-neighbors-4096',
        grouping_policy='grouping-policy.tsv', grouping_ledger='LI2GROUPED-LEDGER-2' if compact else 'LI2GROUPED-LEDGER-1',
        portable_metadata_verification='checked',
        embedded_metadata_binding='checked' if report['strict_full'] else 'not-complete')
    if min5:
        expected_fields.update(grouping_policy_version=policy_version, window_sealing='minimum-whole-instruction-v1')
    if physical_windows:
        expected_fields.update(grouping_policy_version=policy_version, window_sealing='physical-minimum-whole-instruction-v1')
    if suffix60: expected_fields['group_routed_suffix'] = 'single-byte60-v1'
    if placement is not None: expected_fields['group_relocation_placement'] = placement
    assert all(fields.get(k) == v for k, v in expected_fields.items())
    assert all(name in info['files'] for name in ('metadata.li2meta', 'target.tsv', 'planning-profile.tsv'))
    selection = info['files']['selection.txt']['sha256']
    grouping = info['files']['grouping-policy.tsv']['sha256']
    assert members['binding-policy.tsv'] == grouped_binding_bytes(selection, original, domain, grouping, profile=profile)
    number = lambda value: int(value) if re.fullmatch(r'0|[1-9][0-9]*', value) else None
    def numeric(value):
        result = number(value); assert result is not None; return result
    def rows(name):
        table = [line.split('\t') for line in members[name].decode().splitlines()]
        if compact and name in ('plan-ledger.tsv', 'ledger.tsv'):
            # Rust's authenticated bounded codec owns chunk interpretation.
            # Only its declared representation rows are hidden for the same
            # existing structural consumer; unknown semantic rows stay visible.
            assert table[0] == ['LI2GROUPED-LEDGER', '2']
            table[0] = ['LI2GROUPED-LEDGER', '1']
            table = [row for row in table if row[0] not in ('read-storage', 'step-reads', 'step-read-ref')]
        return table
    def one(table, tag):
        found = [row for row in table if row[0] == tag]; assert len(found) == 1; return found[0]

    # Verify the declared block partition. No code decoding or placement occurs.
    blocks = {}
    for site in sites: blocks.setdefault((site[6], site[7]), []).append(site)
    groups = sorted((v for v in blocks.values() if len(v) > 1), key=lambda v: -v[0][1])
    singles = sorted((v for v in blocks.values() if len(v) == 1), key=lambda v: -v[0][1])
    units = groups + singles
    policy = rows('grouping-policy.tsv')
    if physical_windows:
        assert members['grouping-policy.tsv'] == ('\n'.join('\t'.join(row) for row in policy)+'\n').encode('utf-8')
    # Only this distinct profile needs head geometry before policy comparison.
    # Legacy profiles retain the original parser invocation/error order below.
    heads = grouped_source_heads(members['disassembly.txt'], original, sites, numeric) if min5 else None
    seals = grouped_min5_seals(policy, units, sites, heads, numeric) if min5 else {}
    physical_seals = {}
    if physical_windows:
        encoded = {}
        heads = grouped_source_heads(members['disassembly.txt'], original, sites, numeric, encoded_bytes=encoded)
        physical_seals = grouped_physical_seals(policy, units, sites, heads, encoded, numeric)
    prefix = [
        ['LI2GROUPING-POLICY', '1'], ['profile', profile],
        ['schedule', 'all-multisite-blocks-descending-then-singletons-descending-v1'],
        ['window', 'first-selected-head-through-last-selected-instruction'],
        ['group_tactic', 'RelocationOnly'], ['group_attempts', '1'], ['group_fallback', 'none'],
        ['member_budgets', 'shared-not-summed'], ['entry_completeness', 'AllInstructionHeads'],
        ['singleton_profile', 'whole-program-packed-overlapping-neighbors-4096'],
        ['qualification_complete', 'false'], ['original_sha256', original],
        ['selection_sha256', selection], ['complete_site_count', str(len(sites))]]
    if min5:
        prefix[0] = ['LI2GROUPING-POLICY', policy_version]
        at = prefix.index(['window', 'first-selected-head-through-last-selected-instruction'])
        prefix[at:at+1] = [
            ['window', 'minimum-whole-instruction-through-last-selected-min5-v1'],
            ['seal_source', 'immutable-original'], ['seal_stage', 'before-overlay-mutation']]
    if placement is not None:
        if physical_windows:
            prefix[0] = ['LI2GROUPING-POLICY', policy_version]
            at = prefix.index(['window', 'first-selected-head-through-last-selected-instruction'])
            prefix[at:at+1] = [['window', 'per-physical-minimum-whole-instruction-v1'],
                ['seal_source', 'immutable-original'], ['seal_stage', 'before-overlay-mutation']]
        at = prefix.index(['seal_stage', 'before-overlay-mutation']) + 1
        prefix.insert(at, ['group_relocation_placement', placement])
        if physical_windows:
            prefix.insert(at+1, ['source_dependency', 'collector-examined-instruction-envelope-v1'])
        if suffix60: prefix.insert(at+1, ['group_routed_suffix', 'single-byte60-v1'])
    if upstream:
        at = prefix.index(['group_attempts', '1'])
        prefix[at:at+1] = [
            ['physical_schedule', 'same-site-then-single-cache-line-then-nearest-upstream-v1'],
            ['max_physical_sites', '64'], ['max_upstream_bytes', '64'],
            ['max_displaced_bytes', '256'], ['image_candidates_per_physical', '1'],
            ['image_mappings_per_physical', '1'], ['image_bytes_per_physical', '4096'],
            ['physical_domain', 'same-block-heads-through-first-member'],
            ['membership', 'full-manifest-maximum-prefix-and-actual-window']]
    expected_policy = list(prefix)
    member_rows = {}
    for unit, population in enumerate(units):
        start, end = population[0][1], population[-1][1]+population[-1][2]
        assert population == [s for s in sites if s[1] < end and start < s[1]+s[2]]
        assert all(start <= s[1] < s[1]+s[2] <= end for s in population)
        kind = 'group' if len(population) > 1 else 'singleton'
        expected_policy.append(['unit', str(unit), kind, str(start), str(end), str(len(population))])
        if min5 and kind == 'group': expected_policy.append(seals[unit])
        if physical_windows and kind == 'group': expected_policy.extend(physical_seals[unit])
        member_rows[unit] = [['member', str(unit), str(s[0]), str(s[1]), str(s[2]), s[8]] for s in population]
        expected_policy.extend(member_rows[unit])
    assert policy == expected_policy

    # Source-owned input rows provide the complete head set, without redisassembly.
    if not min5 and not physical_windows: heads = grouped_source_heads(members['disassembly.txt'], original, sites, numeric)
    manifest = members['selection.txt'].decode().splitlines()
    assert manifest[0] == 'LI2TOOL-SHARED-REGIONS 1' and manifest.count('profile '+STACK_PROFILE) == 1
    hook_rows = [line.split() for line in manifest if line.startswith('hook ')]
    assert len(hook_rows) == 1 and len(hook_rows[0]) == 5 and hook_rows[0][1] == '1' and hook_rows[0][3] == '1'
    hook = numeric(hook_rows[0][2])
    assert hook_rows[0][4] == hashlib.sha256(b'\xc3').hexdigest() and heads[hook] == 1

    plan = rows('plan-ledger.tsv')
    assert plan[0] == ['LI2GROUPED-LEDGER', '1']
    for key, value in [('original_sha256', original), ('selection_sha256', selection),
        ('bias_policy', 'fixed-exec-zero-bias-indexed-jump32-v1'), ('bias_domain', str(domain)),
        ('qualification_complete', 'false'), ('execution_authority', 'none'),
        ('grouping', 'complete-selected-block-units-v1')]: assert one(plan, key) == [key, value]
    assert [row for row in plan if row[0] == 'hook'] == [['hook', '1', str(hook), '1', hook_rows[0][4]]]
    at = plan.index(['GROUP-ASSOCIATIONS', '1'])
    assert sum(row[0] == 'GROUP-ASSOCIATIONS' for row in plan) == 1
    assert not any(row[0] in ('member', 'accepted-unit', 'accepted_member_count', 'complete_site_count', 'policy_sha256') for row in plan[:at])
    assert plan[at+1] == ['policy_sha256', grouping]
    assert plan[-1] == ['required-fixed-source', original, str(domain), '1', str(domain), '0']
    accepted = {}; cursor = at+2
    while cursor < len(plan) and plan[cursor][0] == 'accepted-unit':
        row = plan[cursor]; assert len(row) == 5
        unit, primary, count = map(numeric, (row[1], row[2], row[4]))
        assert unit not in accepted and unit < len(units)
        population = units[unit]
        assert primary == population[0][0] and count == len(population)
        assert row[3] == ('group' if count > 1 else 'singleton')
        if min5 and count > 1: assert seals[unit][2] == 'ready'
        assert plan[cursor+1:cursor+1+count] == member_rows[unit]
        accepted[unit] = primary; cursor += 1+count
    assert list(accepted) == sorted(accepted)
    accepted_ids = [s[0] for unit in accepted for s in units[unit]]
    assert len(set(accepted_ids)) == len(accepted_ids)
    assert plan[cursor:-1] == [['accepted_member_count', str(len(accepted_ids))], ['complete_site_count', str(len(sites))]]

    # Every unique plan/image belongs to one accepted unit. Group fields name
    # every observed PC and the shared hook; routes include unselected heads too.
    primaries = set(accepted.values()); steps = {}; images = {}
    for row in plan[:at]:
        if row[0] == 'step':
            assert len(row) == 8 and numeric(row[1]) in primaries
            primary, step = numeric(row[1]), numeric(row[2])
            assert step == len(steps.setdefault(primary, [])); steps[primary].append(row)
        if row[0] == 'image':
            assert len(row) == 7
            image, primary, address, size = map(numeric, row[1:5])
            assert image == len(images) and primary in primaries and size > 0
            assert row[6] == f'image-{image:04}.bin'
            assert info['files'][row[6]] == dict(bytes=size, sha256=row[5])
            images[image] = (primary, address, size)
    assert set(steps) == primaries and {v[0] for v in images.values()} == primaries
    assert {name for name in info['files'] if re.fullmatch(r'image-[0-9]+\.bin', name)} == {f'image-{i:04}.bin' for i in images}
    assert {numeric(row[1]) for row in plan[:at] if row[0] in ('route', 'restored-boundary', 'field')} <= set(images)
    actual_ordinals = {}
    for unit, primary in accepted.items():
        population = units[unit]
        if len(population) == 1: continue
        start, end = population[0][1], population[-1][1]+population[-1][2]
        if min5: end = numeric(seals[unit][3])
        physical = start
        if upstream:
            assert len(steps[primary]) == 1
            step = steps[primary][0]
            assert step[:5] == ['step', str(primary), '0', 'relocation', str(start)]
            physical = numeric(step[5])
            if physical_windows:
                end = numeric(step[7])
                actual_ordinals[unit] = grouped_physical_ordinal(physical_seals[unit], physical, end)
            floor = max(population[0][6], max(0, start-64))
            assert floor <= physical <= start and physical in heads
            assert step[6:] == [str(physical), str(end)] and 5 <= end-physical <= 256
            assert all(s[6] == population[0][6] and s[7] == population[0][7] for s in population)
            assert end <= population[0][6]+population[0][7]
            # Full immutable selection, including accepted and straddling rows.
            # Neither pending-only membership nor a self-pinned shorter ledger suffices.
            for left in (floor, physical):
                assert population == [s for s in sites if s[1] < end and left < s[1]+s[2]]
                assert all(left <= s[1] < s[1]+s[2] <= end for s in population)
        else:
            assert steps[primary] == [['step', str(primary), '0', 'relocation', str(start), str(start), str(start), str(end)]]
        owned = [i for i, v in images.items() if v[0] == primary]; assert len(owned) == 1
        image = owned[0]; address, size = images[image][1:]
        routes = [row for row in plan[:at] if row[:2] == ['route', str(image)]]
        restored = [row for row in plan[:at] if row[:2] == ['restored-boundary', str(image)]]
        expected_heads = sorted(pc for pc in heads if physical <= pc < end)
        if upstream:
            assert size <= 4096 and expected_heads[0] == physical
            assert all(pc+heads[pc] == next_pc for pc, next_pc in zip(expected_heads, expected_heads[1:]+[end]))
        for table in (routes, restored):
            assert all(len(row) == 4 and address <= numeric(row[3]) < address+size for row in table)
            assert [numeric(row[2]) for row in table] == expected_heads
        data = [row for row in plan[:at] if row[:2] == ['field', str(image)]]
        assert all(len(row) == 10 for row in data)
        logical = [numeric(row[6]) for row in data if row[8] == b'LogicalPc'.hex()]
        calls = [numeric(row[6]) for row in data if row[8] == b'HookCall'.hex()]
        assert logical == [s[1] for s in population] and calls == [hook]*len(population)
        assert all(row[7] == str(domain) for row in data)
        assert info['files'].get(f'group-{unit}.diagnostics.txt') is not None

    assert report == li2_report(members['report.tsv'], sites, original, report['strict_full'])
    report_rows = rows('report.tsv')
    assert one(report_rows, 'selection_sha256') == ['selection_sha256', selection]
    local = []
    assert report['requested'] == len(sites) and len(report['rows']) == len(sites)
    for record in report['rows']:
        emitted = record['candidate_emitted'] == 'true'
        stage, code = record['stage'], record['refusal_code']
        if report['strict_full']:
            assert emitted and stage == code == 'none' and record['core_tactic'] in ('B1', 'B2', 'T1', 'T2', 'T3')
            local.append(int(record['site']))
        else:
            assert not emitted and stage != 'none' and code != 'none'
            if stage in ('atomic-selection', 'carrier'):
                assert code == ('10003' if stage == 'atomic-selection' else '10002')
                assert record['core_tactic'] in ('B1', 'B2', 'T1', 'T2', 'T3')
                local.append(int(record['site']))
    assert set(local) == set(accepted_ids)
    records = {int(row['site']): row for row in report['rows']}
    if physical_windows:
        for unit, seal in physical_seals.items():
            if seal[0][0] != 'unit-preflight': continue
            assert unit not in accepted
            for site in units[unit]:
                row = records[site[0]]
                assert row['core_tactic'] == 'none' and row['candidate_emitted'] == 'false'
                assert (row['refusal_code'], row['stage'], row['detail_hex']) == tuple(seal[0][3:])
    if min5:
        for unit, seal in seals.items():
            if seal[2] != 'refused': continue
            assert unit not in accepted
            for site in units[unit]:
                row = records[site[0]]
                assert row['core_tactic'] == 'none' and row['candidate_emitted'] == 'false'
                assert (row['refusal_code'], row['stage'], row['detail_hex']) == tuple(seal[4:])
    for population in groups:
        signatures = {(records[s[0]]['core_tactic'], records[s[0]]['candidate_emitted'], records[s[0]]['refusal_code'], records[s[0]]['stage']) for s in population}
        assert len(signatures) == 1
        if population[0][0] in accepted_ids:
            assert all(records[s[0]]['core_tactic'] == 'B1' for s in population)
    final = members['ledger.tsv']; pre = members['plan-ledger.tsv']
    assert final.startswith(pre)
    if report['strict_full']:
        assert set(accepted_ids) == {s[0] for s in sites}
        assert final[len(pre):].startswith(b'CARRIER-EXTENSION\t1\n')
        tail = rows('ledger.tsv')[len(plan):]
        assert one(tail, 'candidate_sha256') == ['candidate_sha256', info['files']['candidate.elf']['sha256']]
        assert one(tail, 'fixed-output-readback') == ['fixed-output-readback', 'checked']
        assert not any(row[0] in ('GROUP-ASSOCIATIONS', 'accepted-unit', 'member') for row in tail)
    else:
        assert final == pre and 'candidate.elf' not in info['files'] and 'source.li2sparse' not in info['files']
    result = dict(status='PASS' if report['strict_full'] else 'FAILED', policy_sha256=grouping,
                policy_units=len(units), group_units=len(groups), singleton_units=len(singles),
                accepted_units=len(accepted), accepted_members=len(accepted_ids),
                unique_images=len(images), requested=len(sites), emitted=report['emitted'],
                grouping_ledger='LI2GROUPED-LEDGER-2' if compact else 'LI2GROUPED-LEDGER-1',
                metadata_verification='Rust format/embedded check recorded; Python authenticates member hashes and text joins')
    if placement is not None:
        result.update(grouping_policy_version=policy_version, group_relocation_placement=placement)
    if suffix60: result['group_routed_suffix'] = 'single-byte60-v1'
    if compact: result['ledger_storage'] = storage_result
    if physical_windows: result['accepted_physical_ordinals'] = actual_ordinals
    return result


CHUNK_STORAGE = 'read-chunks256-v1'
CHUNK_MEMBERS = ('read-chunks.tsv', 'ledger-verification.tsv', 'bundle-index.tsv')


def chunk_storage(info, members, original):
    """Authenticate the Rust codec/replay receipt; never decode chunk contents."""
    fields, pins = info['fields'], info['files']
    expected = dict(ledger_storage=CHUNK_STORAGE, ledger_read_table='read-chunks.tsv',
        ledger_verification='ledger-verification.tsv', ledger_bootstrap='unsupported',
        ledger_wire_verification='checked', ledger_current_read_verification='checked-before-writes')
    assert all(fields.get(k) == v for k, v in expected.items())
    names = ('plan-ledger.tsv', 'ledger.tsv', 'read-chunks.tsv')
    for name in (*names, 'ledger-verification.tsv', 'bundle-index.tsv'):
        raw = members[name]
        assert len(raw) <= 64*M and pins[name] == dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    assert sum(len(members[name]) for name in names) <= 128*M
    plan, final, table = (members[name] for name in names)
    assert final.startswith(plan)
    head = plan.split(b'\n', 2)
    assert head[0] == b'LI2GROUPED-LEDGER\t2'
    assert head[1] == ('read-storage\t'+CHUNK_STORAGE+'\t'+str(len(table))+'\t'+pins['read-chunks.tsv']['sha256']).encode()
    assert table.startswith(b'LI2READ-CHUNKS\t1\t256\t') and table.endswith(b'\n')
    rows = [line.split('\t') for line in members['ledger-verification.tsv'].decode().splitlines()]
    assert rows[0] == ['LI2LEDGER-VERIFICATION', '1']
    values = {}; bound = {}
    for row in rows[1:]:
        if row[0] == 'member':
            assert len(row) == 4 and row[1] not in bound and re.fullmatch(r'0|[1-9][0-9]*', row[2]) and re.fullmatch('[0-9a-f]{64}', row[3])
            bound[row[1]] = dict(bytes=int(row[2]), sha256=row[3])
        else:
            assert len(row) == 2 and row[0] not in values; values[row[0]] = row[1]
    assert bound == {name: pins[name] for name in names}
    fixed = dict(storage=CHUNK_STORAGE, original_sha256=original,
        selection_sha256=pins['selection.txt']['sha256'], wire='checked',
        current_overlay_reads='checked-before-writes', semantic_scope='current-reads-and-record-shape-only',
        bootstrap='unsupported', member_limit=str(64*M), aggregate_limit=str(128*M), qualification_complete='false')
    assert set(values) == set(fixed) | {'canonical_bytes', 'canonical_sha256', 'steps', 'reads', 'references'}
    assert all(values[k] == v for k, v in fixed.items())
    assert re.fullmatch('[0-9a-f]{64}', values['canonical_sha256'])
    for key in ('canonical_bytes', 'steps', 'reads', 'references'):
        assert re.fullmatch(r'0|[1-9][0-9]*', values[key])
    plan_rows = [line.split(b'\t') for line in plan.splitlines()]
    assert int(values['steps']) == sum(row[0] == b'step' for row in plan_rows)
    assert int(values['reads']) == sum(row[0] == b'step-read-ref' for row in plan_rows)
    assert int(values['steps']) == int(values['reads'])
    # Bundle and COMPLETE must name the same physical members, including the
    # replay receipt itself. No proof inferred from six native output matches.
    rows = [line.split('\t') for line in members['bundle-index.tsv'].decode().splitlines()]
    assert rows[0] == ['LI2BUNDLE', '1']
    bundle = {}; declarations = {}
    for row in rows[1:]:
        if row[0] == 'file':
            assert len(row) == 4 and row[1] not in bundle and re.fullmatch(r'0|[1-9][0-9]*', row[2]) and re.fullmatch('[0-9a-f]{64}', row[3])
            bundle[row[1]] = dict(bytes=int(row[2]), sha256=row[3])
        else:
            assert len(row) == 2 and row[0] not in declarations
            declarations[row[0]] = row[1]
    assert declarations == dict(original_sha256=original, qualification_complete='false',
                                consumer_action='RuntimeScan-while-gated-until-qualified')
    assert bundle == {name: pin for name, pin in pins.items() if name != 'bundle-index.tsv'}
    return dict(storage=CHUNK_STORAGE, members=bound, verification=pins['ledger-verification.tsv'],
        canonical_bytes=int(values['canonical_bytes']), canonical_sha256=values['canonical_sha256'],
        steps=int(values['steps']), reads=int(values['reads']), references=int(values['references']),
        semantic_scope=values['semantic_scope'], bootstrap='unsupported')
