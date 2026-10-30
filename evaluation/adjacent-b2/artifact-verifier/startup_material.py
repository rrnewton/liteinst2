"""Explicit original-layout dispatch; checked old codecs, no planner or native calls.

The readonly profile consumes the real linker bytes and original ELF. It never
substitutes legacy linker bytes to pass the old adapter's authored-source check.
All three startup readers use derive through the authenticated original capture.
"""
import hashlib
import re
import struct

CAP = 1048576
LEGACY = 'startup-original-facts-rooted-v1'
READONLY = 'startup-original-facts-readonly-headerpad-v1'
PROFILE = 'startup-readonly-headerpad-adjacent-routed-jmp-material-v1'
FAMILY = 'original-geometry-jcc-or-routed-jmp-v1'
OLD_LINE = b' .header_pad : { BYTE(0); . = ALIGN(4096); } :ro'
NEW_LINE = b' .header_pad : { *(.li2.header_pad); . = ALIGN(4096); } :ro'
SEED_SOURCE = b'.section .li2.header_pad,"a",@progbits\n.byte 0\n.section .note.GNU-stack,"",@progbits\n'
SEED_INPUTS = ('header_pad_source', 'header_pad_object')


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def readonly_linker(d):
    old = d.C.LINKER.encode('ascii')
    need(old.count(OLD_LINE) == 1, 'single frozen legacy linker declaration')
    return old.replace(OLD_LINE, NEW_LINE, 1)


def readonly_section(image):
    # ownership() already proves the exact zero bytes, extent, file offset and
    # unique R LOAD. This is an additional requirement, not a carrier exemption.
    row = image.section('.header_pad')
    need(row[1:3] == (1, 2), 'readonly header padding PROGBITS/ALLOC flags')


def _check(a, program, result, original):
    """The existing v6 material invariants with an honest new source profile."""
    heads, selected = a.COUNTS[program]
    need(result['profile'] == PROFILE and result['original_profile'] == READONLY
         and result['program'] == program and result['adjacent_pairs'] == FAMILY
         and all(type(result[k]) is int for k in ('adjacent_upper', 'adjacent_lower', 'adjacent_joint'))
         and [result['adjacent_upper'], result['adjacent_lower'], result['adjacent_joint']] == [2, 1, 2]
         and result['neighbor_victims'] == 'short-only' and result['neighbor_ownership'] == 'inherited-t3'
         and result['pending_selected'] == 'full-instruction-ownership'
         and result['qualification_complete'] is False and result['importer_verified'] is False,
         'readonly material profile/budget/qualification')
    need([result['source_expected_heads'], result['source_expected_jumps']] == [heads, selected],
         'readonly literal denominator')
    material = result['files']
    need(set(material) <= {'ledger.txt', 'policy.txt', 'source-inventory.tsv'}, 'readonly diagnostic members')
    if result['status'] != 'MATERIALS_READY':
        need(result['status'] == 'MATERIALS_REFUSED', 'readonly material status')
        return
    need(set(material) == {'ledger.txt', 'policy.txt', 'source-inventory.tsv'}
         and [result['roster_checked_heads'], result['roster_checked_jumps']] == [heads, selected],
         'readonly full checked roster')
    a.selected_rows(program, material)
    rows = material['policy.txt'].decode('ascii').splitlines()
    need(rows[:8] == ['LI2DISASM-POLICY 6', 'original ' + sha(original),
         'ledger ' + sha(material['ledger.txt']), 'neighbor-victims short-only',
         'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
         'adjacent-pairs ' + FAMILY, 'adjacent-pair-budgets 2 1 2'], 'readonly exact v6 prefix')
    need(rows[8].startswith('target ') and rows[9:13] == ['domain 1', 'carrier 4718592',
         'limits 1048576 32 32 131072 128 2097152 1048576 128 2147483648', 'null-hook 4206592']
         and len(rows) == 13 + 3 * selected, 'unchanged complete policy limits')
    for sid in range(1, selected + 1):
        at = 13 + (sid - 1) * 3
        need(rows[at] == f'search {sid} preferred 64 256 64 none 256 4096', 'unchanged singleton search')
        for row, role in zip(rows[at + 1:at + 3], ('selected', 'victim')):
            cells = row.split(' ')
            need(len(cells) == 8 and cells[:3] == ['allocation', str(sid), role]
                 and cells[4:6] == ['1', '4096']
                 and cells[6:] == ['4546560:172032', '4726784:2146951168'],
                 'unchanged cap-1 allocation and broad permits')


def attempt_readonly(d, program, inputs, expected):
    """One finite material attempt for the complete newly linked original."""
    need(program in d.COUNTS and type(inputs) is dict and type(expected) is dict
         and set(inputs) == set(expected) == set(d.INPUTS) | set(SEED_INPUTS), 'exact readonly material input roster')
    result = dict(profile=PROFILE, original_profile=READONLY, program=program,
        status='MATERIALS_REFUSED', source_expected_heads=d.COUNTS[program][0],
        source_expected_jumps=d.COUNTS[program][1], roster_checked_heads=None,
        roster_checked_jumps=None, qualification_complete=False, importer_verified=False,
        adjacent_pairs=FAMILY, adjacent_upper=2, adjacent_lower=1, adjacent_joint=2,
        neighbor_victims='short-only', neighbor_ownership='inherited-t3',
        pending_selected='full-instruction-ownership', files={})
    files = result['files']
    stage = 'inputs'
    try:
        for key in (*d.INPUTS, *SEED_INPUTS):
            need(type(inputs[key]) is bytes and 0 < len(inputs[key]) <= CAP, 'input bound')
            need(type(expected[key]) is str and re.fullmatch('[0-9a-f]{64}', expected[key]) is not None,
                 'frozen input digest shape')
            need(sha(inputs[key]) == expected[key], 'frozen input digest')
        need(inputs['source'] == d.C.assembly(program) and inputs['linker'] == readonly_linker(d)
             and inputs['header_pad_source'] == SEED_SOURCE,
             'exact authored instruction source, readonly linker and metadata seed')
        # The separate seed object has no instruction heads. Its exact bytes and
        # actual assembler invocation are authenticated by original capture; the
        # resulting ELF must independently satisfy the entire old ownership and
        # instruction/relocation proof plus the exact readonly header padding.
        stage = 'object-elf-ownership'
        image, obj, sizes = d.ownership(inputs['original'], inputs['object'], program)
        stage = 'readonly-section-ownership'
        readonly_section(image)
        stage = 'head-transport'
        heads = d.head_transport(program, inputs['heads'], inputs['original'], inputs['object'], sizes)
        stage = 'relocations-and-code'
        d.code_and_relocations(image, obj, heads, program)
        stage = 'ledger'
        ledger = ['LI2DISASM 1', 'original ' + sha(inputs['original']),
                  'contract complete-code no-overlap no-code-as-data private-image']
        inventory = ['role\tindex\tpc\tfile_offset\tlength\tselected_jump']
        instructions, _ = d.source_roster()
        jumps = []
        for role in d.ROLES:
            base = d.BASES['.text.' + role]
            offset = image.owned(base, sizes[role], 5)[0]
            for_head = heads[role]
            ledger.append(f'region {base} {offset} {sizes[role]}')
            for index, (off, code) in enumerate(for_head):
                selected = (instructions[index].startswith('j') if role == 'start' else
                            d.C.instructions(program)[index]['target'] is not None if role == 'kernel' else False)
                if selected:
                    jumps.append((base + off, len(code), offset + off))
                ledger.append(f'head {base + off} {code.hex()}')
                inventory.append(f'{role}\t{index}\t{base + off}\t{offset + off}\t{len(code)}\t{int(selected)}')
        count = sum(len(v) for v in heads.values())
        need((count, len(jumps)) == d.COUNTS[program], 'full original/selected denominator')
        files['ledger.txt'] = ('\n'.join(ledger) + '\n').encode('ascii')
        files['source-inventory.tsv'] = ('\n'.join(inventory) + '\n').encode('ascii')
        result.update(roster_checked_heads=count, roster_checked_jumps=len(jumps))
        stage = 'policy'
        target = d.T.target_record(inputs['target']).rstrip('\n')
        rows = ['LI2DISASM-POLICY 6', 'original ' + sha(inputs['original']),
                'ledger ' + sha(files['ledger.txt']), 'neighbor-victims short-only',
                'neighbor-ownership inherited-t3', 'pending-selected full-instruction-ownership',
                'adjacent-pairs ' + FAMILY, 'adjacent-pair-budgets 2 1 2', target,
                'domain 1', 'carrier 4718592', 'limits ' + d.BROAD_LIMITS, 'null-hook 4206592']
        rows += d.broad_policy(image, jumps)
        files['policy.txt'] = ('\n'.join(rows) + '\n').encode('ascii')
        need(all(len(v) <= CAP for v in files.values()), 'full material file bound')
        result['status'] = 'MATERIALS_READY'
    except (AssertionError, ValueError, KeyError, IndexError, struct.error) as error:
        result['failure'] = dict(stage=stage, error=type(error).__name__)
    result['observed_input_sha256'] = {k:sha(v) if type(v) is bytes and len(v) <= CAP else None for k,v in inputs.items()}
    result['observed_input_bytes'] = {k:len(v) if type(v) is bytes else None for k,v in inputs.items()}
    result['expected_input_sha256'] = dict(expected)
    return result


def derive(ctx, a, capture_profile, program, inputs):
    """Dispatch from the authenticated capture profile, before material results."""
    need(capture_profile in (LEGACY, READONLY), 'explicit original capture profile')
    expected = {key:sha(value) for key,value in inputs.items()}
    if capture_profile == LEGACY:
        adapter = ctx.load('adjacent_routed_jmp_material.py', a.MATERIAL_SHA)
        result = adapter.attempt_adjacent_routed_jmp(program, inputs, expected, upper=2, lower=1, joint=2)
        a.check_material(program, result, result['files'], inputs['original'], a.ROUTED)
        return result
    result = attempt_readonly(ctx.D, program, inputs, expected)
    _check(a, program, result, inputs['original'])
    return result

