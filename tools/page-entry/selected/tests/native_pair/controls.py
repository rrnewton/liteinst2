"""Supplied corruptions of an already qualified actual native/gated capture.

The enclosing owner supplies the same retained bytes, ELF-derived image, layout,
PIDs, exits and parsed stderr accepted by pair() and terminal(). These checks
provide reader-rejection evidence only; no synthetic successful record, native
operation, kernel event or completed owner is created or credited.
"""
from copy import deepcopy


def require(value, message):
    if not value:
        raise ValueError(message)


def validate(check, nrecord, grecord, nout, gout, layout, image,
             npid, gpid, cpu, nexit, gexit, parsed):
    """Return numeric refusal observations after both original readers pass."""
    original = dict(nrecord=nrecord, grecord=grecord, nout=nout, gout=gout,
                    layout=layout, image=image, npid=npid, gpid=gpid, cpu=cpu,
                    nexit=nexit, gexit=gexit, parsed=parsed)

    def read(arguments):
        check.pair(arguments['nrecord'], arguments['grecord'],
                   arguments['nout'], arguments['gout'], arguments['layout'],
                   arguments['image'], arguments['npid'], arguments['gpid'],
                   arguments['cpu'], arguments['nexit'], arguments['gexit'])
        check.terminal(arguments['parsed'], arguments['grecord'],
                       arguments['layout']['gated'], arguments['image'],
                       arguments['gpid'], arguments['gexit'])

    # Never count rejection of an originally invalid input as a control pass.
    read(original)
    results = {}

    def reject(name, **changes):
        require(name not in results and changes, 'unique nonempty supplied mutation')
        arguments = dict(original, **changes)
        try:
            read(arguments)
        except ValueError:
            results[name] = 1
        else:
            raise ValueError('reader accepted supplied corruption: '+name)
        # Other exception classes escape; malformed controls cannot earn credit.

    def field(lane, typename, name):
        entry = layout[lane]['types'][typename]['fields'][name]
        return entry['offset'], entry['bytes']

    def extent(lane, typename):
        return layout[lane]['types'][typename]['bytes']

    def flip(data, offsets, bit=1):
        require(type(data) is bytes and type(bit) is int and 0 < bit < 256,
                'copied actual byte extent and one byte mask')
        out = bytearray(data)
        for at in offsets:
            require(type(at) is int and 0 <= at < len(out),
                    'source-selected supplied byte lies within actual capture')
            out[at] ^= bit
        require(bytes(out) != data, 'supplied corruption actually changes retained bytes')
        return bytes(out)

    def record_field(name):
        return field('gated', 'npf_record', name)[0]

    def row_base(lane, index):
        record = 'npf_native_record' if lane == 'native' else 'npf_record'
        row = 'npf_native_row' if lane == 'native' else 'npf_row'
        return field(lane, record, 'rows')[0]+index*extent(lane, row), row

    def frame_offsets(lane, index, member, relative=0):
        base, row = row_base(lane, index)
        member_at, size = field(lane, 'rn_frame', member)
        require(0 <= relative < size, 'actual complete frame member extent')
        event = image['spec'][lane+'_flow'][index]
        names = ('before', 'after') if lane == 'native' or event['pair_result'] is not None else ('before',)
        return [base+field(lane, row, name)[0]+member_at+relative for name in names]

    # Truncation and the last byte of whole unused rows/stages, not just headers.
    reject('native_truncated', nrecord=nrecord[:-1])
    reject('gated_truncated', grecord=grecord[:-1])
    for lane, data, key in (('native', nrecord, 'nrecord'), ('gated', grecord, 'grecord')):
        count = len(image['spec'][lane+'_flow'])
        require(count < check.ROWS, 'actual unused row required by every finite profile')
        base, row = row_base(lane, count)
        reject(lane+'_unused_row_tail', **{key:flip(data, [base+extent(lane, row)-1])})
    count = image['spec']['case']['stages']
    require(count < check.STAGES, 'actual unused lifecycle stage in every finite profile')
    at = record_field('stages')+(count+1)*extent('gated', 'npf_stage')-1
    reject('unused_stage_tail', grecord=flip(grecord, [at]))

    # Coherent first-row before/after changes must fail independent content
    # checks, rather than merely the helper's before==after comparison.
    for lane, data, key in (('native', nrecord, 'nrecord'), ('gated', grecord, 'grecord')):
        base, row = row_base(lane, 0)
        offsets = [base+field(lane, row, name)[0]+127
                   for name in ('signal_before', 'signal_after')]
        offsets += frame_offsets(lane, 0, 'uc', layout[lane]['offsets']['mask']+8+127)
        reject(lane+'_siginfo_padding', **{key:flip(data, offsets)})
    selected = (
        ('whole_uc_reserved', 'uc', layout['gated']['uc_bytes']-1),
        ('seeded_gpr', 'uc', layout['gated']['offsets']['greg']),
        ('unused_uc_tail', 'uc', 2047),
        ('full_fp_control', 'fp', 0),
        ('unused_fp_tail', 'fp', 65535),
        ('source_tail', 'source', check.SOURCE_BYTES-1),
        ('whole_data_tail', 'data', check.DATA_BYTES-1),
        ('whole_rseq_page_tail', 'rseq', 4095),
    )
    for name, member, offset in selected:
        reject(name, grecord=flip(grecord, frame_offsets('gated', 0, member, offset)))

    # Independent retained-ELF and complete terminal capture bindings.
    # Relocate the complete self-consistent observed native altstack by one
    # page. The unchanged ELF symbol is the independent rejection authority;
    # UC/FP/SI ranges, before==after and all relative geometry stay coherent.
    native_h = field('native', 'npf_native_record', 'h')[0]
    pointers = [native_h+11*8]
    for i in range(len(image['spec']['native_flow'])):
        base, row = row_base('native', i)
        header = base+field('native', row, 'h')[0]
        pointers.extend((header+24*8, header+25*8))
        for member in ('before', 'after'):
            frame = base+field('native', row, member)[0]
            pointers.append(frame+field('native', 'rn_frame', 'h')[0]+3*8)
            uc = frame+field('native', 'rn_frame', 'uc')[0]
            for name in ('stack_sp', 'fp_pointer'):
                require(layout['native']['widths'][name] == 8,
                        'actual full native pointer scalar width')
                pointers.append(uc+layout['native']['offsets'][name])
    require(len(pointers) == len(set(pointers)), 'each actual native pointer shifted once')
    shifted = bytearray(nrecord)
    for at in pointers:
        require(0 <= at <= len(shifted)-8, 'bounded actual native pointer field')
        value = int.from_bytes(nrecord[at:at+8], 'little')
        require(0 < value <= (1 << 64)-1-4096, 'checked one-page native pointer relocation')
        shifted[at:at+8] = (value+4096).to_bytes(8, 'little')
    reject('native_altstack_elf', nrecord=bytes(shifted))
    different = deepcopy(image)
    different['sealed_carrier_bytes'] += 4096
    reject('appended_carrier_extent', image=different)
    for member, typename, key in (
        ('terminal_pair', 'li2_native_pair_progress', 'session'),
        ('terminal_life', 'li2_native_pair_lifecycle', 'owner'),
    ):
        at = record_field(member)+field('gated', typename, key)[0]
        reject('bridge_'+key, grecord=flip(grecord, [at]))
    for name in ('terminal_source', 'terminal_data', 'terminal_page'):
        at, size = field('gated', 'npf_record', name)
        reject(name+'_tail', grecord=flip(grecord, [at+size-1]))
    common = len(results)
    require(common == 22, 'all twenty-two common supplied controls rejected')

    # The genuine completed lanes must retain the exact final flags and all
    # final capture bytes. For case4, flip AF in both PUSHFQ output locations:
    # the independent XOR model permits that undefined bit, so the actual
    # CLOSE-frame equality must reject this otherwise coherent output.
    for key, data, status in (('nout', nout, nexit), ('gout', gout, gexit)):
        if status == 0:
            reject(key+'_full_flags', **{key:flip(data, [6336, 16312], 16)})
            reject(key+'_final_byte', **{key:flip(data, [len(data)-1])})
        else:
            require(data == b'', 'genuine required-failure output is empty')
            reject(key+'_invented_output', **{key:b'\x01'})

    flow = image['spec']['gated_flow']
    unreturned = [i for i, event in enumerate(flow) if event['pair_result'] is None]
    for i in unreturned:
        base, row = row_base('gated', i)
        at = base+field('gated', row, 'after')[0]+extent('gated', 'rn_frame')-1
        reject('unreturned_after_'+str(i), grecord=flip(grecord, [at]))
        at = base+field('gated', row, 'pair_after')[0]
        reject('unreturned_owner_'+str(i), grecord=flip(grecord, [at]))

    if image['spec']['case']['safe_prefix']:
        require(parsed is None, 'actual unsafe prefix has no terminal report')
        at, size = field('gated', 'npf_record', 'terminal_frame')
        reject('unsafe_invented_terminal_frame', grecord=flip(grecord, [at+size-1]))
        reject('unsafe_invented_terminal_marker', grecord=flip(grecord, [record_field('h')+9*8]))
        reject('unsafe_invented_report', parsed={})
    else:
        require(type(parsed) is dict, 'actual full terminal report set')
        reject('missing_terminal_report', parsed=None)
        changed = deepcopy(parsed)
        changed['native_pair']['counts'][0] ^= 1
        reject('pair_report_event_count', parsed=changed)
        changed = deepcopy(parsed)
        changed['loader']['admissions'] ^= 1
        reject('physical_admission_report', parsed=changed)
        changed = deepcopy(parsed)
        changed['rseq']['owner'][1] ^= 1
        reject('rseq_registration_report', parsed=changed)
        if gexit:
            changed = deepcopy(parsed)
            changed['loader']['status'] = 0
            reject('failure_report_relabelled', parsed=changed)
            at, size = field('gated', 'npf_record', 'terminal_frame')
            reject('failure_terminal_frame_tail', grecord=flip(grecord, [at+size-1]))

    if image['case'] == 11:
        different = deepcopy(image)
        different['bridge']['symbols']['li2_raw6']['return_pc'] += 1
        reject('nested_actual_raw_pc', image=different)
        at, size = field('gated', 'npf_record', 'nested_outer_frame')
        reject('whole_suspended_outer_frame', grecord=flip(grecord, [at+size-1]))
        # Coherent corruption preserves inner-to-terminal equality. Only the
        # independent complete kernel-initial FP model can reject this FCW bit.
        base, row = row_base('gated', 2)
        fp = field('gated', 'rn_frame', 'fp')[0]
        inner = base+field('gated', row, 'before')[0]+fp
        terminal = record_field('terminal_frame')+fp
        reject('nested_kernel_initial_fcw', grecord=flip(grecord, [inner, terminal]))
        # This kernel saves configured altstack flags, while address bounds
        # independently establish nested on-stack execution. Preserve the
        # entire inner/terminal equality while corrupting both saved flags.
        uc = field('gated', 'rn_frame', 'uc')[0]
        flags = layout['gated']['offsets']['stack_flags']
        inner_flags = base+field('gated', row, 'before')[0]+uc+flags
        terminal_flags = record_field('terminal_frame')+uc+flags
        reject('nested_configured_stack_flags',
               grecord=flip(grecord, [inner_flags, terminal_flags]))
        # CPUID(D,9) offset is independently observed before arm in both lanes.
        # Mutating only gated metadata must fail that join, including absent PKRU.
        reject('native_gated_cpuid_d9_offset',
               grecord=flip(grecord, [record_field('h')+37*8]))
    expected = {
        (0,0):30, (1,0):30, (2,0):30, (3,0):30, (4,0):30, (5,0):30,
        (6,0):30, (7,0):30, (8,0):30, (9,0):30, (10,0):30, (11,0):40,
        (12,0):31, (13,0):31, (14,0):28, (15,0):33, (16,0):31,
        (16,1):28, (17,0):31, (18,0):31, (19,0):30, (20,0):31,
    }
    key = (image['case'], image['control'])
    require(key in expected and len(results) == sum(results.values()) == expected[key],
            'complete exact supplied-refusal population for this actual finite profile')
    return dict(supplied_reader_controls=len(results), supplied_reader_refusals=sum(results.values()),
                common_controls=common, profile_controls=len(results)-common,
                native_operation_credit=0, **results)
