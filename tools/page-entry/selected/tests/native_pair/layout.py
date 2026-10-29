"""Complete actual retained-ELF DWARF; no inferior is started or evaluated."""
import gdb
import json


def name_of(t):
    name = t.tag or str(t)
    for prefix in ('struct ', 'union '):
        if name.startswith(prefix):
            name = name[len(prefix):]
    if not name or '<anonymous' in name:
        raise ValueError('named complete embedded DWARF type')
    return name


def alignment(t):
    # Actual DWARF/GDB alignment only; no ABI guess or permissive fallback.
    value = int(t.strip_typedefs().alignof)
    if value <= 0 or value & (value-1):
        raise ValueError('actual power-of-two type alignment')
    return value


types, kinds, member_witnesses = {}, {}, {}


def member_alignment(parent, field):
    if parent == 'li2_step_frame' and field.name == 'fp':
        symbol = gdb.lookup_static_symbol('npf_step_frame_fp_alignment')
        if symbol is None or int(symbol.type.sizeof) != 8:
            raise ValueError('actual emitted member-alignment witness')
        value = int(symbol.value())
        if value <= 0 or value & (value-1):
            raise ValueError('actual power-of-two member alignment')
        member_witnesses['li2_step_frame.fp'] = dict(
            symbol=symbol.name, bytes=int(symbol.type.sizeof), alignment=value)
        return value
    return alignment(field.type)


def embedded(t):
    """Follow captured arrays/aggregates only, never dereference a pointer."""
    t = t.strip_typedefs()
    if t.code == gdb.TYPE_CODE_ARRAY:
        embedded(t.target())
        return
    if t.code not in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        return
    name = name_of(t)
    if name in types:
        if int(t.sizeof) != types[name]['bytes']:
            raise ValueError('unique actual embedded type')
        return
    if int(t.sizeof) <= 0:
        raise ValueError('complete embedded extent')
    fields = {}
    children = []
    for field in t.fields():
        if field.name is None or field.name in fields or field.bitpos % 8 or field.bitsize:
            raise ValueError('complete named byte field')
        offset, count = int(field.bitpos)//8, int(field.type.sizeof)
        if count <= 0 or offset < 0 or offset+count > int(t.sizeof):
            raise ValueError('bounded complete embedded field')
        fields[field.name] = dict(offset=offset, bytes=count,
            alignment=member_alignment(name, field), type=str(field.type.strip_typedefs()))
        children.append(field.type)
    if not fields:
        raise ValueError('nonempty actual aggregate')
    types[name] = dict(bytes=int(t.sizeof), alignment=alignment(t), fields=fields)
    kinds[name] = 'union' if t.code == gdb.TYPE_CODE_UNION else 'struct'
    for child in children:
        embedded(child)


native = gdb.lookup_static_symbol('npf_native_record')
record = 'npf_native_record' if native is not None else 'npf_record'
symbol = native if native is not None else gdb.lookup_static_symbol(record)
if symbol is None:
    raise ValueError('actual complete record symbol')
embedded(symbol.type)
if record not in types or int(symbol.type.sizeof) != types[record]['bytes']:
    raise ValueError('symbol and record DWARF identity')
required = {'rn_frame', record, 'npf_native_row' if native is not None else 'npf_row'}
if native is None:
    required.update(('npf_stage', 'li2_native_pair_progress', 'li2_native_pair_lifecycle',
        'li2_native_pair_slot', 'li2_rseq_pair_progress', 'li2_rseq_state',
        'li2_rseq_transaction', 'li2_rseq_data', 'li2_step_frame', 'li2_native_close',
        'li2_fetch_page', 'li2_fetch_backing', 'stat', 'timespec',
        'li2_fetch_map_progress', 'li2_maps_observation', 'li2_write_footprint',
        'li2_selected_hardware'))
if not required <= types.keys():
    raise ValueError('complete transitive captured type inventory')


def offset(expression):
    return int(gdb.parse_and_eval('(unsigned long)&('+expression+')'))


def width(expression):
    return int(gdb.parse_and_eval('sizeof('+expression+')'))


uc = dict(greg='((ucontext_t*)0)->uc_mcontext.gregs',
    fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',
    mask='((ucontext_t*)0)->uc_sigmask', stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',
    stack_flags='((ucontext_t*)0)->uc_stack.ss_flags',
    stack_size='((ucontext_t*)0)->uc_stack.ss_size')
si = dict(si_signo='((siginfo_t*)0)->si_signo', si_errno='((siginfo_t*)0)->si_errno',
    si_code='((siginfo_t*)0)->si_code', si_addr='((siginfo_t*)0)->_sifields._sigfault.si_addr',
    si_pid='((siginfo_t*)0)->_sifields._kill.si_pid', si_uid='((siginfo_t*)0)->_sifields._kill.si_uid')
print(json.dumps(dict(types=types, kinds=kinds, record=record, member_witnesses=member_witnesses,
    offsets={k:offset(v) for k,v in uc.items()},
    widths={k:width(v) for k,v in uc.items()},
    siginfo=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),
        offsets={k:offset(v) for k,v in si.items()}, widths={k:width(v) for k,v in si.items()}),
    uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof)), sort_keys=True, separators=(',', ':')))
