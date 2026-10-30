"""Actual current-TF appendix DWARF and nine static extents; never an inferior."""
import gdb
import json


def symbol(name):
    s = gdb.lookup_static_symbol(name)
    if s is None:
        raise ValueError('required emitted symbol ' + name)
    return s


def align(t):
    n = int(t.strip_typedefs().alignof)
    if n <= 0 or n & (n - 1):
        raise ValueError('actual power-of-two alignment')
    return n


owner = symbol('selected_unrolled').type.strip_typedefs()
phdr = gdb.lookup_type('Elf64_Phdr').strip_typedefs()
if gdb.selected_inferior().pid != 0:
    raise ValueError('file-only layout never starts an inferior')
types, edges, witnesses = {}, {}, {}
opaque = {('uh_frame', 'si'), ('uh_frame', 'uc')}


def shape(t, name=None):
    t = t.strip_typedefs()
    if t.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('actual complete structure')
    name = name or ('unrolled_owner' if t == owner else 'Elf64_Phdr' if t == phdr else t.tag)
    if not name:
        raise ValueError('named captured type or exact owner type equality')
    if name in types:
        if types[name]['bytes'] != int(t.sizeof):
            raise ValueError('unique complete type')
        return name
    fields, children = {}, []
    for f in t.fields():
        if f.name is None or f.name in fields or f.bitpos % 8 or f.bitsize:
            raise ValueError('unique whole-byte captured fields')
        a = align(f.type)
        member_symbols = {('li2_step_frame', 'fp'): 'uho_step_frame_fp_alignment',
            ('uho_nested_fp', 'zero'): 'uho_nested_zero_alignment',
            ('uho_nested_fp', 'ones'): 'uho_nested_ones_alignment'}
        if (name, f.name) in member_symbols:
            s = symbol(member_symbols[name, f.name])
            if int(s.type.sizeof) != 8:
                raise ValueError('actual member witness extent')
            a = int(s.value())
            if a <= 0 or a & (a - 1):
                raise ValueError('actual member witness alignment')
            witnesses[name+'.'+f.name] = dict(symbol=s.name, bytes=8, alignment=a)
        offset, size = int(f.bitpos) // 8, int(f.type.sizeof)
        if size <= 0 or offset < 0 or offset + size > int(t.sizeof):
            raise ValueError('bounded complete field')
        fields[f.name] = dict(offset=offset, bytes=size, alignment=a,
                              type=str(f.type.strip_typedefs()))
        child = f.type.strip_typedefs()
        while child.code == gdb.TYPE_CODE_ARRAY:
            child = child.target().strip_typedefs()
        if (name, f.name) in opaque:
            continue
        if child.code == gdb.TYPE_CODE_UNION:
            raise ValueError('unexpected private captured union')
        if child.code == gdb.TYPE_CODE_STRUCT:
            children.append((f.name, child))
    if not fields:
        raise ValueError('nonempty captured structure')
    types[name] = dict(bytes=int(t.sizeof), alignment=align(t), fields=fields)
    edges[name] = {}
    for key, child in children:
        edges[name][key] = shape(child)
    return name


record = symbol('cto_wire')
if record.type.strip_typedefs().tag != 'cto_wire' or shape(record.type) != 'cto_wire':
    raise ValueError('actual wire symbol/type identity')
old_record = symbol('uho_wire')
if (not 0 < int(old_record.type.sizeof) < 4 << 20 or not 0 < int(record.type.sizeof) or
        int(old_record.type.sizeof) + 64 + int(record.type.sizeof) + 64 >= 16 << 20):
    raise ValueError('complete old+new record under original capture ceiling')


def offset(expression):
    return int(gdb.parse_and_eval('(unsigned long)&(' + expression + ')'))


def width(expression):
    return int(gdb.parse_and_eval('sizeof(' + expression + ')'))


uc = dict(flags='((ucontext_t*)0)->uc_flags', link='((ucontext_t*)0)->uc_link',
    greg='((ucontext_t*)0)->uc_mcontext.gregs', fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',
    mask='((ucontext_t*)0)->uc_sigmask', stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',
    stack_flags='((ucontext_t*)0)->uc_stack.ss_flags', stack_size='((ucontext_t*)0)->uc_stack.ss_size')
si = dict(signo='((siginfo_t*)0)->si_signo', errno='((siginfo_t*)0)->si_errno',
    code='((siginfo_t*)0)->si_code', addr='((siginfo_t*)0)->_sifields._sigfault.si_addr',
    pid='((siginfo_t*)0)->_sifields._kill.si_pid', uid='((siginfo_t*)0)->_sifields._kill.si_uid')
NAMES = ('maps_current', 'mct_physical_receipt', 'mct_physical_id',
         'rx_current', 'rx_current_busy', 'cc', 'cc_candidate', 'cc_serial', 'cc_stats')


def need(value, message):
    if not value:
        raise ValueError(message)


def extent(name):
    symbol = gdb.lookup_static_symbol(name)
    need(symbol is not None and symbol.is_variable and symbol.symtab is not None,
         'actual static variable and declaring compilation unit: ' + name)
    t = symbol.type.strip_typedefs()
    size, alignment = int(t.sizeof), int(t.alignof)
    need(0 < size <= 1 << 20 and 0 < alignment <= 4096 and not alignment & (alignment - 1),
         'complete actual storage extent and alignment')
    address = int(symbol.value().address)
    need(address > 0 and address % alignment == 0, 'actual aligned symbol address')
    fields = {}
    if t.code == gdb.TYPE_CODE_STRUCT:
        for f in t.fields():
            need(f.name and f.name not in fields and not f.bitsize and f.bitpos % 8 == 0,
                 'every direct field is a unique whole-byte field')
            offset, width = int(f.bitpos) // 8, int(f.type.sizeof)
            need(0 <= offset < size and 0 < width <= size - offset, 'complete member inside object')
            fields[f.name] = dict(offset=offset, bytes=width, type=str(f.type.strip_typedefs()))
    else:
        need(t.code == gdb.TYPE_CODE_INT, 'only actual integer or structure state')
    return dict(address=address, bytes=size, alignment=alignment, type=str(t),
                source=symbol.symtab.fullname(), fields=fields)


# Exact byte registrations selected by this profile's unchanged initialization.
# These witnesses are distinct from the nine maps/current storage observations.
REGISTERED={
    'selected_run_owner':('selected_globals.inc','li2_run_owner'),
    'selected_run_history':('selected_globals.inc','li2_run_completion_history'),
    'cache':('register_run_publish.c','li2_run_cache'),
    'selected_repeat_lease':('selected_globals.inc','li2_repeat_lease_owner'),
    'selected_session':('selected_globals.inc','li2_step_session'),
    'rep_custody':('repeat_custody.inc',None),
    'rep_custody_stats':('repeat_custody.inc','li2_repeat_custody_observation'),
    'selected_unrolled':('selected_unrolled_hash.inc',None),
    'uho_wire':('unrolled_hash_observe.inc','uho_wire'),
    'cto_wire':('current_tf_observe.inc','cto_wire'),
}

def registered_extent(name):
    s=symbol(name);t=s.type.strip_typedefs()
    need(s.is_variable and s.symtab is not None and t.code==gdb.TYPE_CODE_STRUCT,
         'actual registered structure and declaring source')
    address,size,alignment=int(s.value().address),int(t.sizeof),align(t)
    need(0<address and 0<size<16<<20 and alignment<=4096 and address%alignment==0,
         'complete actual registered byte extent')
    return dict(address=address,bytes=size,alignment=alignment,tag=t.tag,
                source=s.symtab.fullname())


symbols = {s: offset(s) for s in ('cto_wire', 'uho_wire', 'selected_chain', 'selected_unrolled',
    'selected_session', 'protected', 'li2_raw6', 'li2_gateway_start', 'li2_gateway_end')}
print(json.dumps(dict(record='cto_wire', types=types, edges=edges, member_witnesses=witnesses,
    old_bytes=int(old_record.type.sizeof), symbols=symbols,
    storage=dict(version=1, symbols={name: extent(name) for name in NAMES}),
    registrations={name:registered_extent(name) for name in REGISTERED},
    uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
    uc=dict(offsets={k:offset(v) for k,v in uc.items()}, widths={k:width(v) for k,v in uc.items()}),
    si=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),
        offsets={k:offset(v) for k,v in si.items()}, widths={k:width(v) for k,v in si.items()})),
    sort_keys=True, separators=(',', ':')))
