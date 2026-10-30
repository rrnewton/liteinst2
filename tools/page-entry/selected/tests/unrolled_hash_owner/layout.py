"""Read the actual retained capture ELF's DWARF. Never starts an inferior."""
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
types, edges, witnesses = {}, {}, {}
opaque = {('uh_frame', 'si'), ('uh_frame', 'uc')}


def shape(t, name=None):
    t = t.strip_typedefs()
    if t.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('actual complete structure')
    name = name or ('unrolled_owner' if t == owner else t.tag)
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
        if (name, f.name) == ('li2_step_frame', 'fp'):
            s = symbol('uho_step_frame_fp_alignment')
            if int(s.type.sizeof) != 8:
                raise ValueError('actual member witness extent')
            a = int(s.value())
            if a <= 0 or a & (a - 1):
                raise ValueError('actual member witness alignment')
            witnesses['li2_step_frame.fp'] = dict(symbol=s.name, bytes=8, alignment=a)
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


record = symbol('uho_wire')
if record.type.strip_typedefs().tag != 'uho_wire' or shape(record.type) != 'uho_wire':
    raise ValueError('actual wire symbol/type identity')
if not 0 < int(record.type.sizeof) < 4 << 20:
    raise ValueError('unchanged complete capture ceiling')


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
symbols = {s: offset(s) for s in ('uho_wire', 'selected_unrolled', 'selected_session',
    'li2_raw6', 'li2_gateway_start', 'li2_gateway_end')}
print(json.dumps(dict(record='uho_wire', types=types, edges=edges, member_witnesses=witnesses,
    symbols=symbols, uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
    uc=dict(offsets={k:offset(v) for k,v in uc.items()}, widths={k:width(v) for k,v in uc.items()}),
    si=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),
        offsets={k:offset(v) for k,v in si.items()}, widths={k:width(v) for k,v in si.items()})),
    sort_keys=True, separators=(',', ':')))
