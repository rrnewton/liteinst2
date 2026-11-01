"""Observe the actual native fixture's DWARF without starting an inferior."""
import gdb
import json


if any(inferior.pid for inferior in gdb.inferiors()):
    raise ValueError('layout observation requires no running inferior')

types, edges, actual_types = {}, {}, {}
required = {'lp_prefix', 'lp_suffix', 'ua_live', 'ua_frame'}


def align(t):
    value = int(t.strip_typedefs().alignof)
    if value <= 0 or value & (value - 1):
        raise ValueError('actual power-of-two alignment')
    return value


def shape(t):
    t = t.strip_typedefs()
    name = t.tag
    if t.code != gdb.TYPE_CODE_STRUCT or name not in required or int(t.sizeof) <= 0:
        raise ValueError('complete named native record type')
    if name in types:
        if actual_types[name] != t:
            raise ValueError('unique actual native type identity')
        return name
    fields, children = {}, []
    for field in t.fields():
        if (field.name is None or field.name in fields or field.bitpos is None
                or field.bitpos % 8 or field.bitsize):
            raise ValueError('unique whole-byte native fields')
        offset, size = int(field.bitpos) // 8, int(field.type.sizeof)
        if size <= 0 or offset < 0 or offset + size > int(t.sizeof):
            raise ValueError('bounded complete native field')
        fields[field.name] = dict(offset=offset, bytes=size, alignment=align(field.type))
        child = field.type.strip_typedefs()
        while child.code == gdb.TYPE_CODE_ARRAY:
            child = child.target().strip_typedefs()
        if child.code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            children.append((field.name, child))
    if not fields:
        raise ValueError('nonempty native type')
    actual_types[name] = t
    types[name] = dict(bytes=int(t.sizeof), alignment=align(t), fields=fields)
    edges[name] = {field: shape(child) for field, child in children}
    return name


def offset(expression):
    return int(gdb.parse_and_eval('(unsigned long)&(' + expression + ')'))


def width(expression):
    return int(gdb.parse_and_eval('sizeof(' + expression + ')'))


def object_value(name, tag):
    symbol = gdb.lookup_static_symbol(name)
    if symbol is None or not symbol.is_variable or symbol.symtab is None:
        raise ValueError('actual native object and source DWARF')
    t = symbol.type.strip_typedefs()
    source = symbol.symtab.fullname()
    if (t.tag != tag or t != gdb.lookup_type('struct ' + tag).strip_typedefs()
            or not source or not source.endswith('/tunables_loop_paired_app/main.c')
            or shape(t) != tag):
        raise ValueError('native object source and declared type identity')
    address = int(symbol.value().address)
    if address <= 0 or address != offset(name) or address % align(t):
        raise ValueError('actual aligned native object address')
    return dict(address=address, bytes=int(t.sizeof), alignment=align(t),
                tag=t.tag, source=source)


objects = {name: object_value(name, tag) for name, tag in
           (('prefix', 'lp_prefix'), ('suffix', 'lp_suffix'))}
if set(types) != required or set(edges) != required:
    raise ValueError('whole four-type native closure')

uc = dict(flags='((ucontext_t*)0)->uc_flags', link='((ucontext_t*)0)->uc_link',
    greg='((ucontext_t*)0)->uc_mcontext.gregs', fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',
    mask='((ucontext_t*)0)->uc_sigmask', stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',
    stack_flags='((ucontext_t*)0)->uc_stack.ss_flags', stack_size='((ucontext_t*)0)->uc_stack.ss_size')
si = dict(signo='((siginfo_t*)0)->si_signo', errno='((siginfo_t*)0)->si_errno',
    code='((siginfo_t*)0)->si_code', addr='((siginfo_t*)0)->_sifields._sigfault.si_addr')
print(json.dumps(dict(record='lp_paired_v2', types=types, edges=edges, objects=objects,
    uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
    uc=dict(offsets={key: offset(value) for key, value in uc.items()},
            widths={key: width(value) for key, value in uc.items()}),
    si=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),
            offsets={key: offset(value) for key, value in si.items()},
            widths={key: width(value) for key, value in si.items()})),
    sort_keys=True, separators=(',', ':')))
