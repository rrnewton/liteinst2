"""Read only the actual linked oracle DWARF; never start an inferior."""
import sys
sys.dont_write_bytecode = True
import gdb
import json

types = {}
opaque = {('eso_frame', 'info')}


def shape(t, name):
    t = t.strip_typedefs()
    if t.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('complete actual struct')
    fields = {}
    for f in t.fields():
        if f.name is None or f.bitpos % 8 or f.bitsize:
            raise ValueError('whole named byte fields')
        fields[f.name] = dict(offset=int(f.bitpos)//8, bytes=int(f.type.sizeof))
    value = dict(bytes=int(t.sizeof), fields=fields)
    if name in types:
        if types[name] != value:
            raise ValueError('unique actual type shape')
        return
    types[name] = value
    for f in t.fields():
        child = f.type.strip_typedefs()
        while child.code == gdb.TYPE_CODE_ARRAY:
            child = child.target().strip_typedefs()
        if (name, f.name) in opaque:
            continue
        if child.code == gdb.TYPE_CODE_STRUCT:
            key = child.tag or ('entry_timing' if name == 'eso_record' and f.name == 'timing' else None)
            if key is None:
                raise ValueError('unknown anonymous observed struct')
            shape(child, key)
        elif child.code == gdb.TYPE_CODE_UNION:
            raise ValueError('unexpected private union')


shape(gdb.lookup_type('struct eso_record'), 'eso_record')
record = gdb.lookup_static_symbol('eso_record')
if record is None or record.type.sizeof != types['eso_record']['bytes'] or not 0 < record.type.sizeof < 16 << 20:
    raise ValueError('actual complete record in the old bound')


def off(expression):
    return int(gdb.parse_and_eval('(unsigned long)&(' + expression + ')'))


offsets = {k: off(v) for k, v in {
    'greg': '((ucontext_t*)0)->uc_mcontext.gregs',
    'fp_pointer': '((ucontext_t*)0)->uc_mcontext.fpregs',
    'mask': '((ucontext_t*)0)->uc_sigmask',
    'siginfo_signo': '((siginfo_t*)0)->si_signo',
    'siginfo_code': '((siginfo_t*)0)->si_code',
    'siginfo_errno': '((siginfo_t*)0)->si_errno',
    'siginfo_address': '((siginfo_t*)0)->_sifields._sigfault.si_addr',
    'siginfo_pid': '((siginfo_t*)0)->_sifields._kill.si_pid',
}.items()}
symbols = {name: off(name) for name in ('eso_entry', '_start', 'li2_boot', 'li2_entry_time_start',
    'eso_saved_before', 'eso_saved_after', 'eso_seed_gpr', 'eso_seed_fp', 'eso_seed_stack',
    'selected_authenticate', 'selected_step_failure', 'li2_saved', 'li2_xstate', 'li2_xmask', 'li2_xmode', 'li2_target', 'selected_session')}
print(json.dumps(dict(types=types, offsets=offsets, symbols=symbols,
    uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
    siginfo_bytes=int(gdb.lookup_type('siginfo_t').sizeof)), sort_keys=True, separators=(',', ':')))
