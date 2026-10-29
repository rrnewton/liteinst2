"""File-only emitted-bridge ABI; never starts an inferior."""
import sys
sys.dont_write_bytecode = True
import gdb
import json

types, edges = {}, {}
opaque = {('pao_frame', 'info'), ('li2_fetch_backing', 'stat'),
          ('effect_runtime', 'before'), ('effect_runtime', 'work'), ('effect_runtime', 'after')}


def shape(t, name):
    t = t.strip_typedefs()
    if t.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('actual structure')
    fields = {}
    for f in t.fields():
        if f.name is None or f.bitpos % 8 or f.bitsize:
            raise ValueError('actual whole-byte fields')
        fields[f.name] = {'offset': int(f.bitpos)//8, 'bytes': int(f.type.sizeof)}
    value = {'bytes': int(t.sizeof), 'fields': fields}
    if name in types:
        if types[name] != value:
            raise ValueError('unique actual type name')
        return
    types[name], edges[name] = value, {}
    if name == 'stat':
        return
    for f in t.fields():
        child = f.type.strip_typedefs()
        while child.code == gdb.TYPE_CODE_ARRAY:
            child = child.target().strip_typedefs()
        if (name, f.name) in opaque:
            continue
        if child.code == gdb.TYPE_CODE_UNION:
            raise ValueError('unexpected private owner union')
        if child.code == gdb.TYPE_CODE_STRUCT:
            key = child.tag
            if not key:
                raise ValueError('explicit named nested private type')
            edges[name][f.name] = key
            shape(child, key)


for name in ('pao_record', 'pao_row', 'pao_frame', 'pab_state', 'pab_module',
             'pa_policy_site', 'pa_policy_context', 'li2_effect_object_binding',
             'li2_effect_input', 'li2_effect_source', 'li2_effect_state',
             'li2_effect_owner', 'li2_effect_result', 'li2_effect_decision',
             'li2_oneshot_owner', 'li2_oneshot_plan', 'li2_oneshot_transfer',
             'li2_oneshot_release', 'li2_oneshot_lifecycle_progress', 'li2_oneshot_reuse_stats',
             'li2_rseq_state', 'li2_rseq_publication_state', 'li2_rseq_data',
             'li2_fetch_page', 'li2_fetch_backing', 'li2_lifecycle_counts',
             'li2_step_frame', 'li2_step_session', 'li2_selected_hardware', 'li2_decoded',
             'stat', 'selected_effect_raw_prefix'):
    # The anonymous controller and counts snapshots have explicit stable keys.
    if name in ('pao_record', 'pao_row'):
        continue
    shape(gdb.lookup_type('struct ' + name), name)
for key, symbol in (('effect_runtime', 'selected_effect_runtime'), ('oneshot_counts', 'selected_oneshot_counts')):
    value = gdb.lookup_static_symbol(symbol)
    if value is None:
        raise ValueError('actual retained owner symbol')
    shape(value.type, key)

# Resolve the same anonymous types embedded in record/rows by actual type
# equality, not invented field offsets or a guessed C ABI.
def envelope(t, name):
    t = t.strip_typedefs()
    fields = {f.name: {'offset': int(f.bitpos)//8, 'bytes': int(f.type.sizeof)} for f in t.fields()}
    if any(f.name is None or f.bitpos % 8 or f.bitsize for f in t.fields()):
        raise ValueError('actual envelope fields')
    types[name] = {'bytes': int(t.sizeof), 'fields': fields}; edges[name] = {}
    for f in t.fields():
        child = f.type.strip_typedefs()
        while child.code == gdb.TYPE_CODE_ARRAY:
            child = child.target().strip_typedefs()
        if child.code != gdb.TYPE_CODE_STRUCT:
            continue
        if (name, f.name) in opaque:
            continue
        if child == gdb.lookup_static_symbol('selected_effect_runtime').type.strip_typedefs():
            edges[name][f.name] = 'effect_runtime'
        elif child == gdb.lookup_static_symbol('selected_oneshot_counts').type.strip_typedefs():
            edges[name][f.name] = 'oneshot_counts'
        elif child.tag:
            edges[name][f.name] = child.tag
            if child.tag not in ('pao_row', 'pao_record'):
                shape(child, child.tag)
        else:
            raise ValueError('unknown anonymous envelope type')


envelope(gdb.lookup_type('struct pao_row'), 'pao_row')
envelope(gdb.lookup_type('struct pao_record'), 'pao_record')
record = gdb.lookup_static_symbol('pao_record')
if record is None or int(record.type.sizeof) != types['pao_record']['bytes'] or not 0 < types['pao_record']['bytes'] < 16 << 20:
    raise ValueError('actual ELF/DWARF record and unchanged complete-stream cap')


def off(expression):
    return int(gdb.parse_and_eval('(unsigned long)&(' + expression + ')'))


offsets = {k: off(v) for k, v in {
    'greg': '((ucontext_t*)0)->uc_mcontext.gregs', 'fp_pointer': '((ucontext_t*)0)->uc_mcontext.fpregs',
    'mask': '((ucontext_t*)0)->uc_sigmask', 'siginfo_signo': '((siginfo_t*)0)->si_signo',
    'siginfo_code': '((siginfo_t*)0)->si_code', 'siginfo_errno': '((siginfo_t*)0)->si_errno',
    'siginfo_address': '((siginfo_t*)0)->_sifields._sigfault.si_addr',
}.items()}
symbols = {name: off(name) for name in (
    'selected_session', 'selected_oneshot_current', 'pa_policy_context', 'pa_policy_callback',
    'li2_effect_runtime_binding', 'raw', 'selected_oneshot_frame_range',
    'li2_lifecycle_oneshot_transfer', 'li2_lifecycle_oneshot_advance',
    'li2_lifecycle_oneshot_observe', 'li2_lifecycle_oneshot_release', 'os_slots')}
print(json.dumps({'types': types, 'edges': edges, 'symbols': symbols, 'offsets': offsets,
                  'uc_bytes': int(gdb.lookup_type('ucontext_t').sizeof),
                  'siginfo_bytes': int(gdb.lookup_type('siginfo_t').sizeof)},
                 sort_keys=True, separators=(',', ':')))
