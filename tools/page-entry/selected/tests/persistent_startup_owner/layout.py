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


phdr = gdb.lookup_type('Elf64_Phdr').strip_typedefs()
types, edges, witnesses = {}, {}, {}
opaque = {('le_frame', 'si'), ('le_frame', 'uc')}


def shape(t, name=None):
    t = t.strip_typedefs()
    if t.code not in (gdb.TYPE_CODE_STRUCT,gdb.TYPE_CODE_UNION):
        raise ValueError('actual complete structure')
    name = name or ('Elf64_Phdr' if t == phdr else t.tag)
    if not name:
        raise ValueError('named captured type or exact owner type equality')
    if t.code==gdb.TYPE_CODE_UNION and name not in {'li2_pg_instruction','li2_pg_guard','li2_pg_guard_record'}:
        raise ValueError('unexpected resident typed union')
    if name in types:
        if types[name]['bytes'] != int(t.sizeof):
            raise ValueError('unique complete type')
        return name
    fields, children = {}, []
    for f in t.fields():
        if f.name is None or f.name in fields or f.bitpos % 8 or f.bitsize:
            raise ValueError('unique whole-byte captured fields')
        a = align(f.type)
        member_symbols = {('li2_step_frame', 'fp'): 'pdao_step_frame_fp_alignment'}
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
        if child.code in (gdb.TYPE_CODE_STRUCT,gdb.TYPE_CODE_UNION):
            children.append((f.name, child))
    if not fields:
        raise ValueError('nonempty captured structure')
    types[name] = dict(bytes=int(t.sizeof), alignment=align(t), fields=fields)
    edges[name] = {}
    for key, child in children:
        edges[name][key] = shape(child)
    return name


record = symbol('pdao_wire')
if record.type.strip_typedefs().tag != 'pdao_wire' or shape(record.type) != 'pdao_wire':
    raise ValueError('actual wire symbol/type identity')
# Exact separate full planner and ordinary-chain type closure.
shape(gdb.lookup_type('struct li2_pg_plan'))
shape(gdb.lookup_type('struct li2_tf_chain'))
shape(gdb.lookup_type('struct li2_ptr_slot'))
if not 0 < int(record.type.sizeof) < (4 << 20)-64:
    raise ValueError('complete dynamic record plus footer under original4MiB record cap')


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
REGISTERED={'selected_run_owner': ('selected_globals.inc', 'li2_run_owner'), 'selected_run_history': ('selected_globals.inc', 'li2_run_completion_history'), 'cache': ('register_run_publish.c', 'li2_run_cache'), 'selected_repeat_lease': ('selected_globals.inc', 'li2_repeat_lease_owner'), 'selected_session': ('selected_globals.inc', 'li2_step_session'), 'rep_custody': ('repeat_custody.inc', None), 'rep_custody_stats': ('repeat_custody.inc', 'li2_repeat_custody_observation'), 'selected_unrolled': ('selected_unrolled_hash.inc', None), 'selected_scalar_region': ('selected_scalar_region.inc', None), 'srr': ('selected_scalar_reuse.inc', None), 'selected_linked_epoch': ('linked_controller.inc', None), 'ler': ('linked_reuse.inc', None), 'lep': ('linked_controller.inc', None), 'linked_epoch': ('linked_source.inc', 'li2_link_epoch'), 'linked_registered': ('linked_source.inc', None), 'pe': ('persistent_group_controller.inc', 'li2_pg_epoch'), 'pg_source': ('persistent_group_source.inc', None), 'pg_rseq': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'pg_rseq_previous': ('persistent_group_rseq.inc', 'li2_pg_rseq_progress'), 'pdao_wire': ('persistent_startup_observe.inc', 'pdao_wire')}

def registration(name):
    s=symbol(name);t=s.type.strip_typedefs()
    if not s.is_variable or s.symtab is None or int(t.sizeof)<=0:
        raise ValueError('complete actual private registration symbol')
    return dict(address=offset(name),bytes=int(t.sizeof),alignment=align(t),tag=t.tag,source=s.symtab.fullname())

symbols={name:offset(name)for name in tuple(REGISTERED)+('selected_chain','span_transfer','protected','li2_raw6','li2_gateway_start','li2_gateway_end','maps_current','rows')}
symbols['span_progress']=offset('span_transfer.progress')
symbols['pg_domain_source']=offset('pg_source.domain')
print(json.dumps(dict(record='pdao_wire',types=types,edges=edges,member_witnesses=witnesses,
    symbols=symbols,retained_storage={k:dict(offset=offset('((struct li2_pg_epoch*)0)->'+k),bytes=width('((struct li2_pg_epoch*)0)->'+k))for k in ('retained','selected_slot','selection','previous_selection','domain')},registrations={name:registration(name)for name in REGISTERED},uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
    uc=dict(offsets={k:offset(v)for k,v in uc.items()},widths={k:width(v)for k,v in uc.items()}),
    si=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),offsets={k:offset(v)for k,v in si.items()},widths={k:width(v)for k,v in si.items()})),sort_keys=True,separators=(',',':')))
