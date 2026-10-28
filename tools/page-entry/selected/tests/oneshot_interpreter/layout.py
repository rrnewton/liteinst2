"""Actual retained bridge DWARF only; GDB -batch, no inferior."""
import gdb,json
def shape(name):
    t=gdb.lookup_type('struct '+name).strip_typedefs();fields={}
    if t.code!=gdb.TYPE_CODE_STRUCT:raise ValueError('actual struct')
    for f in t.fields():
        if f.name is None or f.bitpos%8 or f.bitsize:raise ValueError('byte-aligned fields')
        fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof),fields=fields)
names=('oi_record','oi_owner','oi_frame','li2_oneshot_owner','li2_oneshot_admission_state',
 'li2_oneshot_plan','li2_oneshot_call','li2_oneshot_operation','li2_oneshot_observation',
 'li2_oneshot_page','li2_oneshot_hooks','li2_oneshot_transfer','li2_oneshot_generation',
 'li2_oneshot_release','li2_oneshot_lifecycle_progress','li2_step_frame','li2_step_owner',
 'li2_step_request','li2_tf_owner','li2_tf_chain_slot','li2_chain_fetch','li2_chain_release',
 'li2_tf_continuation','li2_decoded','li2_fetch_progress','selected_builtin_prefix',
 'li2_fetch_map_progress','li2_maps_observation','li2_fetch_backing','stat')
types={n:shape(n)for n in names}
symbol=gdb.lookup_static_symbol('oi_record')
if symbol is None or int(symbol.type.sizeof)!=types['oi_record']['bytes']:raise ValueError('unique whole record symbol')
def off(expr):return int(gdb.parse_and_eval('(unsigned long)&('+expr+')'))
offsets={k:off(v)for k,v in dict(greg='((ucontext_t *)0)->uc_mcontext.gregs',
 fp_pointer='((ucontext_t *)0)->uc_mcontext.fpregs',mask='((ucontext_t *)0)->uc_sigmask',
 si_signo='((siginfo_t *)0)->si_signo',si_errno='((siginfo_t *)0)->si_errno',
 si_code='((siginfo_t *)0)->si_code',si_addr='((siginfo_t *)0)->_sifields._sigfault.si_addr').items()}
print(json.dumps(dict(types=types,offsets=offsets,uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof),
 si_bytes=int(gdb.lookup_type('siginfo_t').sizeof)),sort_keys=True,separators=(',',':')))
