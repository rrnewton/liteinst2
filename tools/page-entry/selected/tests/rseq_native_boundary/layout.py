"""Actual retained ELF DWARF only; this script never starts an inferior."""
import gdb,json
def shape(name):
    t=gdb.lookup_type('struct '+name).strip_typedefs();fields={}
    if t.code!=gdb.TYPE_CODE_STRUCT:raise ValueError('actual structure')
    for f in t.fields():
        if f.name is None or f.bitpos%8 or f.bitsize:raise ValueError('actual byte field')
        fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof),fields=fields)
native=gdb.lookup_static_symbol('rnb_native_record')
record='rnb_native_record' if native is not None else 'rnb_record'
names=['rn_frame',record,'rnb_native_row' if record=='rnb_native_record' else 'rnb_row']
if record=='rnb_record':names+=['li2_rseq_native_boundary_state','li2_rseq_native_state','li2_rseq_state','li2_rseq_data','li2_native_close','li2_write_footprint','li2_selected_hardware','li2_fetch_map_progress','li2_maps_observation']
types={n:shape(n)for n in names}
s=gdb.lookup_static_symbol(record)
if s is None or int(s.type.sizeof)!=types[record]['bytes']:raise ValueError('complete actual record symbol')
def off(s):return int(gdb.parse_and_eval('(unsigned long)&('+s+')'))
offsets={k:off(v)for k,v in dict(greg='((ucontext_t*)0)->uc_mcontext.gregs',fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',mask='((ucontext_t*)0)->uc_sigmask',stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',stack_flags='((ucontext_t*)0)->uc_stack.ss_flags',stack_size='((ucontext_t*)0)->uc_stack.ss_size').items()}
si_fields=dict(si_signo='((siginfo_t*)0)->si_signo',si_errno='((siginfo_t*)0)->si_errno',si_code='((siginfo_t*)0)->si_code',si_addr='((siginfo_t*)0)->_sifields._sigfault.si_addr')
siginfo=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),offsets={k:off(v)for k,v in si_fields.items()},widths={k:int(gdb.parse_and_eval('sizeof('+v+')'))for k,v in si_fields.items()})
print(json.dumps(dict(types=types,record=record,offsets=offsets,siginfo=siginfo,uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof)),sort_keys=True,separators=(',',':')))
