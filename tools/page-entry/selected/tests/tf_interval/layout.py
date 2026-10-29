"""Actual retained DWARF only; no inferior is started."""
import gdb,json
def shape(name):
 t=gdb.lookup_type('struct '+name).strip_typedefs();fields={}
 if t.code!=gdb.TYPE_CODE_STRUCT:raise ValueError('actual complete structure')
 for f in t.fields():
  if f.name is None or f.bitpos%8 or f.bitsize:raise ValueError('actual byte field')
  fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
 return dict(bytes=int(t.sizeof),fields=fields)
native=gdb.lookup_static_symbol('tfi_native_record');record='tfi_native_record'if native is not None else'tfi_record'
names=['rn_frame','tfi_endpoint',record]
if record=='tfi_record':names+=['tfi_event','tfi_trace_frame','tfi_owner','li2_tf_chain','li2_tf_trace_entry','li2_tf_chain_slot','li2_tf_owner','li2_step_owner','li2_step_request','li2_step_page','li2_step_frame','li2_chain_fetch','li2_chain_release','li2_tf_continuation','li2_tf_same_page','li2_fetch_rx_view','li2_fetch_ref','li2_fetch_progress','li2_fetch_page','li2_fetch_backing','stat','li2_fetch_map_progress','li2_maps_observation','li2_lifecycle_page_view','li2_rseq_state','li2_rseq_transaction','li2_rseq_data','li2_write_footprint','li2_decoded','li2_tf_classification']
types={n:shape(n)for n in names};s=gdb.lookup_static_symbol(record)
if s is None or int(s.type.sizeof)!=types[record]['bytes']:raise ValueError('complete actual record symbol')
def off(s):return int(gdb.parse_and_eval('(unsigned long)&('+s+')'))
offsets={k:off(v)for k,v in dict(greg='((ucontext_t*)0)->uc_mcontext.gregs',fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',mask='((ucontext_t*)0)->uc_sigmask',stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',stack_flags='((ucontext_t*)0)->uc_stack.ss_flags',stack_size='((ucontext_t*)0)->uc_stack.ss_size').items()}
si_fields=dict(si_signo='((siginfo_t*)0)->si_signo',si_errno='((siginfo_t*)0)->si_errno',si_code='((siginfo_t*)0)->si_code',si_addr='((siginfo_t*)0)->_sifields._sigfault.si_addr',si_pid='((siginfo_t*)0)->_sifields._kill.si_pid',si_uid='((siginfo_t*)0)->_sifields._kill.si_uid')
siginfo=dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),offsets={k:off(v)for k,v in si_fields.items()},widths={k:int(gdb.parse_and_eval('sizeof('+v+')'))for k,v in si_fields.items()})
print(json.dumps(dict(types=types,record=record,offsets=offsets,siginfo=siginfo,uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof)),sort_keys=True,separators=(',',':')))
