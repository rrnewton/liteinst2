"""File-only GDB query: addresses/types, never an inferior or target value."""
import gdb,json

def symbol(name):
    s=gdb.lookup_static_symbol(name)
    if s is None or not s.is_variable or s.symtab is None:
        raise ValueError('actual emitted variable '+name)
    t=s.type.strip_typedefs()
    return s,t

names=('p last_terminal next_serial next_generation offers publications hits cold_attempts '
       'cancelled retirements permit_claims misses selected_bank resuming warm permit generation '
       'initialized close_started close_complete prepare_started prepare_complete build_started '
       'build_returned redirected exit_seen recovery_started recovery_complete guest_data_fault '
       'cleanup_started cleanup_complete consumed build_result recovery_result release_result '
       'entries completed unexpected ingress before after').split()
s,t=symbol('pe')
if t.tag!='li2_pe_epoch':raise ValueError('actual dynamic owner type')
fields={}
for f in t.fields():
    if f.name not in names:continue
    if f.bitsize or f.bitpos%8:raise ValueError('whole owner field')
    ft=f.type.strip_typedefs()
    fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(ft.sizeof),type=str(ft))
if set(fields)!=set(names):raise ValueError('all requested actual owner fields')
result=dict(schema=1,pe=dict(address=int(s.value().address),bytes=int(t.sizeof),
    tag=t.tag,source=s.symtab.fullname(),fields=fields),flags={})
for name in ('pe_busy','pe_active','pe_failing','pe_closing','pe_decoding','pe_terminal_ingress'):
    s,t=symbol(name)
    if int(t.sizeof)!=4:raise ValueError('actual sig_atomic_t width')
    result['flags'][name]=dict(address=int(s.value().address),bytes=4,source=s.symtab.fullname())
print(json.dumps(result,sort_keys=True,separators=(',',':')))
