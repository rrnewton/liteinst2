"""File-only retained bridge DWARF; never starts an inferior."""
import gdb,json
def shape(name):
    t=gdb.lookup_type('struct '+name).strip_typedefs();fields={}
    if t.code!=gdb.TYPE_CODE_STRUCT:raise ValueError('actual structure')
    for f in t.fields():
        if f.name is None or f.bitpos%8 or f.bitsize:raise ValueError('actual byte field')
        fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof),fields=fields)
types={n:shape(n)for n in ('pb_record','pb_sample','pb_state','li2_selected_hardware')}
s=gdb.lookup_static_symbol('pb_record')
if s is None or int(s.type.sizeof)!=types['pb_record']['bytes']:raise ValueError('actual retained record')
def off(s):return int(gdb.parse_and_eval('(unsigned long)&('+s+')'))
offsets={k:off(v)for k,v in dict(greg='((ucontext_t*)0)->uc_mcontext.gregs',
 fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',mask='((ucontext_t*)0)->uc_sigmask').items()}
print(json.dumps(dict(types=types,offsets=offsets,uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof)),sort_keys=True,separators=(',',':')))
