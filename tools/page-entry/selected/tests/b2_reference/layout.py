"""File-only GDB layout; never executes the inferior."""
import gdb,json
result={}
for name in ('b2_record','b2_row','b2_snapshot','b2_format_record','b2_format_sample'):
 t=gdb.lookup_type('struct '+name)
 result[name]={'bytes':int(t.sizeof),'fields':{f.name:{'offset':int(f.bitpos)//8,'bytes':int(f.type.sizeof)}for f in t.fields()}}
u=gdb.lookup_type('ucontext_t');m=next(f for f in u.fields()if f.name=='uc_mcontext');mt=m.type
result['layout']={'uc_bytes':int(u.sizeof),'greg':int(m.bitpos)//8+int(next(f for f in mt.fields()if f.name=='gregs').bitpos)//8,
 'fp_pointer':int(m.bitpos)//8+int(next(f for f in mt.fields()if f.name=='fpregs').bitpos)//8,
 'sigmask':int(next(f for f in u.fields()if f.name=='uc_sigmask').bitpos)//8}
print(json.dumps(result,sort_keys=True))
