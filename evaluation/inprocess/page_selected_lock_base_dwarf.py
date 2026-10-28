"""File-only type layout; no inferior or memory/function expressions."""
import gdb
import json

def fields(name,names):
    t=gdb.lookup_type(name).strip_typedefs();out={}
    for f in t.fields():
        if f.name in names:
            if f.bitpos%8 or f.bitsize:raise ValueError('unexpected bitfield')
            out[f.name]=int(f.bitpos)//8
    if set(out)!=set(names):raise ValueError('missing actual field')
    return int(t.sizeof),out
sample_bytes,sample=fields('struct sample',('pc','target','id','native_before','step_before'))
_,state=fields('struct state',('frame','fs','gs'))
_,frame=fields('struct li2_step_frame',('greg',))
t=gdb.lookup_type('struct li2_step_frame').strip_typedefs()
greg=next(f.type.strip_typedefs() for f in t.fields() if f.name=='greg')
lo,hi=map(int,greg.range())
if lo!=0 or int(greg.target().sizeof)!=8:raise ValueError('actual greg shape')
print(json.dumps(dict(sample_bytes=sample_bytes,query_bytes=int(gdb.lookup_type('struct lock_query_record').sizeof),
    greg_count=hi+1,sample=sample,state=state,frame=frame),sort_keys=True,separators=(',',':')))
