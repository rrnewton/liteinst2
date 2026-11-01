"""Read actual certificate storage DWARF only; never start an inferior."""
import gdb
import json

def symbol(name):
    s=gdb.lookup_static_symbol(name)
    if s is None or not s.is_variable or s.symtab is None:
        raise ValueError('actual unique complete certificate storage symbol '+name)
    t=s.type.strip_typedefs()
    return dict(address=int(s.value().address),bytes=int(t.sizeof),alignment=int(t.alignof),
                tag=t.tag,source=s.symtab.fullname())

def shape(name):
    t=gdb.lookup_type('struct '+name).strip_typedefs();fields={}
    for f in t.fields():
        if f.name is None or f.name in fields or f.bitpos%8 or f.bitsize:
            raise ValueError('whole distinct actual certificate field')
        fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof),alignment=int(t.alignof),fields=fields)

def offset(text):return int(gdb.parse_and_eval('(unsigned long)&('+text+')'))
print(json.dumps(dict(schema=1,objects={k:symbol(k)for k in ('sbc_observed','sbco')},
    types={k:shape(k)for k in ('sbc_certificate','sbc_owner','sbc_counts','sbco_observation','sg_owner_state')},
    storage=dict(sg_bytes=offset('((struct sg_owner_state*)0)->bytes'))),sort_keys=True,separators=(',',':')))
