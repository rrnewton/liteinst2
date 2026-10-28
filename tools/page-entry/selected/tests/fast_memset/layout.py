"""GDB metadata only: no inferior, calls, or record-supplied offsets."""
import gdb
import json


def shape(name):
    t = gdb.lookup_type('struct '+name).strip_typedefs()
    if t.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('actual struct type')
    fields = {}
    for f in t.fields():
        if f.name is None or f.bitpos % 8 or f.bitsize:
            raise ValueError('named byte-aligned field')
        fields[f.name] = dict(offset=int(f.bitpos)//8, bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof), fields=fields)


record = gdb.lookup_static_symbol('record')
if record is None or int(record.type.sizeof) != int(gdb.lookup_type('struct record').sizeof):
    raise ValueError('actual static record type')
print(json.dumps(dict(slot_bytes=int(gdb.lookup_type('struct li2_tf_chain_slot').sizeof),
                      record=shape('record'), row=shape('row')),
                 sort_keys=True, separators=(',', ':')))
