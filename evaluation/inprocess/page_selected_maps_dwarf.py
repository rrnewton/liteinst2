"""File-only GDB script. No inferior, expression call or fixture-provided offsets."""
import gdb
import json


def describe(value):
    value = value.strip_typedefs()
    size = int(value.sizeof)
    if value.code == gdb.TYPE_CODE_STRUCT:
        fields = []
        for field in value.fields():
            if field.bitpos % 8 or field.bitsize:
                raise ValueError('unexpected bitfield')
            fields.append(dict(name=field.name, offset=int(field.bitpos)//8,
                               type=describe(field.type)))
        return dict(kind='struct', bytes=size, fields=fields)
    if value.code == gdb.TYPE_CODE_ARRAY:
        low, high = map(int, value.range())
        if low != 0 or high < 0 or high > 65535:
            raise ValueError('closed record array extent')
        return dict(kind='array', bytes=size, count=high+1, element=describe(value.target()))
    if value.code == gdb.TYPE_CODE_PTR:
        if size != 8:
            raise ValueError('x86-64 pointer')
        return dict(kind='scalar', bytes=size, signed=False)
    if value.code in (gdb.TYPE_CODE_INT, gdb.TYPE_CODE_ENUM):
        if size not in (1, 2, 4, 8):
            raise ValueError('closed integral size')
        return dict(kind='scalar', bytes=size, signed=int(gdb.Value(-1).cast(value)) < 0)
    raise ValueError('unexpected record field type')


symbol = gdb.lookup_global_symbol('li2_maps_record') or gdb.lookup_static_symbol('li2_maps_record')
if symbol is None:
    raise ValueError('actual retained record symbol absent')
print(json.dumps(describe(symbol.type), sort_keys=True, separators=(',', ':')))
