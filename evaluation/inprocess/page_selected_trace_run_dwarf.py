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


result={}
for name in ('tr','samples'):
    symbol=gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    if symbol is None:raise ValueError('retained TRACE/run record symbol absent: '+name)
    result[name]=describe(symbol.type)
def offset(type_name, names):
    t=gdb.lookup_type(type_name).strip_typedefs(); total=0
    for name in names:
        fields=[f for f in t.fields() if f.name==name]
        if len(fields)!=1 or fields[0].bitpos%8 or fields[0].bitsize:raise ValueError('actual frame field')
        field=fields[0];total+=int(field.bitpos)//8;t=field.type.strip_typedefs()
    return total,int(t.sizeof)
result['frame']={
    'uc_bytes':int(gdb.lookup_type('ucontext_t').sizeof),
    'si_bytes':int(gdb.lookup_type('siginfo_t').sizeof),
    'greg':offset('ucontext_t',['uc_mcontext','gregs']),
    'mask':offset('ucontext_t',['uc_sigmask']),
    'fp':offset('ucontext_t',['uc_mcontext','fpregs']),
    'signo':offset('siginfo_t',['si_signo']),
    'errno':offset('siginfo_t',['si_errno']),
    'code':offset('siginfo_t',['si_code']),
    'address':offset('siginfo_t',['_sifields','_sigfault','si_addr']),
    'sender_pid':offset('siginfo_t',['_sifields','_kill','si_pid']),
    'sender_uid':offset('siginfo_t',['_sifields','_kill','si_uid'])}
print(json.dumps(result,sort_keys=True,separators=(',',':')))
