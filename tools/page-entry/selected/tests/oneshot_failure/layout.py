"""Run only in GDB -batch over the actual retained ELF; no inferior."""
import gdb,json

def shape(name):
    t=gdb.lookup_type('struct '+name).strip_typedefs()
    if t.code!=gdb.TYPE_CODE_STRUCT:raise ValueError('actual struct')
    fields={}
    for f in t.fields():
        if f.name is None or f.bitpos%8 or f.bitsize:raise ValueError('byte-aligned actual fields')
        fields[f.name]=dict(offset=int(f.bitpos)//8,bytes=int(f.type.sizeof))
    return dict(bytes=int(t.sizeof),fields=fields)

names=('failure_record','failure_raw','failure_backend','failure_event','li2_oneshot_owner',
       'li2_oneshot_admission_state','li2_oneshot_plan','li2_oneshot_call',
       'li2_oneshot_operation','li2_oneshot_lifecycle_progress','li2_oneshot_transfer',
       'li2_oneshot_generation','li2_oneshot_release')
types={n:shape(n)for n in names}
symbol=gdb.lookup_static_symbol('li2_oneshot_failure_record')
if symbol is None or int(symbol.type.sizeof)!=types['failure_record']['bytes']:
    raise ValueError('actual unique retained record symbol')
def offset(expression):return int(gdb.parse_and_eval('(unsigned long)&('+expression+')'))
offsets={name:offset(expr)for name,expr in dict(
    greg='((ucontext_t *)0)->uc_mcontext.gregs',
    fp_pointer='((ucontext_t *)0)->uc_mcontext.fpregs',mask='((ucontext_t *)0)->uc_sigmask',
    si_signo='((siginfo_t *)0)->si_signo',si_errno='((siginfo_t *)0)->si_errno',
    si_code='((siginfo_t *)0)->si_code',si_addr='((siginfo_t *)0)->_sifields._sigfault.si_addr').items()}
print(json.dumps(dict(types=types,offsets=offsets),sort_keys=True,separators=(',',':')))
