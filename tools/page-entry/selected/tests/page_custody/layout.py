"""Actual retained custody DWARF only; no inferior is started."""
import gdb
import json


def shape(name):
    value = gdb.lookup_type('struct ' + name).strip_typedefs()
    if value.code != gdb.TYPE_CODE_STRUCT:
        raise ValueError('actual complete structure')
    fields = {}
    for field in value.fields():
        if field.name is None or field.bitpos % 8 or field.bitsize:
            raise ValueError('actual byte field')
        fields[field.name] = dict(offset=int(field.bitpos) // 8,
                                  bytes=int(field.type.sizeof))
    return dict(bytes=int(value.sizeof), fields=fields)


NAMES = (
    'cso_stream', 'cso_record', 'cso_row', 'cso_meta', 'cso_snapshot',
    'lso_record', 'lso_event', 'lso_native_row', 'rn_frame',
    'li2_tf_chain', 'li2_tf_chain_slot', 'li2_tf_trace_entry', 'li2_decoder_stats',
    'li2_tf_owner', 'li2_tf_hooks', 'li2_tf_shstk_observation', 'li2_step_owner',
    'li2_step_hooks', 'li2_step_session', 'li2_step_request', 'li2_step_page',
    'li2_step_frame', 'li2_chain_fetch', 'li2_chain_release', 'li2_tf_continuation',
    'li2_tf_same_page', 'li2_fetch_rx_view', 'li2_fetch_ref', 'li2_fetch_progress',
    'li2_fetch_page', 'li2_fetch_backing', 'stat', 'li2_fetch_map_progress',
    'li2_maps_observation', 'li2_maps_stats', 'li2_page_custody_receipt',
    'li2_page_custody_stats', 'li2_rseq_state', 'li2_rseq_transaction',
    'li2_rseq_data', 'li2_write_footprint', 'li2_decoded', 'li2_tf_classification',
)
types = {name: shape(name) for name in NAMES}
symbol = gdb.lookup_static_symbol('cso_stream')
if symbol is None or int(symbol.type.sizeof) != types['cso_stream']['bytes']:
    raise ValueError('complete actual named stream storage')
if not 0 < types['cso_stream']['bytes'] < 16 << 20:
    raise ValueError('unchanged complete record bound')


def off(expression):
    return int(gdb.parse_and_eval('(unsigned long)&(' + expression + ')'))


offsets = {key: off(value) for key, value in dict(
    greg='((ucontext_t*)0)->uc_mcontext.gregs',
    fp_pointer='((ucontext_t*)0)->uc_mcontext.fpregs',
    mask='((ucontext_t*)0)->uc_sigmask',
    stack_sp='((ucontext_t*)0)->uc_stack.ss_sp',
    stack_flags='((ucontext_t*)0)->uc_stack.ss_flags',
    stack_size='((ucontext_t*)0)->uc_stack.ss_size',
).items()}
si_fields = dict(si_signo='((siginfo_t*)0)->si_signo',
                 si_errno='((siginfo_t*)0)->si_errno',
                 si_code='((siginfo_t*)0)->si_code',
                 si_addr='((siginfo_t*)0)->_sifields._sigfault.si_addr',
                 si_pid='((siginfo_t*)0)->_sifields._kill.si_pid',
                 si_uid='((siginfo_t*)0)->_sifields._kill.si_uid')
siginfo = dict(bytes=int(gdb.lookup_type('siginfo_t').sizeof),
               offsets={key: off(value) for key, value in si_fields.items()},
               widths={key: int(gdb.parse_and_eval('sizeof(' + value + ')'))
                       for key, value in si_fields.items()})
print(json.dumps(dict(types=types, record='cso_stream', offsets=offsets,
                      siginfo=siginfo, uc_bytes=int(gdb.lookup_type('ucontext_t').sizeof)),
                 sort_keys=True, separators=(',', ':')))
