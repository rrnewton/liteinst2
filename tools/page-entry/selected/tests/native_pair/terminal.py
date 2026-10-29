"""Exact finite-oracle terminal report/capture joins; no case acceptance flag.

The caller first validates the complete record, ELF, frames and owner history.
`parsed` is the unchanged explicit pair-profile parser result. These joins do
not substitute a successful-workload contract for a real failed prefix. The
only report-free results are the two captured safe prefixes preceding unsafe
nonreturning exits; their post-mutation owners were deliberately not captured.
"""
import struct
from page_selected import need
import page_native_pair_reports as reports

U64 = (1 << 64)-1
P = 'li2_native_pair_progress'
L = 'li2_native_pair_lifecycle'
R = 'li2_rseq_pair_progress'
S = 'li2_rseq_state'
C = 'li2_native_close'


class Fields:
    def __init__(self, reader, data, name):
        self.reader, self.data, self.name = reader, data, name
        need(type(data) is bytes and len(data) == reader.types[name]['bytes'] and
             id(reader.types[name]) in reader.padding,
             'whole owner with source-authenticated layout/padding '+name)

    def field(self, key):return self.reader.field(self.data, self.name, key)
    def integer(self, key):return self.reader.integer(self.data, self.name, key)
    def values(self, keys):return [self.integer(k) for k in keys.split()]
    def child(self, key, name):return Fields(self.reader, self.field(key), name)
    def signed(self, key):
        b = self.field(key)
        need(len(b) in (2,4,8), 'actual signed scalar extent '+self.name+'.'+key)
        return int.from_bytes(b, 'little', signed=True)
    def cast(self, key):return self.signed(key)&U64
    def magnitude(self, key):
        value = self.signed(key)
        return [abs(value), int(value < 0)]


def pair_row(p, l, r, close, outcome):
    """Literal native_pair_report.inc order, including signed C casts."""
    slots = l.field('slots')
    size = l.reader.types['li2_native_pair_slot']['bytes']
    need(len(slots) == 2*size, 'exact two captured lifecycle slots')
    rows = []
    for index in range(2):
        s = Fields(l.reader, slots[index*size:(index+1)*size], 'li2_native_pair_slot')
        page = s.child('page', 'li2_fetch_page')
        backing = s.child('backing', 'li2_fetch_backing')
        stat = backing.child('stat', 'stat')
        rows.append(s.values('prepared published slot pc')+
            page.values('address allocation generation offset object backing logical closed_prot')+
            s.values('window_before window_after window_bytes window_initialized policy')+
            [backing.cast('retained_fd'), backing.cast('seals')]+
            backing.values('seals_observed stat_observed')+[backing.cast('stat_result')]+
            stat.values('st_dev st_ino st_size st_mode'))
    first = p.magnitude('first_detail')
    life_first = l.magnitude('first_detail')
    rseq_first = r.magnitude('first_detail')
    return dict(version=1, **outcome,
        control=p.values('initialized phase in_handler first_error')+first[::-1]+
                p.values('live entry_pending first_observed second_observed close_reason pid tid'),
        counts=p.values('events seeds extensions epochs_closed one_page_closes two_page_closes '
                        'policy_closes capacity_closes refaults refault_completed'),
        last_nx=[p.cast(k) for k in ('signal_number','signal_code','signal_errno')]+
                p.values('pc signal_address logical_flags'),
        lifecycle=l.values('initialized busy live first_error')+life_first[::-1]+
                  l.values('sequence allocation_epoch generation_epoch transactions_epoch records_epoch '
                           'attempts published closed_pages close_calls candidate candidate_policy '
                           'candidate_eligible opening post_verified'),
        slots=rows,
        rseq=r.values('initialized registered active checking entry_checked first_error')+
             rseq_first[::-1]+r.values('unsafe_terminal pid tid attempts published preentries entries '
                'refreshes closed registration_epoch address page length signature word_before word_entry '
                'word_after fs_before gs_before fs_after gs_after fs_selector_entry gs_selector_entry '
                'fs_selector_after gs_selector_after'),
        pin_before=r.child('before','li2_rseq_data').values('allocation generation offset attempted complete error'),
        pin_after=r.child('after','li2_rseq_data').values('allocation generation offset attempted complete error'),
        close=close.values('sequence pages attempted returned closed verified busy complete first_error '
                           'cleanup_started cleanup_complete'))


def data_row(data):
    """All 28 existing rseq_data_report fields; no synthetic maps receipt."""
    maps = data.child('maps','li2_fetch_map_progress')
    observation = maps.child('observation','li2_maps_observation')
    return (data.values('address page allocation generation offset pid tid attempted complete error')+
            data.magnitude('detail')+maps.magnitude('fd')+maps.magnitude('last_read')+
            maps.magnitude('close_result')+maps.values('bytes rows opened close_started closed')+
            observation.values('acquisition_id handler_id mutation_epoch kind io_performed'))


def rseq_row(state, outcome):
    """Complete unchanged LI2_RSEQ row from the actual terminal snapshot."""
    transaction = state.child('transaction','li2_rseq_transaction')
    footprint = state.child('last_footprint','li2_write_footprint')
    data = state.child('data','li2_rseq_data')
    args = transaction.field('args')
    need(len(args) == 48, 'six complete actual rseq syscall arguments')
    return dict(version=1, scope='registered_inactive_prototype', **outcome, maps_profile=1,
        owner=state.values('initialized registered held phase first_error')+
              state.magnitude('first_detail')+state.values('pid tid address page length signature epoch'),
        tls=state.values('tls_attempted tls_complete')+state.magnitude('fs_result')+
            state.magnitude('gs_result')+state.values('fs_base gs_base'),
        counts=state.values('calls registrations unregistrations kernel_errors instruction_checks '
                            'range_checks repeat_checks run_checks syscall_checks'),
        last=state.values('last_pc last_code last_policy last_first last_end'),
        footprint=footprint.values('abi_version pc next_pc code length policy first end'),
        transaction=transaction.values('attempted issued returned prior_registered')+
                    transaction.magnitude('result')+transaction.values('input_word_observed input_word'),
        args=list(struct.unpack('<6Q',args)),
        identity=data.values('complete allocation generation offset'),
        before=data_row(transaction.child('before','li2_rseq_data')),
        after=data_row(transaction.child('after','li2_rseq_data')))


def idle_old_owners(parsed, outcome):
    """Actual unused old owners retain the shared failure outcome, when failed."""
    rn = {k:0 for k in reports.registered.SCALARS}
    rn.update(version=1, scope='registered_native_epochs', before=[0]*28, after=[0]*28, **outcome)
    boundary = {k:0 for k in reports.boundary.SCALARS}
    boundary.update(version=1, scope='registered_current_pc_refault', **outcome,
                    **{k:[0]*n for k,n in reports.boundary.ARRAYS.items()})
    need(parsed['rseq_native'] == rn and parsed['rseq_boundary'] == boundary,
         'actual old registered-native/refault owners remain entirely idle, without rewriting their rows')
    native = parsed['native']
    need([native[k] for k in ('epoch_exits','refaults','epoch_error')] == [0,0,0],
         'old physical native-epoch owner has no invented pair execution')


def validate(parsed, reader, record, image, pid, exit_status):
    """Join reports after independent raw-record/owner validation; numeric only."""
    need(type(pid) is int and pid > 0 and type(exit_status) is int,
         'actual child identity and observed exit status')
    spec = image['spec']['case']
    case, control = image['case'], image['control']
    need((spec['case'],spec['control']) == (case,control) and exit_status == spec['gated_exit'],
         'exact fixed finite case and actual outcome')
    raw = Fields(reader, record, 'npf_record')
    h = struct.unpack('<64Q',raw.field('h'))
    need(h[3] == case and h[21] == control and h[7:9] == (1,0),
         'same complete actual terminal observation without capture error')
    p = raw.child('terminal_pair',P)
    l = raw.child('terminal_life',L)
    r = raw.child('terminal_rseq_pair',R)
    state = raw.child('terminal_rseq',S)
    close = raw.child('terminal_close',C)
    need(p.values('initialized pid tid') == [1,pid,pid] and
         l.values('initialized pid tid') == [1,pid,pid] and
         r.values('initialized pid tid') == [1,pid,pid] and
         state.values('initialized pid tid') == [1,pid,pid],
         'all four captured singleton owners belong to the actual process')
    unsafe = (case,control) in ((14,0),(16,1))
    need(spec['safe_prefix'] is unsafe and spec['terminal_record'] is (not unsafe),
         'exact two predeclared report-free unsafe prefixes')
    if unsafe:
        need(parsed is None and exit_status == 125 and spec['gated_terminal'] is None and
             h[9:13] == (0,0,0,0) and h[19] == 1 and h[13] == 1 and h[20] == 2,
             'actual safe prefix before unsafe exit; no terminal report or fabricated completed owner')
        need(p.values('phase in_handler first_error first_detail live entry_pending') == [4,0,0,0,1,0] and
             l.values('busy live first_error first_detail opening post_verified') == [0,1,0,0,0,1] and
             r.values('registered active checking entry_checked first_error first_detail unsafe_terminal') ==
                 [1,1,0,0,0,0,0] and
             state.values('registered held phase first_error first_detail') == [1,1,3,0,0],
             'retained state is the genuine safe one-page prefix, not a post-mutation claim')
        need(not any(raw.field('terminal_frame')) and not any(raw.field('nested_outer_frame')) and
             not any(raw.field('nested_outer_signal')),
             'unsafe prefix contains no invented terminal or nested-return frame')
        return dict(reports_present=0, safe_prefix=1, exit_status=exit_status,
                    captured_physical_admissions=h[17], captured_physical_closed=h[18])

    code, detail = spec['gated_terminal']
    need(type(code) is int and type(detail) is int and
         h[9:13] == (1,exit_status,code,detail&U64) and h[19] == 0,
         'actual complete terminal status, code and signed detail match the fixed case')
    need(type(parsed) is dict, 'mandatory actual full terminal report set')
    outcome = dict(status=exit_status, failure_code=code,
                   detail_negative=int(detail<0), detail_abs=abs(detail))
    reports.pair_schema(parsed['native_pair'])
    reports.extensions(parsed)
    expected_pair = pair_row(p,l,r,close,outcome)
    need(parsed['native_pair'] == expected_pair,
         'all actual pair report fields equal the complete captured terminal owners')
    need(parsed['rseq'] == rseq_row(state,outcome),
         'all actual inactive-rseq report fields equal the complete captured terminal owner')
    for name in ('loader','native_pair','rseq','run','chain','trace_run','reuse','repeat_lease'):
        need(all(parsed[name][k] == v for k,v in outcome.items()),
             'same actual terminal outcome in '+name)
    if parsed['repeat'] is not None:
        need(all(parsed['repeat'][k] == v for k,v in outcome.items()),
             'same actual optional REP terminal outcome')
    idle_old_owners(parsed,outcome)
    native, loader = parsed['native'], parsed['loader']
    need(native['status'] == exit_status and native['failure_code'] == code and
         native['admissions'] == h[17] and native['closed'] == h[18] and
         loader['admissions'] == h[17] and
         [native[k] for k in ('close_error','close_complete','close_busy')] ==
             close.values('first_error complete busy'),
         'actual physical admissions/closures and final close disposition join raw captures')
    first = (1477,41) if case == 11 else (code,detail)
    need((p.integer('first_error'),p.signed('first_detail')) == first and
         p.integer('phase') == (2 if exit_status == 0 else 11),
         'actual first pair error is retained, including nested error before controller failure')
    if exit_status == 0:
        need(code == detail == 0 and p.values('in_handler live entry_pending') == [0,0,0] and
             l.values('busy live first_error first_detail opening') == [0,0,0,0,0] and
             r.values('active checking entry_checked first_error first_detail unsafe_terminal') == [0]*6 and
             h[17] == h[18] and close.values('busy complete first_error cleanup_started cleanup_complete') == [0,1,0,0,0],
             'successful operation has genuine quiet owners and fully verified final close')
    else:
        need(exit_status == 125 and code > 0,
             'required failed operation remains failed; no successful close inferred from exit alone')
    return dict(reports_present=1, safe_prefix=0, exit_status=exit_status, failure_code=code,
        detail_negative=int(detail<0), detail_abs=abs(detail),
        pair_first_error=p.integer('first_error'), lifecycle_first_error=l.integer('first_error'),
        rseq_pair_first_error=r.integer('first_error'), close_first_error=close.integer('first_error'),
        physical_admissions=h[17], physical_closed=h[18], seeds=p.integer('seeds'),
        extensions=p.integer('extensions'), epochs_closed=p.integer('epochs_closed'),
        lifecycle_published=l.integer('published'), lifecycle_closed_pages=l.integer('closed_pages'),
        close_complete=close.integer('complete'), cleanup_started=close.integer('cleanup_started'),
        cleanup_complete=close.integer('cleanup_complete'))
