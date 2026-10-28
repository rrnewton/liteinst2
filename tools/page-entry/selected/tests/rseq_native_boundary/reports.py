"""Explicit registered current-PC refaults; all prior completion checks retained."""
import importlib.util
from pathlib import Path

from page_selected import need
import page_selected_rseq_compare as rseq

_PATH = Path(__file__).resolve().parent.parent/'rseq_native/reports.py'
_SPEC = importlib.util.spec_from_file_location('rseq_boundary_old_reports', _PATH)
old = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(old)

SCALARS = set(('version status failure_code detail_abs detail_negative phase first_error '
               'first_detail_abs first_detail_negative entry_checked').split())
ARRAYS = dict(counts=6, identity=9, geometry=3, words=3, tls=10,
              first_data=28, second_data=28, first_close=33, second_close=33)


def reports(stderr):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete boundary report')
    lines = stderr[:-1].split(b'\n')
    indexes = [i for i, line in enumerate(lines) if line.startswith(b'LI2_RSEQ_BOUNDARY ')]
    need(len(indexes) == 1, 'one actual boundary report')
    at = indexes[0]
    need(at > 0 and lines[at-1].startswith(b'LI2_RSEQ_NATIVE ') and len(lines[at])+1 <= 4096,
         'bounded extension after unchanged registered-native row')
    s = rseq.decode(lines[at][len(b'LI2_RSEQ_BOUNDARY '):])
    old.old._unsigned(s, SCALARS, ARRAYS, 'registered_current_pc_refault')
    parsed = old.reports(b'\n'.join(lines[:at]+lines[at+1:])+b'\n')
    need(all(s[k] == parsed['loader'][k] for k in
             ('status', 'failure_code', 'detail_abs', 'detail_negative')), 'same actual terminal outcome')
    need(s['phase'] <= 5 and all(s[k] in (0, 1) for k in
         ('entry_checked', 'detail_negative', 'first_detail_negative')) and
         all(x < 1 << 16 for x in s['tls'][4:]), 'exact boundary scalar domains')
    a, p, e, o, t, c = s['counts']
    need(c <= t <= o <= e <= p <= a <= parsed['rseq_native']['admissions'] and
         c <= parsed['native']['refaults'], 'actual separate retry prefixes; no inferred completion')
    parsed['rseq_boundary'] = s
    return parsed


def _close(c, pid, pages, address):
    need(c[0] > 0 and c[1] > 0 and c[2] > 0 and c[4] > 0 and
         c[5:10] == [pages]*5 and c[10] == address and c[11:13] == [pid, pid],
         'actual bounded close identity and exact page accounting')
    need(c[13:22] == [0]*9 and c[22] == 1 and c[23:25] == [pages]*2 and c[25:] == [0]*8,
         'verified complete close without error or best-effort cleanup')


def completed(parsed, pid):
    old.completed(parsed, pid)  # Every unchanged native/NX/rseq/chain/run/REP predicate.
    s = parsed['rseq_boundary']
    need(s['status'] == s['failure_code'] == s['phase'] == s['first_error'] ==
         s['first_detail_abs'] == s['first_detail_negative'] == 0, 'no failed or pending boundary token')
    a, p, e, o, t, c = s['counts']
    need(a == p == e == o == t == c, 'each attempted retry entered, observed, refreshed and completed once')
    if not a:
        need(all(s[k] == 0 for k in SCALARS-{'version'}) and
             all(s[k] == [0]*n for k, n in ARRAYS.items()), 'no invented boundary work')
        return
    identity, geometry = s['identity'], s['geometry']
    pc, fault, page = geometry
    need(s['entry_checked'] == 1 and identity[:2] == [pid, pid] and
         identity[2] > 0 and identity[2] & 31 == 0 and identity[2] <= (1 << 64)-32 and
         identity[3] == identity[2] & ~4095 and identity[4] == 32 and identity[5] < 1 << 32 and
         0 < identity[6] <= parsed['rseq']['owner'][13] and
         0 < identity[7] == identity[8] <= parsed['native']['admissions'], 'actual retained registration')
    need(pc >= 0x200000000 and page == pc & ~4095 and page <= (1 << 64)-1-4096 and
         fault == page+4096 and 0 < fault-pc <= 14, 'exact current-PC adjacent-page geometry')
    need(s['words'] == [0]*3 and s['tls'][:2] == s['tls'][2:4] and
         s['tls'][4:6] == s['tls'][6:8] == s['tls'][8:], 'actual zero words and unchanged fresh TLS')
    row = dict(address=identity[2], page=identity[3])
    old._data(s['first_data'], row, pid); old._data(s['second_data'], row, pid)
    need(s['first_data'][:7] == s['second_data'][:7] and
         s['second_data'][23] > s['first_data'][23] and s['second_data'][25] > s['first_data'][25],
         'same pin through separate fresh first/second observations')
    if identity[6] == parsed['rseq']['owner'][13]:
        need(identity[2:6] == parsed['rseq']['owner'][9:13] and
             parsed['rseq']['identity'][0] == 1 and
             s['first_data'][2:5] == s['second_data'][2:5] == parsed['rseq']['identity'][1:4],
             'same current epoch joins the unchanged rseq owner and allocation')
    first, second = s['first_close'], s['second_close']
    _close(first, pid, 1, page); _close(second, pid, 0, 0)
    need(first[0] < (1 << 64)-1 and second[0] == first[0]+1 and first[1:5] == second[1:5],
         'zero-page second observation follows the preserved one-page close without lifecycle mutation')


def compact_public(parsed):
    result = old.compact_public(parsed)
    s = parsed['rseq_boundary']
    result['boundary'] = dict(status=s['status'], failure_code=s['failure_code'], phase=s['phase'],
        first_error=s['first_error'], attempted=s['counts'][0], handler_entries=s['counts'][1],
        authenticated_entries=s['counts'][2], zero_page_observations=s['counts'][3],
        tls_refreshes=s['counts'][4], completed=s['counts'][5])
    return result
