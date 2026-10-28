"""Explicit registered-native extension; all old report/closure checks remain.

The original LI2_RSEQ row describes the retained inactive-owner component.
LI2_RSEQ_NATIVE describes publication permitted only during native epochs.
A parsed prefix never confers completion, instruction-history or performance credit.
"""
import importlib.util
from pathlib import Path

from page_selected import need
import page_selected_rseq_compare as rseq

_PATH = Path(__file__).resolve().parent.parent/'cpuid_nx/reports.py'
_SPEC = importlib.util.spec_from_file_location('rseq_native_old_nx_reports', _PATH)
old = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(old)

SCALARS = set(('version status failure_code detail_abs detail_negative first_detail_abs first_detail_negative '
    'phase first_error unsafe_terminal entry_checked checking attempts admissions preentries entries closed '
    'tls_refreshes pid tid pc address page registration_epoch length signature native_admissions_before '
    'native_closed_before word_before word_entry word_after fs_before gs_before fs_after gs_after '
    'fs_selector_entry gs_selector_entry fs_selector_after gs_selector_after').split())


def reports(stderr):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete actual stderr')
    lines = stderr[:-1].split(b'\n')
    indexes = [i for i, x in enumerate(lines) if x.startswith(b'LI2_RSEQ_NATIVE ')]
    need(len(indexes) == 1, 'one actual registered-native report')
    at = indexes[0]
    need(at > 0 and lines[at-1].startswith(b'LI2_RSEQ ') and len(lines[at])+1 <= 4096,
         'bounded extension immediately after old inactive-owner component')
    row = rseq.decode(lines[at][len(b'LI2_RSEQ_NATIVE '):])
    old._unsigned(row, SCALARS, {'before': 28, 'after': 28}, 'registered_native_epochs')
    parsed = old.reports(b'\n'.join(lines[:at]+lines[at+1:])+b'\n', nx=True)
    need(all(row[k] == parsed['loader'][k] for k in
             ('status', 'failure_code', 'detail_abs', 'detail_negative')), 'same genuine terminal outcome')
    need(row['phase'] <= 4 and all(row[k] in (0, 1) for k in
         ('unsafe_terminal', 'entry_checked', 'checking', 'detail_negative', 'first_detail_negative')) and
         all(row[k] < 1 << 16 for k in
             ('fs_selector_entry', 'gs_selector_entry', 'fs_selector_after', 'gs_selector_after')),
         'exact epoch phase and scalar domains')
    need(row['closed'] <= row['entries'] <= row['admissions'] <= row['attempts'] and
         row['tls_refreshes'] <= row['closed'] and row['entries'] <= row['preentries'] and
         row['admissions'] <= parsed['native']['admissions'], 'actual epoch progress, never inferred completion')
    parsed['rseq_native'] = row
    return parsed


def _data(v, row, pid):
    need(v[0] == row['address'] and v[1] == row['page'] and v[2] > 0 and v[3] > 0 and
         v[5] == v[6] == pid and v[7:12] == [1, 1, 0, 0, 0], 'actual complete pinned page identity')
    need(v[12] < 1 << 31 and v[13:18] == [0]*5 and v[18] > 0 and v[19] > 0 and
         v[20:23] == [1, 1, 1] and v[23] > 0 and v[24] == 0 and v[25] > 0 and
         v[26:] == [0, 1], 'fresh direct maps acquisition with complete actual descriptor closure')


def completed(parsed, pid):
    old.completed(parsed, pid)  # Every original NX/native/chain/register/REP/rseq completion guard.
    s = parsed['rseq_native']
    need(s['status'] == s['failure_code'] == s['phase'] == s['first_error'] ==
         s['first_detail_abs'] == s['first_detail_negative'] == s['unsafe_terminal'] == s['checking'] == 0,
         'no pending or failed registered-native epoch')
    need(s['attempts'] == s['admissions'] == s['preentries'] == s['entries'] == s['closed'] ==
         s['tls_refreshes'], 'every actual registered-native admission closed and refreshed once')
    if not s['attempts']:
        need(all(s[k] == 0 for k in SCALARS-{'version'}) and s['before'] == s['after'] == [0]*28,
             'no invented registered-native work when no admission was attempted')
        return
    need(s['entry_checked'] == 1 and s['pid'] == s['tid'] == pid and s['pc'] >= 0x200000000 and
         s['address'] > 0 and s['address'] & 31 == 0 and s['address'] <= (1 << 64)-32 and
         s['page'] == s['address'] & ~4095 and s['length'] == 32 and s['signature'] < 1 << 32 and
         0 < s['registration_epoch'] <= parsed['rseq']['owner'][13], 'actual retained singleton registration')
    need(s['native_admissions_before'] == s['native_closed_before'] and
         s['native_admissions_before']+1 <= parsed['native']['admissions'] and
         s['word_before'] == s['word_entry'] == s['word_after'] == 0 and
         s['fs_selector_entry'] == s['fs_selector_after'] and
         s['gs_selector_entry'] == s['gs_selector_after'], 'original boundary words and actual refreshed selectors')
    _data(s['before'], s, pid); _data(s['after'], s, pid)
    if s['registration_epoch'] == parsed['rseq']['owner'][13]:
        owner, identity = parsed['rseq']['owner'], parsed['rseq']['identity']
        need([s[k] for k in ('address', 'page', 'length', 'signature')] == owner[9:13] and
             identity[0] == 1 and s['before'][2:5] == s['after'][2:5] == identity[1:4],
             'same current registration epoch joins exact old owner and actual allocation identity')
    need(s['before'][:7] == s['after'][:7] and s['after'][23] > s['before'][23] and
         s['after'][25] > s['before'][25], 'same pinned identity through distinct actual before/after acquisitions')


def compact_public(parsed):
    s = parsed['rseq_native']
    return dict(version=1, registered=parsed['rseq']['owner'][1], exercised=bool(s['admissions']),
                status=s['status'], failure_code=s['failure_code'], phase=s['phase'],
                attempted_epochs=s['attempts'], admitted_epochs=s['admissions'],
                handler_entries=s['preentries'], authenticated_entries=s['entries'],
                closed_epochs=s['closed'], tls_refreshes=s['tls_refreshes'],
                first_error=s['first_error'], unsafe_terminal=s['unsafe_terminal'])
