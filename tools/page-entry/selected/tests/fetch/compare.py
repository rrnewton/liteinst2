"""Complete fetch case table and saved-record comparator; no workload execution."""
import json

CASES = {
    'anon_one': 0, 'anon_two': 0, 'sealed_one': 0, 'sealed_two': 0,
    'release_open': 305, 'stale_ref': 0, 'occupied': 0, 'source_changed': 306,
    'wrong_mapping': 114, 'writable_alias': 119, 'closed_backing': 307,
    'copied_identity': 0, 'second_missing': 113, 'beyond_eof': 307,
    'unowned': 305, 'read_fault': 106, 'close_fault': 107, 'read_close_fault': 106,
}

def need(value, why):
    if not value:
        raise ValueError(why)

def parse(name, data):
    row = json.loads(data)
    need(row['schema'] == 1 and row['case'] == name and row['status'] == 'passed', 'fixture identity')
    need(row['expected_error'] == CASES[name] and len(row['instruction_hex']) == 30 and row['instruction_hex'] == '49bc01020304050607089090909090', 'exact case outcome/source')
    need(row['events'] and row['events'][0]['name'] == 'prepare' and row['raw'], 'actual operation prefix')
    first, last = row['events'][0], row['events'][-1]
    if CASES[name]:
        need(last['error'] == CASES[name] and last['held'] == 1, 'sticky failed owner retained')
    else:
        need(last['error'] == 0 and last['held'] == 0 and last['complete'] == 1, 'successful actual release')
    if name in ('anon_one', 'sealed_one', 'anon_two', 'sealed_two'):
        pages = 2 if name.endswith('_two') else 1
        need(row['owner_opened'] == row['owner_closed'] == pages and row['owner_synced'] == 2 * pages, 'actual owner permission closure')
        need(first['bytes'] == 15 and first['pages'] == pages and row['partial_hex'] == row['instruction_hex'], 'complete copied source')
    if name in ('release_open', 'closed_backing'):
        need(row['owner_opened'] == row['owner_closed'] == 1 and row['owner_synced'] == 2, 'real revoke despite sticky error')
    if name == 'occupied':
        need(row['interlock_denials'] == 1, 'actual interlock branch')
    if name == 'copied_identity':
        pid, tid, result, waited = row['child']
        need(pid > 0 and pid == tid == waited and result == 304, 'actual copied process identity refusal/reap')
        need(row['child_prefix'][:4] == [1, 1, 304, 0] and row['child_prefix'][4:6] == [1, 15], 'retained copied-child prefix')
    if name == 'closed_backing':
        need(row['last_backing'][1:5] == [-9, 0, 1, 0], 'actual failed backing observation')
    if name in ('second_missing', 'beyond_eof', 'unowned', 'read_fault', 'close_fault', 'read_close_fault'):
        need(first['bytes'] == 0 and not first['complete'] and row['partial_hex'] == '', 'no unauthenticated source copy')
    if name in ('second_missing', 'beyond_eof'):
        need(first['pages'] == 1, 'initialized page prefix')
    if name in ('read_fault', 'close_fault', 'read_close_fault'):
        read, close, bad_read, good_close, bad_close = row['injected']
        need(read == (name != 'close_fault') and close == (name != 'read_fault'), 'explicit fault family')
        p = first['prepare']
        need(p['opened'] == 1 and p['bytes'] > 0 and p['close_started'] == 1 and p['closed'] == (not close) and p['rows'] == 0, 'maps failure prefix')
        if read:
            need(bad_read == -9 and first['detail'] == -9, 'actual EBADF read preserved')
        if close:
            need(good_close == 0 and bad_close == -9 and p['close'] == -9, 'actual close-before-close error')
    need(row['lifecycle'][2] == 0, 'fixture never grants legacy admission')
    return row
