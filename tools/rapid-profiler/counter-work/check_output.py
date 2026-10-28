"""Strict finite probe export; successful parsing is not counter qualification."""
import csv
import io
import re
from pathlib import Path

SEEDS = (0x1234567887654320, 0xfedcba9801234567)
CASES = ('reuse4', 'cold16', 'chase8', 'fit2', 'conflict3', 'capacity12')
CYCLES = ((0, 1, 2, 3), tuple(range(16)), (0, 3, 6, 1, 4, 7, 2, 5), (0, 4), (0, 4, 8), tuple(range(12)))
P = 'external_id,seed,case,status,invoked,value,expected,pre_call_rsp,resumed_rsp,invocation_error'
C = 'external_id,event_id,start_value,start_enabled,start_running,end_value,end_enabled,end_running,delta_value,delta_enabled,delta_running,before_cpu,before_pid,before_tid,before_vendor,before_family,before_model,before_stepping,after_cpu,after_pid,after_tid,after_vendor,after_family,after_model,after_stepping,requested_attributes,attributes_after_open,issues'
O = 'external_id,index,operation,result,errno,data_len,data_hex'

def table(data, header):
    assert 0 < len(data) <= 65536 and data.endswith(b'\n')
    assert all(x == 10 or 32 <= x <= 126 for x in data), 'literal LF and printable ASCII only'
    assert data.split(b'\n')[0].decode('ascii') == header
    rows = list(csv.DictReader(io.StringIO(data.decode('ascii')), strict=True))
    assert len(rows) <= 84
    assert all(set(r) == set(header.split(',')) and all(isinstance(x, str) for x in r.values()) for r in rows)
    return rows

def uint(word):
    assert re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word); assert value < 2**64
    return value

def sint(word):
    assert re.fullmatch(r'0|-?[1-9][0-9]*', word)
    value = int(word); assert -(2**63) <= value < 2**63
    return value

def scalar(seed, case):
    key, mask = 0x9e3779b97f4a7c15, 2**64-1
    cycle = CYCLES[case]; n = 16 if case == 1 else 64
    return (sum(seed ^ ((key*(cycle[j % len(cycle)]+1)) & mask) for j in range(n)) & mask) ^ key

def issues(text):
    assert text.startswith('[') and text.endswith(']')
    if text == '[]': return []
    depth, start, parts = 0, 1, []
    for i, ch in enumerate(text[1:-1], 1):
        if ch in '({': depth += 1
        elif ch in ')}': depth -= 1; assert depth >= 0
        elif ch == ',' and depth == 0: parts.append(text[start:i]); start = i+2; assert text[i+1] == ' '
    assert depth == 0; parts.append(text[start:-1]); assert all(parts)
    return parts

def cpu_fields(row, leg):
    fields = [row[leg+'_'+x] for x in ('cpu','pid','tid','vendor','family','model','stepping')]
    if not any(fields): return None
    assert all(fields)
    assert uint(fields[0]) < 1024 and uint(fields[1]) == uint(fields[2]) > 0
    assert fields[3] == b'AuthenticAMD'.hex() and uint(fields[4]) == 26
    assert uint(fields[5]) < 256 and uint(fields[6]) < 16
    return fields

def cpu_issue(tokens, leg):
    prefix = 'Cpu'+leg
    found = [x for x in tokens if x.startswith(prefix+'(')]
    assert len(found) == 1
    pattern = prefix+r'\((?:NotSingleton|UnsupportedVendorOrFamily|(Affinity|CurrentCpu|Identity)\(Syscall \{ result: (-?(?:0|[1-9][0-9]*)), errno: (None|Some\([1-9][0-9]*\)) \}\))\)'
    match = re.fullmatch(pattern, found[0]); assert match
    if match[1] is not None:
        kind, value, error = match[1], sint(match[2]), match[3]
        assert (value < 0) == (error != 'None')
        if error != 'None': assert 0 < uint(error[5:-1]) < 4096
        if kind in ('Affinity', 'CurrentCpu'): assert value == -1
        else: assert value <= 0 or value > 2**31-1
    return found[0]

def counter(row, group, invoked):
    """Derive the exact success/failure prefix and all retained endpoint joins."""
    tokens = issues(row['issues']); expected_issues = []
    before, after = cpu_fields(row, 'before'), cpu_fields(row, 'after')
    if before is None:
        expected_issues.append(cpu_issue(tokens, 'Before'))
        assert group == [] and row['attributes_after_open'] == ''
        assert not invoked and after is None and row['event_id'] == ''
        assert all(row[leg+'_'+field] == '' for leg in ('start','end','delta') for field in ('value','enabled','running'))
        assert tokens == expected_issues
        return False
    assert len(row['attributes_after_open']) == 256
    at = 0
    def take(name, read=False):
        nonlocal at
        assert at < len(group)
        op = group[at]; at += 1; assert op['operation'] == name
        result = sint(op['result']); size = uint(op['data_len'])
        if name == 'Open':
            assert -1 <= result <= 2**31-1 and size == 0
            ok = result >= 0
        elif read:
            assert -1 <= result <= 32
            assert size == max(0,result)
            ok = result == 32
        else:
            assert result in (-1,0)
            assert size == (8 if name == 'Id' and result == 0 else 0)
            ok = result == 0
        if not ok:
            expected_issues.append(f'{"ReadSize" if read and result >= 0 else "Operation"}({name})')
        return ok, bytes.fromhex(op['data_hex'])
    def reading(leg, raw, complete):
        fields = [row[leg+'_'+f] for f in ('value','enabled','running')]
        if not complete: assert fields == ['','','']; return None
        words = [int.from_bytes(raw[i:i+8], 'little') for i in range(0,32,8)]
        assert [uint(x) for x in fields] == words[:3]
        if words[3] != uint(row['event_id']):
            expected_issues.append(f'EventId(ReadDisabled{leg.title()})')
        return words[:3]
    opened, _ = take('Open')
    start = end = None
    enabled = False
    if opened:
        got_id, data = take('Id')
        if got_id:
            assert uint(row['event_id']) == int.from_bytes(data, 'little')
            complete, raw = take('ReadDisabledStart', True)
            start = reading('start', raw, complete)
            if start is not None and start != [0,0,0]: expected_issues.append('NotFresh')
            if not expected_issues:
                enabled, _ = take('Enable')
                if enabled:
                    take('Disable')
                    complete, raw = take('ReadDisabledEnd', True)
                    end = reading('end', raw, complete)
                    if after is None: expected_issues.append(cpu_issue(tokens, 'After'))
                    elif before != after: expected_issues.append('CpuChanged')
        else: assert row['event_id'] == ''
        take('Close')
    else: assert row['event_id'] == ''
    assert at == len(group) and invoked == enabled
    if not enabled: assert after is None
    for leg, value in (('start',start),('end',end)):
        if value is None: assert all(row[leg+'_'+f] == '' for f in ('value','enabled','running'))
    arithmetic = start == [0,0,0] and end is not None and end[1] == end[2] > 0
    if enabled and not arithmetic: expected_issues.append('Arithmetic')
    assert tokens == expected_issues
    full = enabled and arithmetic and not expected_issues
    if full:
        assert [uint(row['delta_'+f]) for f in ('value','enabled','running')] == end
    else:
        assert all(row['delta_'+f] == '' for f in ('value','enabled','running'))
    return full

def check(population, counters, operations, stdout, stderr):
    assert stderr == b''
    p, c, o = table(population, P), table(counters, C), table(operations, O)
    assert len(p) == 12 and 1 <= len(c) <= 12
    failed, invoked, observed = False, 0, 0
    all_ops = []
    cpu_identity = None
    for i, row in enumerate(p):
        seed, case = SEEDS[i//6], i % 6
        assert (uint(row['external_id']), uint(row['seed']), row['case'], uint(row['expected'])) == (i+1, seed, CASES[case], scalar(seed, case))
        if failed:
            assert row['status'] == 'UNRUN' and row['invoked'] == 'false'
            assert all(row[k] == '' for k in ('value','pre_call_rsp','resumed_rsp','invocation_error'))
            continue
        assert i < len(c)
        r = c[i]; assert uint(r['external_id']) == i+1
        group = [x for x in o if uint(x['external_id']) == i+1]
        assert len(group) <= 7
        for n, op in enumerate(group):
            assert uint(op['index']) == n
            sint(op['result'])
            if op['errno'] != '': assert sint(op['result']) < 0 and 0 < uint(op['errno']) < 4096
            else: assert sint(op['result']) >= 0
            size = uint(op['data_len']); assert size <= 32
            assert re.fullmatch('[0-9a-f]*', op['data_hex']) and len(op['data_hex']) == size*2
        all_ops.extend(group)
        attr = bytes.fromhex(r['requested_attributes'])
        assert len(attr) == 128
        expected_attr = bytearray(128)
        for at, size, value in ((0,4,4),(4,4,128),(8,8,0x0964),(32,8,7),(40,8,0x100065)):
            expected_attr[at:at+size] = value.to_bytes(size, 'little')
        assert attr == expected_attr
        assert re.fullmatch('[0-9a-f]*', r['attributes_after_open'])
        assert len(r['attributes_after_open']) in (0,256)
        assert row['invoked'] in ('true','false'); invoked += row['invoked'] == 'true'
        full = counter(r, group, row['invoked'] == 'true')
        for key in ('value','pre_call_rsp','resumed_rsp'):
            if row[key] != '': uint(row[key])
        if row['invoked'] == 'false':
            assert all(row[k] == '' for k in ('value','pre_call_rsp','resumed_rsp','invocation_error'))
        else:
            returned = all(row[k] != '' for k in ('value','pre_call_rsp','resumed_rsp'))
            assert returned or (all(row[k] == '' for k in ('value','pre_call_rsp','resumed_rsp')) and row['invocation_error'] != '')
        if row['status'] == 'FAILED':
            failed = True
            assert i+1 == len(c)
            assert r['issues'] != '[]' or row['invocation_error'] != '' or row['value'] != row['expected'] or row['pre_call_rsp'] != row['resumed_rsp']
            continue
        assert row['status'] == 'OBSERVED_FULL_RUNNING' and row['invoked'] == 'true'
        assert full
        assert row['invocation_error'] == '' and uint(row['value']) == scalar(seed, case)
        assert uint(row['pre_call_rsp']) == uint(row['resumed_rsp']) > 0
        assert r['issues'] == '[]' and r['requested_attributes'] == r['attributes_after_open']
        before = [r['before_'+x] for x in ('cpu','pid','tid','vendor','family','model','stepping')]
        after = [r['after_'+x] for x in ('cpu','pid','tid','vendor','family','model','stepping')]
        assert before == after
        assert uint(before[0]) < 1024 and uint(before[1]) == uint(before[2]) > 0
        assert before[3] == b'AuthenticAMD'.hex() and uint(before[4]) == 26
        assert uint(before[5]) < 256 and uint(before[6]) < 16
        if cpu_identity is None: cpu_identity = before
        assert before == cpu_identity
        assert [x['operation'] for x in group] == ['Open','Id','ReadDisabledStart','Enable','Disable','ReadDisabledEnd','Close']
        assert sint(group[0]['result']) >= 0
        assert [sint(x['result']) for x in group[1:]] == [0,32,0,0,32,0]
        assert all(x['errno'] == '' for x in group)
        assert [uint(x['data_len']) for x in group] == [0,8,32,0,0,32,0]
        event_id = uint(r['event_id'])
        assert int.from_bytes(bytes.fromhex(group[1]['data_hex']), 'little') == event_id
        for label, op in (('start',group[2]),('end',group[5])):
            raw = bytes.fromhex(op['data_hex'])
            words = [int.from_bytes(raw[n:n+8], 'little') for n in range(0,32,8)]
            assert words == [uint(r[label+'_'+x]) for x in ('value','enabled','running')]+[event_id]
        assert [uint(r['start_'+x]) for x in ('value','enabled','running')] == [0,0,0]
        for field in ('value','enabled','running'):
            assert uint(r['delta_'+field]) == uint(r['end_'+field]) - uint(r['start_'+field])
        assert uint(r['delta_enabled']) == uint(r['delta_running']) > 0
        observed += 1
    assert all_ops == o
    assert len(c) == observed + int(failed)
    status = 'FAILED' if failed else 'OBSERVED'
    assert stdout == (f'counter-probe required=12 invoked={invoked} observed_full_running={observed} status={status} scope=whole-original-api hardware_accuracy=unqualified model11h_semantics=unqualified\n').encode('ascii')
    return dict(status=status, required=12, attempted=len(c), invoked=invoked, observed_full_running=observed,
                unrun=12-len(c), raw_event=0x0964, hardware_accuracy='unqualified', model11h_semantics='unqualified',
                scope='whole original API invocation including owner checks and observer dispatch; no scaling or reset')

def directory(path, stdout, stderr):
    path = Path(path)
    return check(*( (path/name).read_bytes() for name in ('population.csv','counters.csv','operations.csv')), stdout, stderr)
