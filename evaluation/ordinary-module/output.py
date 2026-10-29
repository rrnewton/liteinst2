"""Strict functional transcript joins; process custody is a separate prerequisite."""
import re
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
HEADER = 'ordinal,function,case,length,expected,original,installed,return_offset,owner,invocation_plus_one,history_prefix,entry_rsp,return_word,start_ticks,end_ticks,start_aux,end_aux,ack,ack_ordinal'
CSV_LENGTHS = (0, 1, 5, 1, 2, 2, 2, 2, 5, 7, 9, 8, 4, 5, 24, 29)
CSV_VALUES = (1, 1, 3, 2, 3, 2, 2, 1, 1, 2, 3, 2, 1, 2, 4, 3)
LENGTH_BOUNDS = (0, 1, 1, 2, 17, 64, 64, 64)
LENGTH_VALUES = (0, 0, 1, 1, 8, 0, 63, 64)
TERMINAL_KEYS = 'k originals installed functions shared_source_pages records actions journal_words completed unsampled next_entry checkpoints pid tid cpu generation entry0 entry1 length0 length1 caller_entry returns0 returns1 install function0 function1 registration'.split()


def uint(value):
    assert re.fullmatch(r'0|[1-9][0-9]{0,19}', value)
    number = int(value)
    assert number < 2**64
    return number


def check(stdout, stderr, k, lengths, returns, continuation, cpu):
    assert type(stdout) is bytes and 0 < len(stdout) <= 16384 and stderr == b''
    assert k in (16, 1) and len(lengths) == len(returns) == 2
    assert 5 <= lengths[0] <= 256 and 5 <= lengths[1] <= 80
    assert all(1 <= len(s) <= 4 and list(s) == sorted(set(s)) for s in returns)
    assert all(0 < offset < lengths[f] for f in (0, 1) for offset in returns[f])
    assert stdout.endswith(b'\n') and all(b == 10 or 32 <= b < 127 for b in stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert len(lines) == 34 and lines[0] == HEADER
    head = HEADER.split(','); rows = []
    for line in lines[1:33]:
        fields = line.split(','); assert len(fields) == len(head)
        rows.append(dict(zip(head, map(uint, fields))))
    words = lines[33].split(' ')
    assert words[:2] == ['normal-module-work', 'MODULE_FUNCTIONAL_PASS'] and all(words)
    pairs = [word.split('=') for word in words[2:]]
    assert all(len(p) == 2 for p in pairs)
    assert [p[0] for p in pairs] == TERMINAL_KEYS
    t = {name: uint(value) for name, value in pairs}
    fixed = dict(k=k, originals=32, installed=32, functions=2, shared_source_pages=1,
        records=32, actions=2, journal_words=512, completed=2*k, unsampled=32-2*k,
        next_entry=31, checkpoints=1, install=0x6d6f6401, function0=101, function1=202, registration=1)
    assert all(t[name] == value for name, value in fixed.items())
    assert 0 < t['pid'] == t['tid'] < 2**32 and t['cpu'] == cpu < 1024 and t['generation'] > 0
    assert 0 < t['entry0'] and t['entry0'] + lengths[0] <= t['entry1'] < 2**64 - lengths[1]
    assert t['entry0'] // 4096 == (t['entry1'] + lengths[1] - 1) // 4096
    assert [t['length0'], t['length1']] == list(lengths)
    assert [t['returns0'], t['returns1']] == [len(s) for s in returns]
    assert 0 < continuation and 0 < t['caller_entry'] < t['caller_entry'] + continuation < 2**64
    observed = [set(), set()]
    for i, r in enumerate(rows):
        f = i % 2; case = i // 2 if f == 0 else (i // 2) % 8
        bounds = CSV_LENGTHS if f == 0 else LENGTH_BOUNDS
        values = CSV_VALUES if f == 0 else LENGTH_VALUES
        assert r['ordinal'] == i+1 and r['function'] == (101, 202)[f] and r['case'] == case+1
        assert r['length'] == bounds[case] and r['expected'] == r['original'] == r['installed'] == values[case]
        sampled = i < 2*k
        assert r['owner'] == (1 if sampled else 3) and r['invocation_plus_one'] == (i+1 if sampled else 0)
        assert r['history_prefix'] == 1 and r['ack'] == (2 if i == 31 else 1)
        assert r['ack_ordinal'] == (0 if i == 31 else i+2)
        assert r['return_offset'] in returns[f]
        observed[f].add(r['return_offset'])
        assert 128 <= r['entry_rsp'] <= 2**64 - 1 - 8
        assert r['entry_rsp'] % 16 == 8 and r['return_word'] == t['caller_entry'] + continuation
        assert r['start_aux'] == r['end_aux'] < 2**32 and r['start_ticks'] <= r['end_ticks']
    assert observed == [set(s) for s in returns]
    return dict(terminal=t, rows=rows, table=('\n'.join(lines[:33])+'\n').encode('ascii'))
