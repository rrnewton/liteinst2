"""Strict finite optional frontend projections; complete state/journals stay Rust assertions."""
import csv
import re

HEADER = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value,observer_entries,helper_joins'
TEST = 'frontend_native::always_on::optional::tests::native::optional_native_reuse_and_old_owner'
PASS = 'optional-native PASS originals=96 calls=96 fast=32 slow=64 sampled=64 unsampled=0 rows=64 events=128 batches=3 capacity_refusals=2 empty_drains=3 epochs=2 report_records=64 actions=5 registrations=1 helper_joins=1 short_ret_refusals=1 detached=true input_unchanged=true'
REFUSAL = b'case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n'
SEEDS = (0x1234567887654320, 0xfedcba9801234567)


def pairs(table, refusal, terminal, slow):
    assert type(slow) is bool
    assert 0 < len(table) <= 1048576 and table.endswith(b'\n') and b'\r' not in table
    lines = table.decode('ascii').splitlines()
    assert len(lines) == 5 and lines[0] == HEADER
    rows = list(csv.DictReader(lines, strict=True))
    assert len(rows) == 4
    for row, (seed, length) in zip(rows, [(s, n) for s in SEEDS for n in (1, 64)]):
        assert set(row) == set(HEADER.split(',')) and row['status'] == 'PASS'
        for key in set(row)-{'status'}:
            assert isinstance(row[key], str) and re.fullmatch(r'0|[1-9][0-9]*', row[key])
            row[key] = int(row[key]); assert row[key] < 2**64
        assert (row['seed'], row['length'], row['children']) == (seed, length, 2)
        assert 0 < row['original_visits'] < row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        assert max(row['original_steps'], row['candidate_steps']) <= 20000
        assert row['observer_entries'] == (2 if slow else 0) and row['helper_joins'] == 1
        expected = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
    count = sum(row['comparisons'] for row in rows)
    mode = 'slow' if slow else 'fast'
    observers = 8 if slow else 0
    assert refusal == REFUSAL
    assert terminal == f'native-optional-{mode}:required=4:pairs=4:children=8:comparisons={count}:observer-entries={observers}:controller-transitions=4:helper-joins=4:short-ret-refusals=1:real-outer-ret=8:complete\n'.encode('ascii')
    return rows, count


def functional(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= 4096
    protocol = '\nrunning 1 test\ntest '+TEST+' ... '+PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', stdout.decode('ascii'))
    fields = dict(word.split('=', 1) for word in PASS.split()[2:])
    return {key: int(value) if value.isdecimal() else value == 'true' for key, value in fields.items()}
