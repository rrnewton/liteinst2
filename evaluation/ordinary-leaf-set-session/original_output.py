"""Strict original LeafSet scalar transcript, never a process-closure oracle."""
import hashlib
import importlib.util
from pathlib import Path
import sys

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
_DEPENDENCY = Path(__file__).resolve().with_name('output.py')
assert hashlib.sha256(_DEPENDENCY.read_bytes()).hexdigest() == 'c804a953b97494d7ec4ff3cc94ff23a69b1a34d010bd332030ca938db97681b4'
_spec = importlib.util.spec_from_file_location('_leaf_original_truth', _DEPENDENCY)
_truth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_truth)
uint, fnv, truths = _truth.uint, _truth.fnv, _truth.truths
U64 = (1 << 64) - 1
OPERATIONS = ('csv_fields', 'length', 'ascii_digits', 'ascii_spaces')


def integer(value, low=0, high=U64):
    assert type(value) is int and low <= value <= high
    return value


def records_ok(records, n):
    integer(n, 1, 4)
    assert type(records) is tuple and len(records) <= min(2048, 4096 // n)
    return tuple(truths(data) for data in records)


def table_ok(table, caller, cpu):
    assert type(table) is tuple and 1 <= len(table) <= 4
    integer(cpu, 0, 1023)
    assert type(caller) is dict and set(caller) == {'extent', 'continuation'}
    integer(caller['extent'], 1, 256)
    integer(caller['continuation'], 1, caller['extent'] - 1)
    ids, ops, pages = set(), set(), set()
    end = 0
    for row in table:
        assert type(row) is dict and set(row) == {'function_id', 'operation', 'policy', 'elf_va', 'extent', 'returns'}
        identity = integer(row['function_id'])
        assert identity not in ids and type(row['operation']) is str and row['operation'] in OPERATIONS and row['operation'] not in ops
        ids.add(identity); ops.add(row['operation'])
        assert type(row['policy']) is str and row['policy'] in ('certified', 'whole')
        size = integer(row['extent'], 5 if row['policy'] == 'whole' else 1, 80 if row['policy'] == 'whole' else 256)
        va = integer(row['elf_va'], 1, U64 - size)
        assert va >= end
        end = va + size
        returns = row['returns']
        assert type(returns) is tuple and 1 <= len(returns) <= 4
        assert all(type(r) is int and 0 <= r < size for r in returns)
        assert tuple(sorted(set(returns))) == returns
        pages.update(range(va // 4096, (end - 1) // 4096 + 1))
    assert 1 <= len(pages) <= 2 and all(page * 4096 <= U64 - 4096 for page in pages)


def frame(records, *, n):
    records_ok(records, n)
    return b'MODCSV1\0' + len(records).to_bytes(4, 'little') + b''.join(bytes((len(data),)) + data for data in records)


def check(stdout, stderr, *, records, table, caller, cpu):
    """External caller must also require actual exit0 and exact normal closure."""
    table_ok(table, caller, cpu)
    expected = records_ok(records, len(table))
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 4 * 1024 * 1024 and stdout.endswith(b'\n') and b'\r' not in stdout
    lines = stdout.decode('ascii')[:-1].split('\n')
    assert len(lines) == 2 + len(table) + sum(len(t['returns']) for t in table) + len(records) <= 2070
    assert all(0 < len(line) and len(line) + 1 <= 350 for line in lines)
    rows = [line.split(',') for line in lines]
    assert len(rows[0]) == 8 and rows[0][:2] == ['LEAF_ORIGINAL_READY', 'leaf-original-v1']
    ready = dict(zip(('pid', 'tid', 'cpu', 'n', 'caller', 'records'), map(uint, rows[0][2:])))
    assert 0 < ready['pid'] <= (1 << 32) - 1 and ready['tid'] == ready['pid']
    assert ready['cpu'] == cpu and ready['n'] == len(table) and ready['records'] == len(records)
    assert 0 < ready['caller'] <= U64 - caller['extent']
    assert ready['caller'] < ready['caller'] + caller['continuation'] < ready['caller'] + caller['extent']
    at, base, actual_table, pages = 1, None, [], set()
    for index, item in enumerate(table):
        row = rows[at]; at += 1
        assert len(row) == 10 and row[0] == 'LEAF_ORIGINAL_FUNCTION'
        assert row[3:5] == [item['operation'], item['policy']]
        i, identity = map(uint, row[1:3])
        va, extent, entry, end, ret_count = map(uint, row[5:])
        assert (i, identity, va, extent, ret_count) == (index, item['function_id'], item['elf_va'], item['extent'], len(item['returns']))
        assert va <= entry <= U64 - extent and end == entry + extent
        bias = entry - va
        assert bias % 4096 == 0
        if base is None:
            base = bias
        assert bias == base
        pages.update(range(entry // 4096, (end - 1) // 4096 + 1))
        for offset in item['returns']:
            row = rows[at]; at += 1
            assert len(row) == 3 and row[0] == 'LEAF_ORIGINAL_RET'
            assert list(map(uint, row[1:])) == [index, offset]
        actual_table.append(dict(index=index, **item, entry=entry, end=end, return_count=ret_count))
    assert 1 <= len(pages) <= 2 and all(page * 4096 <= U64 - 4096 for page in pages)
    results = []
    for index, (data, values) in enumerate(zip(records, expected), 1):
        row = rows[at]; at += 1
        assert len(row) == 4 + len(table) and row[0] == 'LEAF_ORIGINAL'
        numbers = list(map(uint, row[1:]))
        assert numbers == [index, len(data), fnv(data)] + [values[t['operation']] for t in table]
        results.append(numbers)
    assert at == len(rows) - 1 and len(rows[at]) == 4 and rows[at][0] == 'LEAF_ORIGINAL_DONE'
    total = len(records) * len(table)
    assert list(map(uint, rows[at][1:])) == [len(records), total, total]
    return dict(status='ORIGINAL_SCALAR_PASS', ready=ready, table=actual_table, results=results,
                totals=dict(records=len(records), calls=total, returns=total), raw=stdout,
                scope='Original scalar values and declared geometry only; source/ELF/full decoded RET set/caller ABI/actual exit0/normal owner closure are separately required. No architectural-state, timing, scheduling or allocation claim.')


ORIGINAL_REFUSALS = (
    'bad_magic', 'count_over_2048', 'truncated_length', 'truncated_payload',
    'length_over_64', 'non_ascii_payload', 'malformed_csv', 'trailing_input_byte')


def refusal(stdout, stderr, exit_code, reason):
    """Inherited typed input refusal only; source, closure and deadline are external."""
    assert type(reason) is str and reason in ORIGINAL_REFUSALS
    assert type(exit_code) is int and exit_code == 2
    assert type(stdout) is bytes and stdout == b''
    assert type(stderr) is bytes
    assert stderr == b'module-session-original INPUT_REFUSED: ' + reason.encode('ascii') + b'\n'
    return dict(status='EXPECTED_INPUT_REFUSAL', reason=reason, exit_code=exit_code)
