"""Parent-only original scalar transcript; process/source/native authority is external."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import hashlib
import importlib.util
from pathlib import Path
import re

_DEPENDENCY = Path(__file__).resolve().parents[1] / 'ordinary-leaf-set-session/output.py'
assert not _DEPENDENCY.is_symlink() and _DEPENDENCY.is_file()
assert hashlib.sha256(_DEPENDENCY.read_bytes()).hexdigest() == '83f12525c59f6ad31736d82db545ddc15a3c8682c1c66b30982ed4c627c8fa67'
_spec = importlib.util.spec_from_file_location('_call_pair_original_truth', _DEPENDENCY)
_truth = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_truth)
uint, fnv, truths = _truth.uint, _truth.fnv, _truth.truths
U64 = (1 << 64) - 1
PROFILE = 'call-pair-original-v1'
STATUS = 'CALL_PAIR_ORIGINAL_SCALAR_PASS'
ORIGINAL_REFUSALS = ('bad_magic', 'count_over_2048', 'truncated_length', 'truncated_payload',
    'length_over_64', 'non_ascii_payload', 'malformed_csv', 'trailing_input_byte')


def integer(value, low=0, high=U64):
    assert type(value) is int and low <= value <= high
    return value


def records_ok(records):
    assert type(records) is tuple and len(records) <= 2048
    for record in records:
        assert type(record) is tuple and len(record) == 2
        data, fields = record
        integer(fields, 1, 65)
        assert truths(data)['csv_fields'] == fields


def geometry_ok(geometry, caller, cpu):
    integer(cpu, 0, 1023)
    assert type(geometry) is dict and set(geometry) == {'parent', 'child'}
    parent, child = geometry['parent'], geometry['child']
    base = {'elf_va', 'length', 'heads', 'edges', 'returns'}
    assert type(parent) is dict and set(parent) == base | {'call_offset', 'continuation_offset', 'child_delta', 'callee_entry', 'body_hex'}
    assert type(child) is dict and set(child) == base
    pages = set()
    for node, body in enumerate((parent, child)):
        length = integer(body['length'], 1 if node else 5, 256 if node else 80)
        va = integer(body['elf_va'], 1, U64 - length)
        heads = body['heads']; returns = body['returns']
        assert type(heads) is list and heads and heads[0] == 0 and heads == sorted(set(heads))
        for head in heads: integer(head, 0, length - 1)
        assert all(1 <= b - a <= 15 for a, b in zip(heads, heads[1:] + [length]))
        assert type(returns) is list and 1 <= len(returns) <= (4 if node else 1)
        assert returns == sorted(set(returns)) and all(integer(r, 0, length - 1) in heads for r in returns)
        integer(body['edges'], len(heads) - len(returns), 2 * (len(heads) - len(returns)))
        pages.update(range(va // 4096, (va + length - 1) // 4096 + 1))
    assert parent['elf_va'] + parent['length'] <= child['elf_va'] or child['elf_va'] + child['length'] <= parent['elf_va']
    assert 1 <= len(pages) <= 2 and all(page * 4096 <= U64 - 4096 for page in pages)
    assert parent['returns'] == [parent['length'] - 1] and parent['edges'] == len(parent['heads']) - 1
    call = integer(parent['call_offset'], 1, parent['length'] - 5)
    cont = integer(parent['continuation_offset'], 1, parent['length'] - 1)
    assert call in parent['heads'] and cont == call + 5
    assert parent['heads'][parent['heads'].index(call) + 1] == cont
    assert integer(parent['child_delta']) in (16, 32, 48, 64)
    assert integer(parent['callee_entry'], 1) == child['elf_va']
    raw = parent['body_hex']
    assert type(raw) is str and re.fullmatch('[0-9a-f]{' + str(2 * parent['length']) + '}', raw)
    code = bytes.fromhex(raw)
    assert code[-1] == 0xc3 and code[call] == 0xe8
    assert parent['elf_va'] + cont + int.from_bytes(code[call + 1:cont], 'little', signed=True) == child['elf_va']
    assert type(caller) is dict and set(caller) == {'extent', 'continuation'}
    integer(caller['extent'], 1, 256); integer(caller['continuation'], 1, caller['extent'] - 1)


def frame(records):
    records_ok(records)
    return b'MODCSV1\0' + len(records).to_bytes(4, 'little') + b''.join(bytes((len(data),)) + data for data, _ in records)


def refusal(stdout, stderr, exit_code, reason):
    assert type(reason) is str and reason in ORIGINAL_REFUSALS
    assert type(exit_code) is int and exit_code == 2
    assert type(stdout) is bytes and stdout == b'' and type(stderr) is bytes
    assert stderr == b'module-session-original INPUT_REFUSED: ' + reason.encode('ascii') + b'\n'
    return dict(status='EXPECTED_INPUT_REFUSAL', reason=reason, exit_code=exit_code)


def check(stdout, stderr, *, records, geometry, caller, cpu):
    """The caller must join exact source/ELF/caller ABI, actual exit0 and normal closure."""
    records_ok(records); geometry_ok(geometry, caller, cpu)
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 4 * 1024 * 1024 and stdout.endswith(b'\n')
    assert re.fullmatch(rb'[\x20-\x7e\n]+', stdout)
    lines = stdout[:-1].decode('ascii').split('\n')
    assert all(line and len(line) + 1 <= 350 for line in lines)
    expected_lines = 5 + sum(len(geometry[n]['returns']) for n in ('parent', 'child')) + len(records)
    assert len(lines) == expected_lines <= 2058
    rows = [line.split(',') for line in lines]
    assert len(rows[0]) == 11 and rows[0][:2] == ['ORIGINAL_READY', PROFILE]
    ready = dict(zip(('pid', 'tid', 'cpu', 'parent_entry', 'parent_end', 'child_entry', 'child_end', 'caller_entry', 'records'), map(uint, rows[0][2:])))
    assert 0 < ready['pid'] <= (1 << 32) - 1 and ready['tid'] == ready['pid']
    assert ready['cpu'] == cpu and ready['records'] == len(records)
    integer(ready['caller_entry'], 1, U64 - caller['extent'])
    at, bias, table = 1, None, []
    for node, name in enumerate(('parent', 'child')):
        body = geometry[name]; row = rows[at]; at += 1
        assert len(row) == 7 and row[0] == 'ORIGINAL_FUNCTION'
        index, va, extent, entry, end, count = map(uint, row[1:])
        assert (index, va, extent, count) == (node, body['elf_va'], body['length'], len(body['returns']))
        assert va <= entry <= U64 - extent and end == entry + extent
        assert (entry, end) == (ready[name + '_entry'], ready[name + '_end'])
        delta = entry - va; assert delta % 4096 == 0
        if bias is None: bias = delta
        assert bias == delta
        for offset in body['returns']:
            row = rows[at]; at += 1
            assert len(row) == 3 and row[0] == 'ORIGINAL_RET' and list(map(uint, row[1:])) == [node, offset]
        table.append(dict(node=node, elf_va=va, extent=extent, entry=entry, end=end, return_count=count, returns=tuple(body['returns'])))
    for body in table:
        assert ((body['end'] - 1) // 4096) * 4096 <= U64 - 4096
        assert body['end'] <= ready['caller_entry'] or ready['caller_entry'] + caller['extent'] <= body['entry']
    row = rows[at]; at += 1
    assert len(row) == 5 and row[0] == 'ORIGINAL_EDGE'
    edge = dict(zip(('call_pc', 'child_entry', 'continuation', 'child_delta'), map(uint, row[1:])))
    parent = geometry['parent']
    assert list(edge.values()) == [ready['parent_entry'] + parent['call_offset'], ready['child_entry'], ready['parent_entry'] + parent['continuation_offset'], parent['child_delta']]
    results = []
    for index, (data, fields) in enumerate(records, 1):
        row = rows[at]; at += 1
        assert len(row) == 6 and row[0] == 'ORIGINAL'
        values = list(map(uint, row[1:]))
        assert values == [index, len(data), fnv(data), fields, (len(data) << 32) | fields]
        results.append(values)
    assert at == len(rows) - 1 and len(rows[at]) == 4 and rows[at][0] == 'ORIGINAL_DONE'
    assert list(map(uint, rows[at][1:])) == [len(records)] * 3
    return dict(status=STATUS, ready=ready, table=table, edge=edge, results=results,
        totals=dict(records=len(records), root_calls=len(records), root_returns=len(records)), raw=stdout,
        scope='Parent-only original scalar reference; exact source/ELF/decoded E8 and RET geometry/C caller ABI/process exit0/normal closure require external joins. No Rust-caller full-state, Schedule, timing or full-A5 authority.')
