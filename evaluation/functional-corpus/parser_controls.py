"""Five metadata controls on CLOSED and explicit synthetic data; no backend execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import sys
import time

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit('Use Python -I -B')
for key, value in ((resource.RLIMIT_CPU, 30), (resource.RLIMIT_AS, 256 * 1024**2),
                   (resource.RLIMIT_FSIZE, 8 * 1024**2), (resource.RLIMIT_CORE, 0)):
    resource.setrlimit(key, (value, value))
assert len(sys.argv) == 2 and len(os.sched_getaffinity(0)) == 1
root = Path.cwd()
packet = Path(__file__).resolve().parent
out = root / 'ignored/a3/functional-corpus-controls-v1'
assert not out.exists()
out.mkdir(mode=0o700)


def read(path, expected):
    data = path.read_bytes()
    assert len(data) == expected[0] and hashlib.sha256(data).hexdigest() == expected[1]
    return data


runner = packet / 'run.py'
runner_bytes = runner.read_bytes()
assert hashlib.sha256(runner_bytes).hexdigest() == sys.argv[1]
spec = importlib.util.spec_from_file_location('fixed_corpus_controls', runner)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
request = root / 'ignored/a3/overlapping-neighbor-functional-prepare-v1/cwd/request.jsonl'
request_data = read(request, (2586720, 'bb4146fe44138559a769376c215ccc40c32c203dd157aa7dfe32863bd8bd104e'))
log = root / 'ignored/a3/overlapping-neighbor-functional-compare-v1/original.log'
log_data = read(log, (2043698, 'bb4dc9850c143ed3df0f5b9092af9d063428a2ce66e9133ee992c47225cd0548'))
defs = json.loads(read(packet / 'definitions.json', (3397, '3a9840b193779ec590cc5b189f3dac4b9671ffc55689b5caf18095de63a20d78')))
started = time.monotonic()
info, lengths = p.request(request, 'e9patch', p.ACTIONS[0], defs)
assert info['requested'] == 12924 and info['text'] == [9328, 9328, 52267]
info['source'] = 'e9patch'
stats = p.statistics(log, info, lengths, 2329308)
assert stats['successful'] == 12919 and stats['requested'] == 12924 and stats['strict_full'] is False
assert stats['failed'] == 5 and stats['tactics'] == dict(B1=4901, B2=8018, T1=0, T2=0, T3=0)
expected_failures = [(0xd9b9, 1), (0xd266, 1), (0xbe6b, 1), (0xa988, 1), (0x3835, 1)]
assert stats['failed_tuples_sha256'] == hashlib.sha256(json.dumps(expected_failures, separators=(',', ':')).encode()).hexdigest()
checks = ['complete_original_request_accepted', 'partial_original_log_retains_strict_failure']

# Add a head inside a real multi-byte instruction. All original heads still
# form a complete partition; only the extra overlapping head must be refused.
rows = [json.loads(line) for line in request_data.splitlines()]
instructions = [r['params'] for r in rows if r['method'] == 'instruction']
candidate = next(d for d in instructions if d['length'] > 1)
extra = dict(address=candidate['address'] + 1, offset=candidate['offset'] + 1, length=1)
assert extra['offset'] not in {d['offset'] for d in instructions}
declarations = sorted(instructions + [extra], key=lambda d: d['offset'], reverse=True)
mutated = rows[:2] + [dict(method='instruction', params=d) for d in declarations]
mutated += [dict(method='patch', params=dict(offset=d['offset'], trampoline='passthru')) for d in declarations]
mutated.append(rows[-1])
mutated = [dict(jsonrpc='2.0', method=r['method'], params=r['params'], id=i) for i, r in enumerate(mutated)]
bad_request = out / 'overlapping-head.jsonl'
bad_request.write_text(''.join(json.dumps(r, separators=(',', ':')) + '\n' for r in mutated))
try:
    p.request(bad_request, 'e9patch', p.ACTIONS[0], defs)
except AssertionError:
    checks.append('extra_interior_head_refused')
else:
    raise AssertionError('Overlapping head was accepted')

# Swap one failure with its preceding success, preserving each class's own
# ordering, counts and all final statistics. The merged request order changes.
events = list(re.finditer(rb'debug: (?:patched instruction [^\n]+|failed to patch instruction[^\n]+)', log_data))
index = next(i for i, match in enumerate(events) if i and b'failed to patch' in match[0] and b'patched instruction' in events[i-1][0])
left, right = events[index-1], events[index]
bad_log_data = log_data[:left.start()] + right[0] + log_data[left.end():right.start()] + left[0] + log_data[right.end():]
bad_log = out / 'reordered-events.log'; bad_log.write_bytes(bad_log_data)
try:
    p.statistics(bad_log, info, lengths, 2329308)
except AssertionError:
    checks.append('changed_combined_event_order_refused')
else:
    raise AssertionError('Changed combined event order was accepted')
# This is synthetic parser input, not an observed backend outcome. One failure
# among 20,001 heads rounds to 100.00% in the stock two-decimal summary, which
# adds a tilde specifically to distinguish it from complete coverage.
synthetic_n, synthetic_base = 20001, 0x10000
synthetic_lengths = bytearray([1]) * synthetic_n
synthetic_info = dict(requested=synthetic_n, text=[synthetic_base, synthetic_base, synthetic_n], source='e9patch')
synthetic_events = [
    f'debug: patched instruction 0x{synthetic_base+j:x} [size=1, tactic=B1, trampoline=0x100000..0x100005]\n'
    for j in range(synthetic_n - 1, 0, -1)
]
synthetic_events.append(f'debug: failed to patch instruction at address 0x{synthetic_base:x} (1)\n')
synthetic_summary = [
    'input_binary          = /proc/self/fd/3\n',
    'input_mode            = EXECUTABLE\n',
    'input_file_size       = 93520\n',
    'output_file_size      = 2329308 (2490.71%)\n',
    'num_patched           = 20000 / 20001 (~100.00%)\n',
    'num_patched_B1        = 20000 / 20001 (100.00%)\n',
] + [f'num_patched_{t}        = 0 / 20001 (0.00%)\n' for t in ('B2', 'T1', 'T2', 'T3')]
synthetic_partial = ''.join(synthetic_events + synthetic_summary).encode()
synthetic_log = out / 'synthetic-rounded-partial.log'; synthetic_log.write_bytes(synthetic_partial)
synthetic_stats = p.statistics(synthetic_log, synthetic_info, synthetic_lengths, 2329308)
assert synthetic_stats['successful'] == 20000 and synthetic_stats['requested'] == 20001
assert synthetic_stats['failed'] == 1 and synthetic_stats['strict_full'] is False
assert synthetic_stats['tactics'] == dict(B1=20000, B2=0, T1=0, T2=0, T3=0)
assert synthetic_stats['failed_tuples_sha256'] == hashlib.sha256(json.dumps([(synthetic_base, 1)], separators=(',', ':')).encode()).hexdigest()

# All populations become complete, but a tilde must still fail the literal
# unprefixed 100.00% requirement. Matching counts cannot bypass that guard.
synthetic_full = synthetic_partial.replace(
    f'debug: failed to patch instruction at address 0x{synthetic_base:x} (1)\n'.encode(),
    f'debug: patched instruction 0x{synthetic_base:x} [size=1, tactic=B1, trampoline=0x100000..0x100005]\n'.encode())
assert synthetic_full.count(b'20000 / 20001') == 2
synthetic_full = synthetic_full.replace(b'20000 / 20001', b'20001 / 20001')
synthetic_full_log = out / 'synthetic-full-tilde.log'; synthetic_full_log.write_bytes(synthetic_full)
try:
    p.statistics(synthetic_full_log, synthetic_info, synthetic_lengths, 2329308)
except AssertionError:
    checks.append('synthetic_rounded_partial_stays_failed_and_full_tilde_refused')
else:
    raise AssertionError('Full count with tilde was accepted')
assert len(checks) == 5 and runner.read_bytes() == runner_bytes
record = dict(status='FIVE_PARSER_CONTROLS_PASS', runner_sha256=sys.argv[1], checks=checks,
              cpus=sorted(os.sched_getaffinity(0)), seconds=time.monotonic() - started,
              frontend_attempts=0, backend_attempts=0, generated_output_executions=0,
              historical_strict_status='FAILED_OUTCOME_RETAINED', independent_live_witness=False,
              synthetic_inputs={path.name: dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                                for path, data in ((synthetic_log, synthetic_partial), (synthetic_full_log, synthetic_full))},
              script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
with (out / 'receipt.json').open('x') as f:
    json.dump(record, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
print(json.dumps(record))
