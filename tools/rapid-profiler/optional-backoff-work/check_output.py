"""Strict optional backoff projections; full journal/Report checks remain in Rust."""
import re
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')

TEST = 'frontend_native::backoff::optional::tests::native::optional_backoff_native_disable_rearm_and_old_owner'
PASS = 'optional-backoff-native PASS originals=13 calls=13 fast=1 slow=12 sampled=12 unsampled=0 batches=13 events=24 history_batches=5 actions=5 epochs=3 retired=3 report_records=12 registrations=1 post_disable_fast=1 post_rearm_sampled=2 inflight_old_owner=1 worker_joins=1 short_ret_refusals=1 detached=true input_unchanged=true'
FIELDS = ('originals k calls fast slow sampled unsampled arms reports disabled actions history_batches call_batches max_entry_prefix '
    'epoch_limit call_limit stop_reason max_arm_late_ns stop_ack_ns removed_ns controller_done_ns accepted_exports written_exports '
    'written_bytes worker_detached actual_threads_joined export_synced result_input_rsp_checked worker_backpressure scope '
    'post_disable_rearm_coverage').split()
FIXED = dict(stop_reason='epoch-limit', worker_detached='true', export_synced='true', result_input_rsp_checked='true',
    scope='finite-functional-raw-uncalibrated', post_disable_rearm_coverage='not-qualified')


def native_output(stdout, stderr):
    assert stderr == b'' and 0 < len(stdout) <= 4096
    protocol = '\nrunning 1 test\ntest '+TEST+' ... '+PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', stdout.decode('ascii'))
    fields = dict(word.split('=', 1) for word in PASS.split()[2:])
    return {key: int(value) if value.isdecimal() else value == 'true' for key, value in fields.items()}


def parse_terminal(data, k, export_bytes, worker_backpressure=False):
    assert type(worker_backpressure) is bool and type(k) is int and k in (10, 1000) and type(export_bytes) is int
    assert 0 < len(data) <= 4096 and data.endswith(b'\n') and b'\r' not in data
    words = data[:-1].decode('ascii').split(' ')
    assert words[:2] == ['optional-backoff-work', 'COMPLETE'] and len(words) == 2 + len(FIELDS)
    pairs = [word.split('=') for word in words[2:]]
    assert all(len(pair) == 2 for pair in pairs) and [pair[0] for pair in pairs] == FIELDS
    row = dict(pairs)
    for key, value in FIXED.items(): assert row[key] == value
    assert row['worker_backpressure'] == ('bounded-wait' if worker_backpressure else 'immediate')
    for key in set(FIELDS) - set(FIXED) - {'worker_backpressure'}:
        assert re.fullmatch(r'0|[1-9][0-9]*', row[key])
        row[key] = int(row[key]); assert row[key] < 2**64
    assert (row['originals'], row['k'], row['epoch_limit'], row['call_limit']) == (8, k, 520, 100000)
    assert row['arms'] == row['reports'] == 520 and 0 <= row['disabled'] <= 520
    assert row['actions'] == row['history_batches'] == 521 + row['disabled']
    n = row['calls']; assert 32 < n < 100000
    assert row['fast'] + row['slow'] == n and row['sampled'] + row['unsampled'] == row['slow']
    assert 0 < row['sampled'] <= min(row['slow'], 520*k)
    assert row['disabled']*k <= row['sampled']
    assert 512 < row['max_entry_prefix'] <= row['actions']
    if k == 10: assert row['disabled'] > 0 and row['fast'] > 0
    assert row['max_arm_late_ns'] <= 2000000
    ack, removed, done = (row[key] for key in ('stop_ack_ns', 'removed_ns', 'controller_done_ns'))
    assert 5200000000 <= ack <= removed <= done < min(ack + 2000000000, 7200000000)
    assert (n+3)//4 <= row['call_batches'] <= n
    assert row['accepted_exports'] == row['written_exports'] == row['call_batches'] + row['history_batches'] + row['reports']
    assert 0 < row['written_bytes'] == export_bytes <= 64*1048576 and row['actual_threads_joined'] == 3
    return row


def parse_sink_terminal(data, k, export_bytes, worker_backpressure=False):
    """Authenticate only the opt-in suffix, then retain every old predicate."""
    suffix = b' sink_backpressure=bounded-poll-window sink_retry_ns=1000000 sink_poll_ns=250000\n'
    assert 0 < len(data) <= 4096 and data.endswith(suffix) and b'\r' not in data
    row = parse_terminal(data[:-len(suffix)] + b'\n', k, export_bytes, worker_backpressure)
    row.update(sink_backpressure='bounded-poll-window', sink_retry_ns=1000000, sink_poll_ns=250000)
    return row
