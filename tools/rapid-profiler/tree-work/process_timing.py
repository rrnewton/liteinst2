"""Strict one-child wait4 record. Ownership and functional checks remain separate."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import hashlib
import json
import re

FIELDS = ('token timer_pid child_pid wait_pid argc wait_status exit signal core exec_errno '
    'start_sec start_nsec end_sec end_nsec user_sec user_usec system_sec system_usec '
    'resolution_ns process_wall_ns child_user_us child_system_us child_cpu_us').split()


def token(argv):
    assert type(argv) is list and argv and argv[0].startswith('/')
    assert all(type(word) is str and '\0' not in word for word in argv)
    return hashlib.sha256(json.dumps(argv, ensure_ascii=True, separators=(',', ':')).encode('ascii')).hexdigest()


def scaled(seconds, fraction, base):
    assert type(seconds) is int and type(fraction) is int
    assert 0 <= seconds and 0 <= fraction < base
    value = seconds*base + fraction
    assert value < 2**64
    return value


def parse(data, argv):
    assert type(data) is bytes and 0 < len(data) < 1024 and data.endswith(b'\n')
    assert all(32 <= b <= 126 for b in data[:-1])
    words = data[:-1].decode('ascii').split(' ')
    assert words[0] == 'process-timer-v1' and len(words) == len(FIELDS)+1
    row = {}
    for key, word in zip(FIELDS, words[1:]):
        assert word.startswith(key+'=')
        value = word[len(key)+1:]
        if key == 'token':
            assert value == token(argv)
        else:
            assert re.fullmatch(r'0|[1-9][0-9]*|-1', value)
            value = int(value)
            assert (-1 if key == 'exit' else 0) <= value < 2**64
        row[key] = value
    assert 0 < row['timer_pid'] < 2**31 and 0 < row['child_pid'] < 2**31
    assert row['timer_pid'] != row['child_pid'] == row['wait_pid']
    assert row['argc'] == len(argv) and row['resolution_ns'] > 0
    if row['signal'] == 0:
        assert 0 <= row['exit'] <= 255 and row['core'] == 0
        assert row['wait_status'] == row['exit'] << 8
    else:
        assert 0 < row['signal'] <= 64 and row['exit'] == -1 and row['core'] in (0, 1)
        assert row['wait_status'] == row['signal'] | (row['core'] << 7)
    if row['exec_errno']:
        assert row['exec_errno'] <= 4095 and row['exit'] == 127 and row['signal'] == 0
    start = scaled(row['start_sec'], row['start_nsec'], 10**9)
    end = scaled(row['end_sec'], row['end_nsec'], 10**9)
    assert 0 < end-start == row['process_wall_ns']
    user = scaled(row['user_sec'], row['user_usec'], 10**6)
    system = scaled(row['system_sec'], row['system_usec'], 10**6)
    assert row['child_user_us'] == user and row['child_system_us'] == system
    assert row['child_cpu_us'] == user+system < 2**64
    # Zero CPU and CPU>wall are valid observations; neither is filtered.
    return row


def successful(row):
    assert row['exec_errno'] == row['exit'] == row['signal'] == row['wait_status'] == row['core'] == 0
    assert row['process_wall_ns'] <= 30_000_000_000
    return row
