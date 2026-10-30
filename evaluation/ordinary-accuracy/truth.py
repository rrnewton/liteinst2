#!/usr/bin/env python3
"""Seeded, complete input populations for the literal 37-byte checksum leaf.

This is an independent algebraic oracle, not a machine-state emulator or a
hardware timing model. The existing exact-work interpreter/native state oracle
must independently qualify the executed body and caller. No profiler output is
an input to this module. A seed changes payloads, varied-length work and initial
phase; it does not establish independence of hardware errors.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path


BODY = bytes.fromhex(
    '31c04c8d04370fb60f83f15a4801c848ffc74c39c772ef'
    '48ba157c4a7fb979379e4831d0c3')
FUNCTION = 41
RECORDS = 2048
TRIALS = 100
PHASES = ('calibration', 'holdout', 'comparison')
WORKLOADS = ('short', 'long', 'alternating', 'late_expensive', 'blocks', 'varied')
FIELDS = ('record', 'length', 'value', 'instructions', 'conditional_branches',
          'taken_branches', 'input_bytes', 'return_bytes')
# One valid unquoted CSV field. Quotation/framing never changes the leaf's bytes.
ALPHABET = bytes(b for b in range(32, 127) if b not in (34, 44))
SCOPE = ('Original checksum-leaf work only: function entry through its RET, '
         'including the saved return-word read. No CALL, harness, hook, PMU, '
         'duration, cache, native execution or accuracy verdict is inferred. '
         'The complete function/caller and unsafe execution contract require '
         'independent qualification. Blocks describe call order, not timed bursts.')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, maximum, minimum=0):
    need(type(value) is int and minimum <= value <= maximum, 'integer domain')
    return value


def seed_bytes(text):
    need(type(text) is str and len(text) == 64 and
         all(c in '0123456789abcdef' for c in text), '32-byte lowercase seed required')
    return bytes.fromhex(text)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def trial_seed(master, phase, trial):
    master = seed_bytes(master)
    need(phase in PHASES, 'named independent phase required')
    uint(trial, TRIALS, 1)
    return hashlib.sha256(b'li2-accuracy-trial-v1\0' + master + b'\0' +
                          phase.encode('ascii') + b'\0' + trial.to_bytes(4, 'big')).hexdigest()


class Stream:
    """Counter-based SHA-256 stream with rejection sampling, no modulo bias."""
    def __init__(self, seed, domain):
        need(type(domain) is bytes and 0 < len(domain) <= 128, 'stream domain')
        self.prefix = b'li2-accuracy-stream-v1\0' + seed_bytes(seed) + b'\0' + domain
        self.block = b''
        self.offset = 0
        self.counter = 0

    def word(self):
        if self.offset == len(self.block):
            uint(self.counter, (1 << 64) - 1)
            self.block = hashlib.sha256(self.prefix + self.counter.to_bytes(8, 'big')).digest()
            self.counter += 1
            self.offset = 0
        value = int.from_bytes(self.block[self.offset:self.offset + 8], 'big')
        self.offset += 8
        return value

    def below(self, bound):
        uint(bound, 1 << 64, 1)
        limit = (1 << 64) - ((1 << 64) % bound)
        # Refuse a broken stream instead of silently biasing or looping forever.
        for _ in range(256):
            value = self.word()
            if value < limit:
                return value % bound
        raise ValueError('random stream rejection bound')


def original(payload):
    """Closed-form scalar result and original work counts, including RET."""
    need(type(payload) is bytes and 1 <= len(payload) <= 64, 'nonempty leaf input')
    n = len(payload)
    return dict(length=n, value=sum(b ^ 0x5a for b in payload) ^ 0x9e3779b97f4a7c15,
                instructions=6*n + 5, conditional_branches=n, taken_branches=n - 1,
                input_bytes=n, return_bytes=8)


def population(seed, workload):
    """All 2,048 invocations, including those any first-K policy will discard."""
    seed_bytes(seed)
    need(workload in WORKLOADS, 'named workload required')
    payloads = Stream(seed, b'payload\0' + workload.encode('ascii'))
    lengths = Stream(seed, b'length\0' + workload.encode('ascii'))
    rows = []
    for ordinal in range(1, RECORDS + 1):
        i = ordinal - 1
        length = {
            'short': 1, 'long': 64, 'alternating': 1 if i % 2 == 0 else 64,
            'late_expensive': 1 if i < RECORDS // 2 else 64,
            'blocks': 1 if (i // 64) % 2 == 0 else 64,
        }.get(workload)
        if workload == 'varied':
            length = lengths.below(64) + 1
        need(length is not None, 'workload length')
        payload = bytes(ALPHABET[payloads.below(len(ALPHABET))] for _ in range(length))
        rows.append(dict(record=ordinal, payload=payload, **original(payload)))
    return rows


def policies(seed):
    """The complete proposed K/cadence/phase matrix, without a pass label.

    Phase is a requested delay relative to the controller's established first
    epoch. Actual producer/controller timestamps must qualify its realization.
    The same requested phase is paired across K for a seed/cadence. An input
    manifest alone cannot show that calls were actually phase locked.
    """
    seed_bytes(seed)
    result = []
    for k in (1, 10, 100, 1000):
        for period_ms in (1, 10, 100):
            period_ns = period_ms * 1_000_000
            offset = Stream(seed, b'initial-phase\0' + str(period_ms).encode('ascii')).below(period_ns)
            for phase, delay in (('random', offset), ('locked', 0)):
                result.append(dict(k=k, period_ms=period_ms, phase=phase, delay_ns=delay))
    return result


def artifacts(master, phase, trial, workload):
    seed = trial_seed(master, phase, trial)
    rows = population(seed, workload)
    input_bytes = b''.join(row['payload'] + b'\n' for row in rows)
    table = [f'LI2SELECTED 1 1 {RECORDS}', f'functions {FUNCTION}']
    table.extend(f"record {r['record']} {r['payload'].hex()} {r['value']}" for r in rows)
    table.append('END')
    table_bytes = ('\n'.join(table) + '\n').encode('ascii')
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator='\n')
    writer.writeheader()
    writer.writerows({key: row[key] for key in FIELDS} for row in rows)
    truth_bytes = output.getvalue().encode('ascii')
    files = {'input.csv': input_bytes, 'selected.txt': table_bytes, 'truth.csv': truth_bytes}
    manifest = dict(schema='ordinary-accuracy-population-v1', master=master, phase=phase,
                    trial=trial, seed=seed, workload=workload, function=FUNCTION,
                    records=RECORDS, body=dict(hex=BODY.hex(), **pin(BODY)),
                    files={name: pin(raw) for name, raw in files.items()},
                    totals={key: sum(row[key] for row in rows)
                            for key in FIELDS if key not in ('record', 'length', 'value')},
                    policies=policies(seed), scope=SCOPE)
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--trial', type=int, required=True)
    parser.add_argument('--workload', choices=WORKLOADS, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    files, manifest = artifacts(args.master, args.phase, args.trial, args.workload)
    # A failed/partial output is retained. A later invocation cannot overwrite it.
    args.output.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        with (args.output / name).open('xb') as stream:
            stream.write(raw)
    with (args.output / 'manifest.json').open('xb') as stream:
        stream.write(canonical(manifest))
    print(canonical(dict(status='INPUTS_PREPARED', **pin(canonical(manifest)))).decode(), end='')


if __name__ == '__main__':
    main()
