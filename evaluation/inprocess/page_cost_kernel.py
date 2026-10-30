"""Private, boot-bound core-kernel kallsyms intervals; never guessed ELF function sizes."""
import bisect
import collections
import hashlib
import json
import re
import struct
from pathlib import Path

LIVE = {'boot_id': '/proc/sys/kernel/random/boot_id', 'version': '/proc/version',
        'notes': '/sys/kernel/notes'}


def need(value, why):
    if not value:
        raise ValueError(why)


def fact(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def live_identity():
    return {name: Path(path).read_bytes() for name, path in LIVE.items()}


def build_ids(data):
    result = []; at = 0
    while at < len(data):
        need(at + 12 <= len(data), 'complete kernel note header')
        namesz, descsz, kind = struct.unpack_from('<III', data, at); at += 12
        end = at + ((namesz + 3) & ~3) + ((descsz + 3) & ~3)
        need(end <= len(data), 'complete kernel note payload')
        name = data[at:at + namesz]; at += (namesz + 3) & ~3
        desc = data[at:at + descsz]; at += (descsz + 3) & ~3
        if name == b'GNU\0' and kind == 3:
            need(0 < len(desc) <= 64, 'bounded actual kernel build ID')
            result.append(desc.hex())
    need(len(result) == 1, 'one actual kernel GNU build ID')
    return result


class Resolver:
    def __init__(self, raw):
        rows = []
        for line in raw.decode('ascii').splitlines():
            parts = line.split()
            need(len(parts) in (3, 4) and re.fullmatch('[0-9a-fA-F]{16}', parts[0])
                 and len(parts[1]) == 1, 'exact kallsyms row')
            if len(parts) == 4:
                need(parts[3].startswith('[') and parts[3].endswith(']'), 'module suffix')
                continue  # No guessed module bounds or unload-generation authority.
            rows.append((int(parts[0], 16), parts[1], parts[2]))
        def boundary(name):
            values = [(a, t) for a, t, n in rows if n == name]
            need(len(values) == 1 and values[0][1] in ('t', 'T'), 'unique text boundary ' + name)
            return values[0][0]
        self.first, self.end = boundary('_stext'), boundary('_etext')
        need(0 < self.first < self.end < 1 << 64, 'visible bounded core text addresses')
        core = sorted(set((a, t, n) for a, t, n in rows if self.first <= a <= self.end))
        encoded = json.dumps(core, separators=(',', ':'), ensure_ascii=True).encode()
        self.core_fact = dict(fact(encoded), rows=len(core), text_bytes=self.end - self.first)
        groups = collections.defaultdict(list)
        for address, kind, name in core:
            groups[address].append((kind, name))
        self.starts = sorted(groups)
        self.groups = groups
        need(self.starts[0] == self.first and self.starts[-1] == self.end, 'closed text boundaries')
        self.identity = None

    def lookup(self, ip):
        need(type(ip) is int and 0 <= ip < 1 << 64, 'actual unsigned kernel sample PC')
        if not self.first <= ip < self.end:
            return {'reason': 'outside_core_text'}
        i = bisect.bisect_right(self.starts, ip) - 1
        start, end = self.starts[i], self.starts[i + 1]
        aliases = self.groups[start]
        if not all(kind in ('t', 'T') for kind, _ in aliases):
            return {'reason': 'nontext_or_mixed_symbol_group'}
        need(start <= ip < end <= self.end, 'bounded next-distinct-symbol interval')
        return {'reason': 'core_text_symbol_interval',
                'symbols': sorted({name for _, name in aliases}),
                'offset': ip - start, 'interval_bytes': end - start}


def capture(directory):
    """Before profiling: create a fresh private snapshot directory, no target execution."""
    directory = Path(directory)
    before = live_identity(); raw = Path('/proc/kallsyms').read_bytes()
    need(before == live_identity(), 'kernel identity stable while taking snapshot')
    resolver = Resolver(raw)
    blobs = dict(before, kallsyms=raw)
    meta = {'schema': 1, 'files': {k: fact(v) for k, v in blobs.items()},
            'kernel_build_ids': build_ids(before['notes']), 'core': resolver.core_fact,
            'scope': 'Core [_stext,_etext) text-symbol intervals; module/init/other PCs unknown. '
                     'kallsyms t/T has no ELF STT_FUNC size; bounded intervals can include padding.'}
    directory.mkdir(mode=0o700, exist_ok=False)
    for name, data in blobs.items():
        with (directory / name).open('xb') as stream:
            stream.write(data)
    with (directory / 'snapshot.json').open('x') as stream:
        json.dump(meta, stream, sort_keys=True, separators=(',', ':')); stream.write('\n')
    return meta


def load(directory, expected):
    """After profiling: authenticate snapshot bytes, current boot/build and core symbol positions."""
    directory = Path(directory)
    meta = json.loads((directory / 'snapshot.json').read_bytes())
    need(meta == expected and meta['schema'] == 1, 'same retained snapshot metadata')
    blobs = {name: (directory / name).read_bytes() for name in (*LIVE, 'kallsyms')}
    need({k: fact(v) for k, v in blobs.items()} == meta['files'], 'all exact kernel snapshot facts')
    need(build_ids(blobs['notes']) == meta['kernel_build_ids'], 'actual retained kernel build ID')
    identity = {k: blobs[k] for k in LIVE}
    need(live_identity() == identity, 'same live boot, version and kernel notes')
    resolver = Resolver(blobs['kallsyms'])
    current = Resolver(Path('/proc/kallsyms').read_bytes())
    need(resolver.core_fact == current.core_fact == meta['core'] and live_identity() == identity,
         'same core text addresses/aliases and boot across actual profile')
    resolver.identity = {k: meta['files'][k] for k in LIVE}
    return resolver


def counts(rows, resolver, target_pid):
    """Integer sample/period counts only, restricted to the actual target exec window."""
    need(resolver.identity is not None and type(target_pid) is int and target_pid > 0,
         'authenticated kernel snapshot and actual target PID')
    named = collections.Counter(); periods = collections.Counter(); unknown = collections.Counter()
    unknown_periods = collections.Counter()
    total = preexec = total_period = 0
    for row in rows:
        if row['pid'] != target_pid or row['cpumode'] != 1:
            continue
        need(type(row['in_target_exec_window']) is bool, 'actual exec-window classification')
        if not row['in_target_exec_window']:
            preexec += 1; continue
        need(type(row['period']) is int and row['period'] >= 0, 'actual sampled kernel period')
        total += 1; total_period += row['period']; item = resolver.lookup(row['ip'])
        if item['reason'] == 'core_text_symbol_interval':
            key = tuple(item['symbols']); named[key] += 1; periods[key] += row['period']
        else:
            unknown[item['reason']] += 1; unknown_periods[item['reason']] += row['period']
    need(sum(named.values()) + sum(unknown.values()) == total, 'all kernel samples accounted')
    return {'kernel_samples': total, 'kernel_sampled_period_total': total_period,
            'outside_exec_window_kernel_samples': preexec, 'attributed_samples': sum(named.values()),
            'unknown_samples': sum(unknown.values()), 'unknown_reasons': dict(sorted(unknown.items())),
            'unknown_sampled_period_total': sum(unknown_periods.values()),
            'symbols': [{'aliases': list(k), 'samples': n, 'sampled_period_total': periods[k]}
                        for k, n in sorted(named.items(), key=lambda x: (-x[1], x[0]))],
            'kernel_identity': resolver.identity,
            'scope': 'Bounded kernel-produced core text-symbol intervals, not ELF function-size or '
                     'whole-time proof; modules/init/unknown remain unknown. No benchmark credit.'}
