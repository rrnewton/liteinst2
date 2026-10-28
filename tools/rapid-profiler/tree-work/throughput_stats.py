"""Frozen paired consumer-throughput protocol; conditional intervals, no perf accuracy."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import math

SEED = 0x4c49544554524545
MODES = ('original-sdk', 'k1', 'k10', 'k24')
ROOTS = 1536
METRICS = ('whole_wall_ns', 'whole_cpu_ns', 'loop_wall_ns', 'loop_cpu_ns')
T9 = 2.2621571627409915  # Two-sided 95% Student t, nine degrees of freedom.
# Three warmup blocks followed by ten measured blocks. Generated once using
# Python3.12 random.Random(SEED).shuffle, then frozen before any observations.
ORDER = (
    ('k10', 'k1', 'k24', 'original-sdk'),
    ('k24', 'k10', 'original-sdk', 'k1'),
    ('k24', 'original-sdk', 'k10', 'k1'),
    ('k24', 'original-sdk', 'k10', 'k1'),
    ('k1', 'original-sdk', 'k10', 'k24'),
    ('original-sdk', 'k1', 'k24', 'k10'),
    ('k10', 'original-sdk', 'k24', 'k1'),
    ('original-sdk', 'k24', 'k1', 'k10'),
    ('original-sdk', 'k10', 'k1', 'k24'),
    ('k1', 'k24', 'k10', 'original-sdk'),
    ('k24', 'k1', 'k10', 'original-sdk'),
    ('original-sdk', 'k24', 'k10', 'k1'),
    ('k10', 'k1', 'original-sdk', 'k24'),
)


def plan():
    out = []
    for index, modes in enumerate(ORDER):
        assert len(modes) == 4 and set(modes) == set(MODES)
        for position, mode in enumerate(modes, 1):
            out.append(dict(trial=len(out)+1, phase='warmup' if index < 3 else 'measured',
                block=index+1 if index < 3 else index-2, position=position, mode=mode))
    assert len(out) == 52
    return out


def summarize(records):
    """All52 records are required; fixed warmups remain in the raw output.

    A block pairs independently executed original-SDK and installed processes.
    The interval is conditional on independent approximately normal log ratios;
    its coverage has not been empirically qualified. No observation is trimmed,
    winsorized, converted to zero overhead, or silently changed to a lower span.
    """
    expected = plan()
    assert type(records) is list and len(records) == len(expected)
    measured = {}
    for record, request in zip(records, expected):
        assert isinstance(record, dict)
        assert all(type(record[key]) is type(value) for key, value in request.items())
        assert {key: record[key] for key in request} == request
        assert record['status'] == 'FUNCTIONAL_PASS'
        assert type(record['roots']) is int and record['roots'] == ROOTS
        for name in METRICS:
            assert type(record[name]) is int and 0 < record[name] < 2**64
        assert record['loop_wall_ns'] <= record['whole_wall_ns']
        assert record['loop_cpu_ns'] <= record['whole_cpu_ns']
        if request['phase'] == 'measured':
            key = (request['block'], request['mode'])
            assert key not in measured
            measured[key] = record
    assert len(measured) == 40
    comparisons = []
    for mode in MODES[1:]:
        for metric in METRICS:
            ratios = [measured[(block, 'original-sdk')][metric] / measured[(block, mode)][metric]
                for block in range(1, 11)]
            logs = [math.log(ratio) for ratio in ratios]
            mean = math.fsum(logs) / 10
            sd = math.sqrt(math.fsum((value-mean)**2 for value in logs) / 9)
            margin = T9 * sd / math.sqrt(10)
            ratio = math.exp(mean)
            low, high = math.exp(mean-margin), math.exp(mean+margin)
            values = dict(mode=mode, metric=metric, pairs=10,
                paired_ratios=ratios, mean_log_ratio=mean, sample_sd_log_ratio=sd,
                geometric_ratio=ratio, ratio_interval_low=low, ratio_interval_high=high,
                cost_increase_percent=100*(1/ratio-1),
                cost_interval_low_percent=100*(1/high-1), cost_interval_high_percent=100*(1/low-1))
            if metric.endswith('_wall_ns'):
                values.update(throughput_loss_percent=100*(1-ratio),
                    loss_interval_low_percent=100*(1-high), loss_interval_high_percent=100*(1-low))
            assert all(math.isfinite(value) for key, value in values.items()
                if key not in ('mode', 'metric', 'paired_ratios'))
            comparisons.append(values)
    return dict(seed=SEED, warmup_processes=12, measured_processes=40, roots_per_process=ROOTS,
        primary_metric='whole_wall_ns', comparisons=comparisons,
        estimand='Geometric mean of within-block original-SDK/mode wall or CPU-cost ratios; equal work1536 roots. Throughput loss is reported only for wall time.',
        interval='Conditional two-sided95% Student t9 on mean log paired ratios; no validated coverage claim.',
        scope='Measured guarded SDK consumer region; startup, final timing terminal and exit excluded. No bare-native, hook-latency, hardware-event, perf-accuracy or full A5 claim.')
