"""Prospectively frozen five-mode native comparison; all 65 observations retained."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import math

MODES = ('native', 'original-sdk', 'k1', 'k10', 'k24')
ROOTS = 1536
METRICS = ('process_wall_ns', 'child_cpu_us', 'whole_wall_ns', 'whole_cpu_ns', 'loop_wall_ns', 'loop_cpu_ns')
T9 = 2.2621571627409915
# SHA256(b'tree-native-baseline-v1' + block.to_bytes(4,'big') + mode.encode()),
# ascending for each zero-based block. Frozen before implementation or timing.
ORDER = (
    ('k24', 'k10', 'native', 'original-sdk', 'k1'),
    ('original-sdk', 'native', 'k10', 'k24', 'k1'),
    ('original-sdk', 'k10', 'native', 'k1', 'k24'),
    ('original-sdk', 'k24', 'k1', 'native', 'k10'),
    ('original-sdk', 'native', 'k24', 'k10', 'k1'),
    ('original-sdk', 'native', 'k24', 'k10', 'k1'),
    ('k1', 'native', 'k10', 'k24', 'original-sdk'),
    ('k10', 'k24', 'original-sdk', 'native', 'k1'),
    ('original-sdk', 'k1', 'k10', 'k24', 'native'),
    ('native', 'k10', 'k24', 'k1', 'original-sdk'),
    ('native', 'k10', 'original-sdk', 'k24', 'k1'),
    ('original-sdk', 'k1', 'native', 'k10', 'k24'),
    ('native', 'k24', 'k1', 'k10', 'original-sdk'),
)


def plan():
    out = []
    for index, modes in enumerate(ORDER):
        assert len(modes) == 5 and set(modes) == set(MODES)
        for position, mode in enumerate(modes, 1):
            out.append(dict(trial=len(out)+1, phase='warmup' if index < 3 else 'measured',
                block=index+1 if index < 3 else index-2, position=position, mode=mode))
    assert len(out) == 65
    return out


def summarize(records):
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
            assert type(record[name]) is int and (0 if name == 'child_cpu_us' else 1) <= record[name] < 2**64
        assert record['process_wall_ns'] <= 30_000_000_000
        assert record['loop_wall_ns'] <= record['whole_wall_ns']
        assert record['loop_cpu_ns'] <= record['whole_cpu_ns']
        if request['phase'] == 'measured':
            key = (request['block'], request['mode'])
            assert key not in measured
            measured[key] = record
    assert len(measured) == 50
    comparisons = []
    for mode in MODES[1:]:
        for metric in METRICS:
            pairs = [(measured[(block, 'native')][metric], measured[(block, mode)][metric])
                for block in range(1, 11)]
            if any(first == 0 or second == 0 for first, second in pairs):
                assert metric == 'child_cpu_us'
                comparisons.append(dict(mode=mode, metric=metric, pairs=10, status='UNRESOLVED_ZERO_CPU',
                    paired_values=pairs, reason='At least one raw CPU reading is zero; all ten pairs retained, no ratio estimated.'))
                continue
            ratios = [first/second for first, second in pairs]
            logs = [math.log(ratio) for ratio in ratios]
            mean = math.fsum(logs) / 10
            sd = math.sqrt(math.fsum((value-mean)**2 for value in logs) / 9)
            margin = T9 * sd / math.sqrt(10)
            ratio = math.exp(mean)
            low, high = math.exp(mean-margin), math.exp(mean+margin)
            values = dict(mode=mode, metric=metric, pairs=10, status='ESTIMATED',
                paired_ratios=ratios, mean_log_ratio=mean, sample_sd_log_ratio=sd,
                geometric_ratio=ratio, ratio_interval_low=low, ratio_interval_high=high,
                cost_increase_percent=100*(1/ratio-1),
                cost_interval_low_percent=100*(1/high-1), cost_interval_high_percent=100*(1/low-1))
            if metric.endswith('_wall_ns'):
                values.update(throughput_loss_percent=100*(1-ratio),
                    loss_interval_low_percent=100*(1-high), loss_interval_high_percent=100*(1-low))
            assert all(math.isfinite(value) for key, value in values.items()
                if key not in ('mode', 'metric', 'status', 'paired_ratios'))
            comparisons.append(values)
    return dict(warmup_processes=15, measured_processes=50, roots_per_process=ROOTS,
        primary_metric='process_wall_ns', comparisons=comparisons,
        estimand='Geometric mean of within-block native/mode wall or CPU-cost ratios; equal work1536 roots. Throughput loss is reported only for wall time.',
        interval='Conditional two-sided95% Student t9 on mean log paired ratios; no validated coverage claim.',
        scope='Fork-to-reap wall includes parent fork/wakeup delay and complete child lifetime. Child CPU is wait4 user+system. Internal clocks cover checked/exported consumers and loops. SDK guards remain; native extra cycle validation and fixed15-byte call stub remain. No isolated hook cost, hardware accuracy or full A5 claim.')
