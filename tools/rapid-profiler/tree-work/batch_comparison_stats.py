"""Prospective nine-mode consumer costs; no qualification or accuracy inference."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import hashlib
import json
import math

MODES = ('native', 'original-sdk', 'k1', 'k10', 'k24',
         'original-sdk-batch8', 'k1-batch8', 'k10-batch8', 'k24-batch8')
OLD_SDK = ('original-sdk', 'k1', 'k10', 'k24')
ROOTS = 1536
METRICS = ('process_wall_ns', 'child_cpu_us', 'whole_wall_ns', 'whole_cpu_ns', 'loop_wall_ns', 'loop_cpu_ns')
T9 = 2.2621571627409915
PLAN_SHA256 = '1db341efa8aef143ad51683db4812b0914d181a2f13fcb7e40bc0b268c408d71'
METHOD = 'geometric_mean_of_ten_within_block_paired_ratios'
INTERVAL_METHOD = 'two_sided_95_percent_student_t9_on_mean_log_ratio'
# Exact prospective table from the source-batch performance plan v2. The five
# historical modes retain their relative order; these are fresh observations.
ORDER = (
    ('k10-batch8', 'k1-batch8', 'k24-batch8', 'k24', 'k10', 'native', 'original-sdk', 'k1', 'original-sdk-batch8'),
    ('original-sdk', 'k24-batch8', 'native', 'k10', 'k10-batch8', 'k24', 'k1-batch8', 'k1', 'original-sdk-batch8'),
    ('original-sdk-batch8', 'original-sdk', 'k10', 'k10-batch8', 'k24-batch8', 'native', 'k1-batch8', 'k1', 'k24'),
    ('original-sdk', 'k10-batch8', 'k24', 'k1', 'k1-batch8', 'original-sdk-batch8', 'k24-batch8', 'native', 'k10'),
    ('k24-batch8', 'k1-batch8', 'original-sdk', 'k10-batch8', 'native', 'k24', 'k10', 'original-sdk-batch8', 'k1'),
    ('original-sdk', 'k10-batch8', 'k1-batch8', 'original-sdk-batch8', 'native', 'k24', 'k24-batch8', 'k10', 'k1'),
    ('k1', 'k10-batch8', 'original-sdk-batch8', 'native', 'k24-batch8', 'k10', 'k24', 'original-sdk', 'k1-batch8'),
    ('k10', 'k24-batch8', 'original-sdk-batch8', 'k24', 'original-sdk', 'k10-batch8', 'native', 'k1', 'k1-batch8'),
    ('original-sdk', 'k1', 'k10', 'k24', 'k1-batch8', 'original-sdk-batch8', 'k24-batch8', 'k10-batch8', 'native'),
    ('k1-batch8', 'native', 'k10-batch8', 'k10', 'k24-batch8', 'original-sdk-batch8', 'k24', 'k1', 'original-sdk'),
    ('k10-batch8', 'native', 'k24-batch8', 'k10', 'original-sdk', 'k24', 'k1-batch8', 'k1', 'original-sdk-batch8'),
    ('original-sdk', 'k1', 'native', 'original-sdk-batch8', 'k10', 'k10-batch8', 'k1-batch8', 'k24', 'k24-batch8'),
    ('native', 'original-sdk-batch8', 'k10-batch8', 'k24', 'k1', 'k24-batch8', 'k10', 'k1-batch8', 'original-sdk'),
)


def plan():
    out = []
    assert len(ORDER) == 13
    for index, modes in enumerate(ORDER):
        assert len(modes) == 9 and set(modes) == set(MODES)
        for position, mode in enumerate(modes, 1):
            out.append(dict(trial=len(out)+1, phase='warmup' if index < 3 else 'measured',
                block=index+1 if index < 3 else index-2, position=position, mode=mode))
    assert len(out) == 117
    encoded = json.dumps(out, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    assert len(encoded) == 8532 and hashlib.sha256(encoded).hexdigest() == PLAN_SHA256
    return out


def _comparison(measured, kind, numerator, denominator, metric):
    wall = metric.endswith('_wall_ns')
    name = ('sdk_over_native_cost' if kind == 'sdk_vs_native' else
            'old_sdk_over_batch_sdk_wall_speedup' if wall else 'old_sdk_over_batch_sdk_cpu_cost')
    pairs = [[measured[(block, numerator)][metric], measured[(block, denominator)][metric]]
             for block in range(1, 11)]
    row = dict(comparison=kind, numerator_mode=numerator, denominator_mode=denominator,
        metric=metric, ratio_name=name, method=METHOD, interval_method=INTERVAL_METHOD,
        pairs=10, paired_values=pairs)
    if any(first == 0 or second == 0 for first, second in pairs):
        assert metric == 'child_cpu_us'
        row.update(status='UNRESOLVED_ZERO_CPU',
            reason='At least one raw CPU reading is zero; all ten pairs retained, no ratio estimated.')
        return row
    ratios = [first/second for first, second in pairs]
    logs = [math.log(ratio) for ratio in ratios]
    mean = math.fsum(logs) / 10
    sd = math.sqrt(math.fsum((value-mean)**2 for value in logs) / 9)
    margin = T9 * sd / math.sqrt(10)
    ratio = math.exp(mean)
    low, high = math.exp(mean-margin), math.exp(mean+margin)
    numbers = dict(mean_log_ratio=mean, sample_sd_log_ratio=sd, geometric_ratio=ratio,
        ratio_interval_low=low, ratio_interval_high=high)
    if kind == 'sdk_vs_native':
        # C = SDK/native, the reciprocal of the old module's native/SDK ratio.
        numbers.update(cost_increase_percent=100*(ratio-1),
            cost_interval_low_percent=100*(low-1), cost_interval_high_percent=100*(high-1))
        if wall:
            numbers.update(throughput_loss_percent=100*(1-1/ratio),
                loss_interval_low_percent=100*(1-1/low), loss_interval_high_percent=100*(1-1/high))
    else:
        # Q = old SDK/batch SDK; the increasing transform retains regressions.
        numbers.update(cost_reduction_percent=100*(1-1/ratio),
            reduction_interval_low_percent=100*(1-1/low), reduction_interval_high_percent=100*(1-1/high))
    assert all(math.isfinite(value) for value in ratios)
    assert all(math.isfinite(value) for value in numbers.values())
    row.update(status='ESTIMATED', paired_ratios=ratios, **numbers)
    return row


def summarize(records):
    """Require a complete ordered cohort; raw endpoint authentication is external."""
    expected = plan()
    assert type(records) is list and len(records) == len(expected)
    measured = {}
    # Preserve the old estimator's record/domain/bound checks before estimating.
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
    assert len(measured) == 90
    comparisons = []
    for mode in MODES[1:]:
        for metric in METRICS:
            comparisons.append(_comparison(measured, 'sdk_vs_native', mode, 'native', metric))
    for mode in OLD_SDK:
        for metric in METRICS:
            comparisons.append(_comparison(measured, 'old_sdk_vs_batch_sdk', mode, mode+'-batch8', metric))
    assert len(comparisons) == 72
    return dict(processes=117, warmup_processes=27, measured_processes=90, roots_per_process=ROOTS,
        plan_sha256=PLAN_SHA256, primary_metric='process_wall_ns', comparisons=comparisons,
        method=METHOD, interval_method=INTERVAL_METHOD,
        estimand='Eight SDK/native cost ratios and four old-SDK/batch-SDK wall-speedup or CPU-cost factors per metric; equal work1536 roots. All ten within-block pairs retained.',
        interval='Conditional two-sided95% Student t9 on mean log paired ratios; no validated coverage or multiplicity guarantee.',
        scope='Complete checked consumers under explicit source policies. Process wall encloses fork through wait4 and parent scheduling delay; child CPU is wait4 user+system. Internal sequential clocks cover the consumers and loops. No isolated hook/file-check cost, hardware accuracy or full A5 claim.')
