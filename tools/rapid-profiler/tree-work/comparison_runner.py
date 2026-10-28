"""Additive native comparison, called only after the existing functional gates."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import importlib.util
import json
from pathlib import Path
import re

MIB = 1048576
PREFIX = 'tools/rapid-profiler/tree-work/'
FILES = [PREFIX+n for n in ('comparison_runner.py', 'check_comparison.py', 'test_comparison.py',
    'comparison_stats.py', 'test_comparison_stats.py', 'process_timer.c', 'process_timer_control.c',
    'process_timing.py', 'test_process_timing.py', 'test_process_timer_live.py')]


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def prepare(raw, result, save, digest):
    stats = load('comparison_stats')
    plan = stats.plan()
    save(raw/'tree-comparison-plan.json', dict(trials=plan, cpu_seconds=20, wall_seconds=30, file_bytes=MIB,
        order='SHA256(tree-native-baseline-v1 || block:u32BE || ASCII full mode), ascending; fixed before implementation'))
    result['tree_native_baseline'] = dict(status='UNRUN', plan_digest=digest(raw/'tree-comparison-plan.json'),
        trials=[dict(request, status='UNRUN') for request in plan])


def join_timing(launch, timer, record, subject, data, summary):
    timing = load('process_timing')
    assert launch['argv'] == [str(timer), str(record), timing.token(subject), '--', *subject]
    assert launch['stdout'] == str(record.parent/'stdout.txt')
    assert launch['stderr'] == str(record.parent/'stderr.txt')
    assert (launch['cpu_seconds'], launch['wall_seconds'], launch['file_bytes']) == (20, 30, MIB)
    row = timing.successful(timing.parse(data, subject))
    start = timing.scaled(row['start_sec'], row['start_nsec'], 10**9)
    end = timing.scaled(row['end_sec'], row['end_nsec'], 10**9)
    assert start <= summary['s0_wall_before'] <= summary['s3_wall_after'] <= end
    return row


def run(repo, raw, result, tools, binaries, stage, tree_stable, candidate, trusted, digest, save):
    comparison = result['tree_native_baseline']; comparison['status'] = 'FAILED'
    assert result['tree_population']['status'] == result['call_tree']['status'] == 'PASS'
    assert result['reference_timing']['status'] == 'PASS'
    def invoke(name, argv, cpu, wall, cap):
        def public(word):
            for key, path in tools.items():
                if word == str(path): return '$'+key.upper()
            for path, label in ((raw, '$RAW'), (repo, '$REPO')):
                if word.startswith(str(path)+'/'): return label+word[len(str(path)):]
            return word
        result['commands'].append([public(word) for word in argv])
        return stage(name, argv, cpu, wall, cap)
    checker, timing, stats = (load(name) for name in ('check_comparison', 'process_timing', 'comparison_stats'))
    native = repo/'target/release/tree-native-baseline'
    args = ['build', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
        '--bin', 'tree-native-baseline', '--message-format=json-render-diagnostics']
    built = invoke('comparison-native-build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
    messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
    assert messages[-1] == dict(reason='build-finished', success=True)
    products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'tree-native-baseline']
    assert len(products) == 1; product = products[0]
    assert product['executable'] == str(native) and product['target']['kind'] == product['target']['crate_types'] == ['bin']
    assert type(product['fresh']) is bool and product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
    assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/native-baseline/main.rs')
    assert product['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
    assert type(product['profile']['debuginfo']) is int
    assert all(type(product['profile'][k]) is bool for k in ('test', 'debug_assertions', 'overflow_checks'))
    timer, control = raw/'process-timer', raw/'process-timer-control'
    for executable, source in ((timer, 'process_timer.c'), (control, 'process_timer_control.c')):
        flags = ['-O3', '-std=c11', '-Wall', '-Wextra', '-Werror']
        invoke(executable.name+'-build', [str(tools['gcc']), *flags, str(repo/PREFIX/source), '-o', str(executable)], 20, 30, MIB)
    pins = {str(p): digest(p) for p in (native, timer, control)}
    comparison['artifacts'] = dict(native=pins[str(native)], timer=pins[str(timer)], control=pins[str(control)],
        native_profile=product['profile'], native_cargo_fresh=product['fresh'])
    def stable():
        tree_stable()
        assert {p: digest(Path(p)) for p in pins} == pins

    for name, count in (('test_comparison.py', 9), ('test_comparison_stats.py', 6), ('test_process_timing.py', 5)):
        stable()
        observed = invoke('comparison-'+name[:-3], [str(tools['python']), '-B', str(repo/PREFIX/name)], 20, 30, MIB)
        # unittest writes its terminal to stderr. Require exact count/no skips,
        # while retaining each complete transcript under the existing owner.
        assert (observed/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+
            rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (observed/'stderr.txt').read_bytes())
        stable()
    args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
        '--bin', 'ordinary-interval', 'tree::throughput::collection::tests']
    observed = invoke('comparison-collection-controls', [str(tools['cargo']), *args], 120, 180, 128*MIB)
    terminal = (observed/'stdout.txt').read_text()
    match = re.fullmatch(r'\nrunning 4 tests\n((?:test tree::throughput::collection::tests::[a-z_]+ \.\.\. ok\n){4})'
        r'\ntest result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 60 filtered out; finished in [0-9]+\.[0-9]+s\n\n', terminal)
    assert match is not None
    assert {line.split()[1].split('::')[-1] for line in match[1].splitlines()} == {
        'complete_population_checks_every_value_and_wrapping_sum', 'duplicate_missing_extra_and_reordered_results_refuse',
        'cancellation_cannot_hide_two_wrong_results', 'wrong_or_incomplete_block_summaries_refuse'}
    comparison['collection_controls'] = dict(status='PASS', passed=4, failed=0, ignored=0)
    stable()
    observed = invoke('comparison-timer-controls', [str(tools['python']), '-B', str(repo/PREFIX/'test_process_timer_live.py'),
        '--timer', str(timer), '--control', str(control), '--output', str(raw/'timer-controls')], 20, 30, MIB)
    assert (observed/'stderr.txt').read_bytes() == b''
    assert (observed/'stdout.txt').read_bytes() == b'process-timer-controls PASS controls=11 owners=2 original_helpers=true\n'
    controls = json.loads((raw/'timer-controls/controls.json').read_text())
    assert controls['status'] == 'PASS' and len(controls['controls']) == 11
    comparison['timer_controls'] = dict(status='PASS', controls=11, receipt=digest(raw/'timer-controls/controls.json'))
    stable()

    directory = raw/'native-tree-oracle-output'
    observed = invoke('comparison-native-oracle', [str(binaries['frontend-native-oracle']), 'native-tree-state',
        str(candidate), str(trusted), str(directory)], 90, 90, MIB)
    table = (directory/'native-tree.csv').read_bytes()
    rows = checker.native_pairs(table, (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
    (raw/'native-tree-state-pairs.csv').write_bytes(table)
    comparison['native_qualification'] = dict(status='PASS', pairs=4, children=8, comparisons=1356,
        rows=rows, csv_digest=digest(raw/'native-tree-state-pairs.csv'),
        scope='Exact shared15-byte ABI stub,332 original heads and7 stub heads per pair; original full comparator/bounds; four nontrivial five-role Tree144 no-op candidates.')
    stable()
    assert len(comparison['trials']) == 65
    for request, trial in zip(stats.plan(), comparison['trials']):
        assert trial == dict(request, status='UNRUN')
        mode = request['mode']; label = f'tree-comparison-{request["trial"]:02d}-{mode}'
        trial.update(status='FAILED', stage=label)
        subject = ([str(native), str(candidate), str(trusted)] if mode == 'native' else
            [str(binaries['ordinary-interval']), 'tree-comparison', mode, str(candidate), str(trusted)])
        record = raw/label/'timing.txt'
        wrapped = [str(timer), str(record), timing.token(subject), '--', *subject]
        stable()
        observed = invoke(label, wrapped, 20, 30, MIB)
        # Join the exact launch request to both the sidecar's token and subject.
        launch = json.loads((observed/'request.json').read_text())
        assert launch['argv'] == wrapped and wrapped[4:] == subject and record.parent == observed
        parsed = checker.parse((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), mode)
        summary = parsed['summary']
        time_row = join_timing(launch, timer, record, subject, record.read_bytes(), summary)
        assert not (set(summary) & {'trial', 'phase', 'block', 'position', 'stage'})
        assert summary['mode'] == mode and summary['status'] == 'FUNCTIONAL_PASS'
        trial.update(summary, process_wall_ns=time_row['process_wall_ns'], child_cpu_us=time_row['child_cpu_us'],
            process_timing=time_row, timing_digest=digest(record), stdout_digest=digest(observed/'stdout.txt'),
            stderr_digest=digest(observed/'stderr.txt'))
        stable()
    statistics = stats.summarize(comparison['trials'])
    save(raw/'tree-comparison-statistics.json', statistics)
    comparison.update(status='OBSERVED', fresh_processes=65, statistics=statistics,
        statistics_digest=digest(raw/'tree-comparison-statistics.json'),
        retention='All65 trials retained, including15 predetermined warmups. No retries, trimming, minimum-duration filter or overhead subtraction.',
        scope='Complete fork-to-reap wall enclosure versus bare native fixed work, plus wait4 child CPU and internal checked-consumer clocks. Extra native setup validation and fixed call-stub cost remain; SDK guards remain. No isolated instrumentation overhead or full A5 claim.')
