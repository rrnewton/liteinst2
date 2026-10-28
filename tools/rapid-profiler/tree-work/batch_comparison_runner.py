"""Nine-mode release comparison after the complete original functional chain."""
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


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name+'.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


legacy = load('comparison_runner')
FILES = legacy.FILES + [PREFIX+n for n in ('batch_comparison_runner.py',
    'check_batch_comparison.py', 'test_batch_comparison.py',
    'batch_comparison_stats.py', 'test_batch_comparison_stats.py')]


def prepare(raw, result, save, digest):
    stats = load('batch_comparison_stats')
    requests = stats.plan()
    save(raw/'tree-batch-comparison-plan.json', dict(trials=requests,
        cpu_seconds=20, wall_seconds=30, file_bytes=MIB, catalog_sha256=stats.PLAN_SHA256,
        order='Frozen thirteen nine-mode blocks; historical five-mode projection retained.'))
    result['tree_batch_comparison'] = dict(status='UNRUN',
        plan_digest=digest(raw/'tree-batch-comparison-plan.json'),
        trials=[dict(request, status='UNRUN') for request in requests])


def run(repo, raw, result, tools, binaries, stage, tree_stable, candidate, trusted, digest, save, config):
    comparison = result['tree_batch_comparison']; comparison['status'] = 'FAILED'
    assert result['tree_population']['status'] == result['call_tree']['status'] == 'PASS'
    assert result['reference_timing']['status'] == 'PASS'
    def invoke(name, argv, cpu, wall, cap):
        def public(word):
            for key, path in tools.items():
                if word == str(path): return '$'+key.upper()
            for path, label in ((raw, '$RAW'), (repo, '$REPO'), (config.toolchain, '$TOOLCHAIN'),
                    (config.cargo_home, '$CARGO_HOME'), (config.user_home, '$USER_HOME')):
                if word == str(path) or word.startswith(str(path)+'/'): return label+word[len(str(path)):]
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
    # Run the new qualifications at this exact revision. Outer envelopes cover
    # their complete build/control populations; every inner bound is unchanged.
    owner_checker = load('verify_batch_owners')
    for label, script, flags, expected_stages in (
            ('batch-owner-qualification', 'verify_batch_owners.py', [], 25),
            ('batch-state-qualification', 'verify_hardware_stop.py', ['--batch-state'], 9)):
        directory = raw/(label+'-output')
        observed = invoke(label, [str(tools['python']), '-B', str(repo/PREFIX/script),
            *flags, '--revision', result['revision'], '--raw', str(directory),
            '--toolchain', str(config.toolchain), '--user-home', str(config.user_home),
            '--cargo-home', str(config.cargo_home)], 120, 180, 128*MIB)
        qualification = json.loads((directory/'result.json').read_text())
        assert qualification['revision'] == result['revision']
        assert qualification['status'] == 'PASS' and qualification['stage'] == 'complete'
        assert len(qualification['stages']) == expected_stages
        assert all(s['status'] == 'PASS' for s in qualification['stages'])
        assert (observed/'stderr.txt').read_bytes() == b''
        if script == 'verify_batch_owners.py':
            expected_stdout = ''.join(c[0]+' PASS\n' for c in owner_checker.ALL_CASES)
            expected_stdout += 'tree-batch-owners PASS stage=complete\n'
            assert (observed/'stdout.txt').read_bytes() == expected_stdout.encode('ascii')
            assert len(qualification['cases']) == 20 and all(c['status'] == 'PASS' for c in qualification['cases'])
            assert qualification['totals'] == dict(original_roots=29, installed_roots=62,
                successful_batch_finishes=8, helper_joins=2)
            assert qualification['legacy_totals'] == dict(original_roots=29, installed_roots=61,
                successful_batch_finishes=8, helper_joins=2)
            assert qualification['batch_pure_controls']['passed'] == 10
            summary = dict(totals=qualification['totals'], legacy_totals=qualification['legacy_totals'],
                cases=20, pure_controls=10)
        else:
            assert (observed/'stdout.txt').read_bytes() == b'tree-batch-state PASS stage=complete\n'
            summary = qualification['batch_state']['summary']
            assert summary['status'] == 'PASS' and summary['pairs'] == 4 and summary['roots'] == 64
            assert summary['comparisons'] == 2744 and summary['source_attested_finishes'] == 8
        comparison[label] = dict(status='PASS', stages=expected_stages, summary=summary,
            receipt=digest(directory/'result.json'))
        stable()

    batch_checker, stats = (load(name) for name in ('check_batch_comparison', 'batch_comparison_stats'))
    # Each complete unittest transcript must contain the exact named population.
    for name, count in (('test_batch_comparison.py', 9), ('test_batch_comparison_stats.py', 8)):
        assert count > 0
        observed = invoke('batch-'+name[:-3], [str(tools['python']), '-B', str(repo/PREFIX/name)], 20, 30, MIB)
        assert (observed/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+
            rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (observed/'stderr.txt').read_bytes())
        stable()
    names = {
        'source_batch_modes_are_distinct_from_every_historical_route',
        'source_batch_requests_preserve_all_ids_and_mixed_chunk_inputs',
        'source_batch_requests_refuse_out_of_population_before_indexing',
        'source_batch_finish_accounting_requires_eight_and_bounds_every_increment'}
    observed = invoke('batch-consumer-controls', [str(tools['cargo']), 'test', '--locked', '--offline',
        '--release', '--jobs', '4', '-p', 'rapid-profiler', '--bin', 'ordinary-interval',
        'tree::throughput::batch::tests::'], 120, 180, 128*MIB)
    terminal = (observed/'stdout.txt').read_text()
    match = re.fullmatch(r'\nrunning 4 tests\n((?:test tree::throughput::batch::tests::[a-z_]+ \.\.\. ok\n){4})'
        r'\ntest result: ok\. 4 passed; 0 failed; 0 ignored; 0 measured; 60 filtered out; finished in [0-9]+\.[0-9]+s\n\n', terminal)
    assert match is not None and {line.split()[1].split('::')[-1] for line in match[1].splitlines()} == names
    comparison['batch_consumer_controls'] = dict(status='PASS', passed=4, failed=0, ignored=0, filtered=60)
    stable()
    comparison['batch_consumer_qualification'] = []
    for mode in stats.MODES[5:]:
        observed = invoke('batch-functional-'+mode, [str(binaries['ordinary-interval']),
            'tree-comparison-batch', mode, str(candidate), str(trusted)], 20, 30, MIB)
        parsed = batch_checker.parse((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), mode)
        assert parsed['summary']['source_batch_finishes'] == 192
        comparison['batch_consumer_qualification'].append(dict(summary=parsed['summary'],
            stdout_digest=digest(observed/'stdout.txt'), stderr_digest=digest(observed/'stderr.txt')))
        stable()

    assert len(comparison['trials']) == 117
    for request, trial in zip(stats.plan(), comparison['trials']):
        assert trial == dict(request, status='UNRUN')
        mode = request['mode']; label = f'tree-batch-comparison-{request["trial"]:03d}-{mode}'
        trial.update(status='FAILED', stage=label)
        if mode == 'native':
            subject = [str(native), str(candidate), str(trusted)]
        else:
            route = 'tree-comparison-batch' if mode in stats.MODES[5:] else 'tree-comparison'
            subject = [str(binaries['ordinary-interval']), route, mode, str(candidate), str(trusted)]
        record = raw/label/'timing.txt'
        wrapped = [str(timer), str(record), timing.token(subject), '--', *subject]
        stable()
        observed = invoke(label, wrapped, 20, 30, MIB)
        launch = json.loads((observed/'request.json').read_text())
        assert launch['argv'] == wrapped and wrapped[4:] == subject and record.parent == observed
        parsed = batch_checker.parse((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), mode)
        summary = parsed['summary']
        time_row = legacy.join_timing(launch, timer, record, subject, record.read_bytes(), summary)
        assert not (set(summary) & {'trial', 'phase', 'block', 'position', 'stage'})
        assert summary['mode'] == mode and summary['status'] == 'FUNCTIONAL_PASS'
        trial.update(summary, process_wall_ns=time_row['process_wall_ns'], child_cpu_us=time_row['child_cpu_us'],
            process_timing=time_row, timing_digest=digest(record), stdout_digest=digest(observed/'stdout.txt'),
            stderr_digest=digest(observed/'stderr.txt'))
        stable()
    statistics = stats.summarize(comparison['trials'])
    save(raw/'tree-batch-comparison-statistics.json', statistics)
    comparison.update(status='OBSERVED', fresh_processes=117, statistics=statistics,
        statistics_digest=digest(raw/'tree-batch-comparison-statistics.json'),
        retention='All117 trials retained, including27 predetermined warmups. No retries, trimming, minimum-duration filter or overhead subtraction.',
        scope='Complete checked consumers with actual per-call totals; four explicit source-batch8 modes qualify192 finishes each. Native cost ratios and old/batch factors are distinct. No isolated file-check/hook cost, equal invalid-client diagnostics, clock accuracy or full A5 claim.')
