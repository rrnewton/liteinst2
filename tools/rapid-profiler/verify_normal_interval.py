#!/usr/bin/env python3
"""Fresh release qualification of normal C callers; no performance claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import traceback

MIB = 1048576
CALLER_FLAGS = ['-O2', '-fPIC', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
    '-fno-unwind-tables', '-fcf-protection=none', '-Wall', '-Wextra', '-Werror',
    '-shared', '-nostdlib', '-Wl,-Bsymbolic,--no-undefined,--build-id=none,-z,relro,-z,now,-z,noexecstack']
RUNTIME = ('pending_ret_is_not_completion_and_k1_next_entry_finishes_before_admission',
    'pending_function_closed_retains_epoch_permit_after_report_retirement',
    'old_a_and_b_pending_receipts_keep_original_owner_across_rearm_c',
    'geometry_duplicate_ret_recursion_and_wrong_ack_refuse_before_consumption',
    'thirty_two_call_bound_preserves_last_return_and_rejects_next_admission',
    'checkpoint_validates_whole_journal_and_pending_identity_before_finish',
    'allocation_refusal_and_caught_busy_unwind_keep_pending_first_error',
    'transfer_reuses_buffers_without_resetting_absolute_identity_or_model_sequence',
    'gated_site_cannot_be_relabelled_into_normal_preparation',
    'streaming_normal_pending_owner_survives_600_actions_without_return_acknowledgement',
    'streaming_normal_closed_and_removed_records_join_after_repeated_idle_drains',
    'streaming_normal_upper_prefix_corruption_refuses_before_consuming_pending_owner')
CALLER = ('normal_caller_literal_body_and_every_changed_byte_refuse',
    'normal_caller_dynamic_refuses_load_time_execution_and_dependencies',
    'normal_caller_mapping_requires_complete_exact_rx_owner',
    'normal_caller_complete_elf_refuses_wrong_symbol_body_load_and_dynamic')
STATE = ('normal_ready_refuses_wrong_caller_maps_and_extents',
    'normal_wire_refuses_truncation_tail_and_journal_profile',
    'normal_transfers_refuse_wrong_target_word_rsp_and_order',
    'normal_epilogue_data_and_pending_journal_refuse',
    'normal_original_caller_transition_effects_refuse',
    'normal_control_ack_refuses_wrong_stage_identity_owner_and_tail',
    'normal_population_refuses_missing_second_body_order_and_coverage',
    'normal_mode_and_completion_counts_preserve_fixed_bounds')
CHILD = ('normal_native_rows_require_exact_next_entry_and_checkpoint',
    'normal_native_rows_bind_continuation_owner_prefix_and_complete_journal')
STAGES = ('parser-controls', 'runtime-controls', 'caller-controls', 'state-controls',
    'child-controls', 'caller-build', 'normal-state', 'normal-work', 'drop-sampled', 'drop-closed')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'),
        CC=str(Path('/usr/bin/gcc').resolve(strict=True)), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= MIB
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'tools/rapid-profiler/verify_normal_interval.py',
        'tools/rapid-profiler/verify_strnlen_interval.py', 'evaluation/admission/processes.py',
        'tools/unwind-oracle/bounded_command.py', 'tools/rapid-profiler/selected-work/check_output.py',
        'tools/rapid-profiler/normal-work/check_output.py', 'tests/call_tree_truth.rs'}
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
        'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    before = {name: digest(repo/name) for name in names}
    for name in names:
        assert (repo/name).read_bytes() == git('show', a.revision+':'+name)
    # Every imported source and transitive prerequisite is authenticated first.
    processes = load('normal_processes', repo/'evaluation/admission/processes.py')
    census = load('normal_census', repo/'tools/rapid-profiler/selected-work/check_output.py')
    check = load('normal_output', repo/'tools/rapid-profiler/normal-work/check_output.py')
    prior = load('normal_prior', repo/'tools/rapid-profiler/verify_strnlen_interval.py')
    a.raw.mkdir(mode=0o700)
    save(a.raw/'sources-before.json', before)
    result = dict(schema=1, status='FAILED', stage='setup', revision=a.revision,
        scope='One bounded scalar leaf called by real C code; no arbitrary-application, accuracy, performance or complete-A5 claim.',
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_normal_interval.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'], stages=[],
        sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')))
    artifacts = {}
    tool_paths = {}
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {n: digest(repo/n) for n in names} == before
        assert all(digest(p) == value for p, value in artifacts.items())
        if tool_paths:
            assert {n: digest(p) for n, p in tool_paths.items()} == result['tools']
    def public(value):
        value = str(value)
        for n, path in tool_paths.items():
            if value == str(path): return '$'+n.upper()
        for path, token in ((a.raw, '$RAW'), (repo, '$REPO'), (a.toolchain, '$TOOLCHAIN'),
                            (a.cargo_home, '$CARGO_HOME'), (a.user_home, '$USER_HOME')):
            if value == str(path) or value.startswith(str(path)+'/'):
                return token+value[len(str(path)):]
        assert not value.startswith('/') and '/home/' not in value and '@' not in value
        return value
    def closed_ok(closed):
        assert closed['exit_code'] == 0 and closed['termination'] is None
        assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
    try:
        logs_root = repo/'target/evaluation'
        logs_root.mkdir(parents=True, exist_ok=True)
        assert logs_root.resolve(strict=True) == logs_root
        logs = Path(tempfile.mkdtemp(prefix='normal-interval-', dir=logs_root))
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        nested = a.raw/'strnlen-prerequisite'
        args = [sys.executable, '-B', str(repo/'tools/rapid-profiler/verify_strnlen_interval.py'),
            '--revision', a.revision, '--raw', str(nested), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'strnlen-prerequisite'
        save(a.raw/'prerequisite-command.json', dict(argv=args, env=env, affinity=cpus, wall_seconds=1800))
        closed = processes.run_command(args, env, logs/'prerequisite.log', 1800, 8*MIB)
        (a.raw/'prerequisite.log').write_bytes((logs/'prerequisite.log').read_bytes())
        save(a.raw/'prerequisite-closed.json', closed); closed_ok(closed); unchanged()
        old = json.loads((nested/'result.json').read_bytes())
        artifacts[nested/'result.json'] = digest(nested/'result.json')
        assert old['revision'] == a.revision and old['status'] == 'PASS' and old['stage'] == 'complete'
        assert tuple(s['name'] for s in old['stages']) == prior.STAGES
        assert all(s['status'] == 'PASS' for s in [*old['stages'], *old['prerequisites'].values(), *old['qualifications'].values()])
        assert old['closure'] == dict(owned_stages=24, nested_owned_stages=22, normal_helpers=46, outer_owners=48, rescues=0)
        prior_sources = json.loads((nested/'sources-before.json').read_bytes())
        assert prior_sources == json.loads((nested/'sources-after.json').read_bytes())
        assert all(before[n] == h for n, h in prior_sources.items())
        assert old['sources'] == dict(count=len(prior_sources), manifest=digest(nested/'sources-before.json'))
        private = json.loads((nested/'private-environment.json').read_bytes())
        assert private['env'] == env and private['affinity'] == cpus
        tool_paths.update({n: Path(p) for n, p in private['tools'].items()})
        assert {n: digest(p) for n, p in tool_paths.items()} == old['tools']
        result.update(tools=old['tools'], versions=old['versions'], hardware=old['hardware'],
            prerequisite=dict(result=digest(nested/'result.json'), closed=digest(a.raw/'prerequisite-closed.json'),
                command=digest(a.raw/'prerequisite-command.json'), closure=old['closure']))
        result['hardware']['description'] = 'AMD EPYC Zen 5 dev host' if (
            old['hardware']['vendor'], old['hardware']['family'], old['hardware']['model']) == (
                'AuthenticAMD', 26, 17) else 'x86-64 development host'
        def stage(name, argv, cpu=20, wall=30, cap=MIB):
            unchanged(); result['stage'] = name
            row = dict(name=name, status='FAILED', command=[public(v) for v in argv],
                       cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            request = dict(argv=[str(v) for v in argv], cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu,
                wall_seconds=wall, file_bytes=cap)
            save(d/'request.json', request)
            helper = repo/'tools/unwind-oracle/bounded_command.py'
            parent = [str(tool_paths['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            closed = processes.run_command(parent, env, logs/(name+'.log'), wall+25, MIB)
            (d/'parent.log').write_bytes((logs/(name+'.log')).read_bytes())
            save(d/'parent-closed.json', closed); closed_ok(closed)
            assert json.loads((d/'request.json').read_bytes()) == request
            receipt = json.loads((d/'receipt.json').read_bytes())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert json.loads((d/'parent.log').read_bytes()) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(d/(stream+'.txt'))['sha256']
            row.update({n: digest(d/file) for n, file in (('receipt','receipt.json'),
                ('request','request.json'), ('closed','parent-closed.json'), ('stdout','stdout.txt'), ('stderr','stderr.txt'))})
            unchanged(); row['status'] = 'PASS'
            return d
        python = str(tool_paths['python'])
        d = stage('parser-controls', [python, '-B', repo/'tools/rapid-profiler/normal-work/test_output.py'], 10, 15)
        assert (d/'stdout.txt').read_bytes() == b''
        assert re.fullmatch(rb'\.{9}\n-+\nRan 9 tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        result['controls'] = dict(parser=9)
        for label, old_label, prefix, methods, target, source, kind in (
            ('runtime', 'whole-front', 'frontend_native::always_on::normal::tests::', RUNTIME, 'rapid_profiler', 'src/lib.rs', 'lib'),
            ('caller', 'work-validator', 'normal::caller::tests::', CALLER, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin'),
            ('state', 'state-validator', 'oracle::native_ordinary::normal_caller::tests::', STATE, 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test'),
            ('child', 'state-validator', 'normal_check::tests::', CHILD, 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test')):
            messages = [json.loads(s) for s in (nested/(old_label+'-build')/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target and m['profile']['test']]
            assert len(products) == 1
            product = products[0]; binary = Path(product['executable'])
            assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            assert product['target']['kind'] == [kind]
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert old['artifacts'][old_label]['profile'] == product['profile']
            artifacts[binary] = digest(binary); assert artifacts[binary] == old['artifacts'][old_label]['binary']
            listing = nested/(old_label+'-list')
            inventory = census.census((listing/'stdout.txt').read_bytes(), (listing/'stderr.txt').read_bytes())
            expected = tuple(prefix+n for n in methods)
            assert set(n for n in inventory if n.startswith(prefix)) == set(expected)
            d = stage(label+'-controls', [binary, prefix, '--test-threads=1'])
            result['controls'][label] = census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), expected, inventory)
        artifacts[nested/'selection.json'] = digest(nested/'selection.json')
        assert artifacts[nested/'selection.json'] == old['selection']['manifest']
        selection = json.loads((nested/'selection.json').read_bytes())
        assert selection['revision'] == a.revision and selection['label'] == 'freebsd-strnlen-14.1-v1'
        assert all(selection[key] == old['selection'][key]
                   for key in ('label', 'elf_va', 'length', 'selected_code', 'file_offset'))
        subject, trusted = nested/'candidate.so', nested/'final.so'
        for name, path in (('candidate', subject), ('final', trusted)):
            artifacts[path] = digest(path); assert artifacts[path] == old['selection'][name]
        assert subject.read_bytes() == trusted.read_bytes() and subject.stat().st_ino != trusted.stat().st_ino
        caller = a.raw/'caller.so'
        d = stage('caller-build', [tool_paths['gcc'], *CALLER_FLAGS, repo/'tools/rapid-profiler/normal-work/caller.c', '-o', caller])
        assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
        artifacts[caller] = digest(caller); assert 0 < artifacts[caller]['bytes'] <= MIB
        candidate = a.raw/'caller-candidate.so'
        with candidate.open('xb') as f: f.write(caller.read_bytes())
        assert candidate.read_bytes() == caller.read_bytes() and candidate.stat().st_ino != caller.stat().st_ino
        artifacts[candidate] = digest(candidate)
        binaries = {n: repo/'target/release'/n for n in ('ordinary-interval', 'frontend-native-oracle')}
        for name, binary in binaries.items():
            artifacts[binary] = digest(binary); assert artifacts[binary] == old['artifacts'][name]['binary']
            assert old['artifacts'][name]['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
        argv = [subject, trusted, str(selection['elf_va']), str(selection['length']), candidate, caller]
        output = a.raw/'normal-output'
        d = stage('normal-state', [binaries['frontend-native-oracle'], 'normal-state', *argv, output], 90, 90)
        table = (output/'normal-pairs.csv').read_bytes()
        native, totals = check.state(table, (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), selection['length'])
        (a.raw/'normal-pairs.csv').write_bytes(table)
        d = stage('normal-work', [binaries['ordinary-interval'], 'normal-work', *argv])
        assert (d/'stderr.txt').read_bytes() == b''
        work, table = check.functional((d/'stdout.txt').read_bytes()); check.join(native, work)
        (a.raw/'normal-rows.csv').write_bytes(table)
        for name, owner in (('sampled', 'sampled'), ('closed', 'function-closed')):
            d = stage('drop-'+name, [binaries['ordinary-interval'], 'normal-drop-'+name, *argv])
            assert (d/'stderr.txt').read_bytes() == b''
            check.lifecycle((d/'stdout.txt').read_bytes(), owner)
        unchanged(); save(a.raw/'sources-after.json', {n: digest(repo/n) for n in names})
        assert tuple(r['name'] for r in result['stages']) == STAGES and all(r['status'] == 'PASS' for r in result['stages'])
        result.update(status='PASS', stage='complete',
            artifacts=dict(subject=artifacts[trusted], caller=artifacts[caller], **{n: artifacts[p] for n, p in binaries.items()}),
            outputs={n: digest(a.raw/n) for n in ('normal-pairs.csv', 'normal-rows.csv')},
            native=dict(pairs=17, stable_pairs=16, crossed_pairs=1, children=34, target_calls=68,
                target_returns=68, outer_returns=34, helper_joins=1, **totals),
            work=dict(original_calls=8, installed_calls=8, next_entry_acknowledgements=7,
                checkpoint_acknowledgements=1, sampled=4, function_closed=2, removed=2,
                generations=2, events=16, journal_words=512, reports=2, worker_joins=1),
            abandonment=dict(cases=2, original_calls=16, installed_calls=4, checkpoints=0,
                pending_after_tls_exit=2, reattach_refusals=2, worker_joins=2),
            closure=dict(owned_stages=10, nested_normal_helpers=46, nested_outer_owners=48, rescues=0),
            prior_failures='Fresh attempt with no retries; prior failures remain failures.')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print('normal-interval '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
