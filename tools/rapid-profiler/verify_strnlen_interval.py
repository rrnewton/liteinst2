#!/usr/bin/env python3
"""Bounded unchanged-FreeBSD-strnlen qualification after fresh named+selected prerequisites."""
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
import shutil
import subprocess
import tempfile
import traceback

MIB = 1048576
CORE_PREFIX = 'quiescent::whole_function::tests::'
CORE = tuple(CORE_PREFIX + name for name in (
    'whole_two_short_returns_keep_nops_controls_and_composition',
    'whole_final_branch_after_last_action_forces_full_end',
    'whole_first_five_head_routes_and_legacy_short_ret_refusal',
    'whole_cfg_refuses_escape_falloff_entry_reentry_and_non_scalar_shapes',
    'whole_entry_roles_and_finite_bounds_are_exact',
    'whole_overlay_authentication_precedes_image_search',
    'whole_actual_image_validator_refuses_branch_ret_maps_and_control_mutations'))
FRONT_PREFIX = 'frontend_native::always_on::site::ordinary::whole::tests::'
FRONT = tuple(FRONT_PREFIX + name for name in (
    'whole_group_keeps_entry_and_two_one_byte_return_roles_once',
    'whole_extent_includes_padding_and_branch_after_last_action',
    'whole_extent_keeps_exact_five_through_eighty_bound',
    'whole_missing_duplicate_unsorted_and_outside_roles_refuse',
    'whole_entry_backedge_escape_and_bad_block_geometry_refuse',
    'whole_support_does_not_change_old_valid_groups_or_old_short_refusal'))
STATE_PREFIX = 'oracle::native_ordinary::strnlen::tests::'
STATE = tuple(STATE_PREFIX + name for name in (
    'strnlen_cases_preserve_zero_early_last_and_nonzero_bytes',
    'strnlen_arguments_and_deadline_preserve_exact_bounds',
    'strnlen_operand_validator_joins_real_base_index_width_and_domain',
    'strnlen_cfg_refuses_unknown_transfers_and_nonpadding_unreachable_code',
    'strnlen_trace_refuses_wrong_arguments_successor_return_and_input',
    'strnlen_population_refuses_order_scalar_steps_and_incomplete_coverage'))
WORK_PREFIX = 'strnlen::check::tests::'
WORK = tuple(WORK_PREFIX + name for name in (
    'selected_canonical_cli_numbers', 'selected_exact_population_and_real_reports',
    'selected_call_owner_and_return_refusals', 'selected_whole_journal_prefix_and_tail_refusals',
    'selected_batch_identity_ranges_and_counts_refusals',
    'selected_report_full_identity_sequence_and_payload_refusals',
    'selected_history_requires_all_four_actual_actions'))
GROUPS = ('whole-core', 'whole-front', 'state-validator', 'work-validator')
STAGES = ('provenance-controls', 'parser-controls',
    *(name + suffix for name in GROUPS for suffix in ('-build', '-list', '-controls')),
    'header-closure', 'preprocess', 'macros', 'strnlen-c-build', 'prestrip-symbols', 'strip', 'final-symbols',
    'strnlen-refusals', 'strnlen-state', 'strnlen-work')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_strnlen_interval.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
    tools.update(python=Path(sys.executable).resolve(strict=True),
        **{n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'strip')})
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin') + ':/usr/bin:/bin', RUSTC=str(tools['rustc']), CC=str(tools['gcc']),
        CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
        CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def command(argv):
        data = subprocess.check_output(argv, cwd=repo, env=env, timeout=15)
        assert len(data) <= MIB
        return data.decode('ascii')
    def git(*argv):
        return command([str(tools['git']), '-C', str(repo), *argv])
    assert git('rev-parse', '--show-toplevel').strip() == str(repo)
    assert git('rev-parse', 'HEAD').strip() == a.revision
    assert git('status', '--porcelain', '--untracked-files=no') == ''
    modules = {'shared': 'tools/rapid-profiler/verify_ordinary_interval.py',
        'selected': 'tools/rapid-profiler/verify_selected_interval.py',
        'processes': 'evaluation/admission/processes.py',
        'legacy_check': 'tools/rapid-profiler/selected-work/check_output.py',
        'check': 'tools/rapid-profiler/strnlen-work/check_output.py',
        'provenance': 'tools/rapid-profiler/strnlen-work/provenance.py'}
    required = set(modules.values()) | {'tools/rapid-profiler/verify_strnlen_interval.py',
        'tools/rapid-profiler/selected-work/provenance.py', 'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs',
        'src/quiescent/whole_function.rs', 'src/quiescent/whole_function/tests.rs',
        'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary/whole.rs',
        'tools/rapid-profiler/strnlen-work/strnlen.c', 'tools/rapid-profiler/strnlen-work/UPSTREAM.json',
        'tools/rapid-profiler/strnlen-work/localize.map', 'tools/rapid-profiler/strnlen-work/cases.rs',
        'tools/rapid-profiler/strnlen-work/test_recipe.py', 'tools/rapid-profiler/strnlen-work/test_provenance.py',
        'tools/rapid-profiler/ordinary-interval/strnlen.rs', 'tools/rapid-profiler/native-interval/ordinary/strnlen.rs',
        'tests/support/native_strnlen.rs'}
    # Authenticate every imported source before its first import, including the
    # provenance wrapper's transitive shared module.
    for name in sorted(required):
        blob = subprocess.check_output([str(tools['git']), 'show', a.revision + ':' + name], cwd=repo, timeout=15)
        assert (repo/name).read_bytes() == blob
    shared = load('strnlen_shared', repo/modules['shared'])
    digest, save = shared.digest, shared.save
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
        'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    def sources():
        assert git('rev-parse', 'HEAD').strip() == a.revision
        assert git('status', '--porcelain', '--untracked-files=no') == ''
        assert set(git('ls-files', '-z', '--', *names).rstrip('\0').split('\0')) == set(names)
        return {n: digest(repo/n) for n in names}
    before = sources()
    for n in names:
        blob = subprocess.check_output([str(tools['git']), 'show', a.revision + ':' + n], cwd=repo, timeout=15)
        assert dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest()) == before[n]
    a.raw.mkdir(mode=0o700)
    result = dict(schema=1, revision=a.revision, status='FAILED', stage='setup',
        scope='Unchanged pinned FreeBSD strnlen in a controlled DSO; no deployed-libc, hardware, accuracy, performance or full-A5 claim.',
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_strnlen_interval.py', '--revision', a.revision,
            '--raw', '$RAW', '--toolchain', '$TOOLCHAIN', '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        commands=[], stages=[], planned_stages=list(STAGES),
        prerequisites={n: dict(status='UNRUN') for n in ('selected', *GROUPS)},
        qualifications={n: dict(status='UNRUN') for n in ('refusals', 'state', 'work')})
    artifacts, headers = {}, {}
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        assert sorted(os.sched_getaffinity(0)) == cpus
        for name in ('cc1', 'collect2', 'as', 'ld'):
            reported = command([str(tools['gcc']), '-print-prog-name=' + name]).strip()
            assert reported and '\n' not in reported
            p = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
            assert p.is_absolute()
            tools[name] = p.resolve(strict=True)
        tool_hashes = {n: digest(p) for n, p in tools.items()}
        save(a.raw/'sources-before.json', before)
        save(a.raw/'private-environment.json', dict(env=env, affinity=cpus, tools={n: str(p) for n, p in tools.items()}))
        selected = load('strnlen_selected_runner', repo/modules['selected'])
        processes = load('strnlen_processes', repo/modules['processes'])
        legacy_check = load('strnlen_legacy_check', repo/modules['legacy_check'])
        check = load('strnlen_check', repo/modules['check'])
        provenance = load('strnlen_provenance', repo/modules['provenance'])
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='strnlen-interval-', dir=logs_root))
        def header_record(path):
            resolved = path.resolve(strict=True)
            st = resolved.stat()
            identity = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
            record = dict(resolved=str(resolved), identity=identity(st), content=digest(resolved))
            assert path.resolve(strict=True) == resolved and identity(resolved.stat()) == record['identity']
            assert 0 < record['content']['bytes'] <= MIB
            return record
        def unchanged():
            assert sources() == before
            assert {n: digest(p) for n, p in tools.items()} == tool_hashes
            assert all(digest(p) == record for p, record in artifacts.items())
            assert all(header_record(Path(p)) == record for p, record in headers.items())
        def public_arg(value):
            value = str(value)
            for name, p in tools.items():
                if value == str(p): return '$' + name.upper()
            for p, token in ((a.raw, '$RAW'), (a.toolchain, '$TOOLCHAIN'), (a.user_home, '$USER_HOME'), (a.cargo_home, '$CARGO_HOME'), (repo, '$REPO')):
                if value == str(p) or value.startswith(str(p) + '/'):
                    return token + value[len(str(p)):]
            marker = '-Wl,--version-script='
            if value.startswith(marker): return marker + public_arg(value[len(marker):])
            assert not value.startswith('/') and '/home/' not in value and '@' not in value
            return value
        def closed_ok(closed):
            assert closed['exit_code'] == 0 and closed['termination'] is None
            assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
        def receipt_ok(d, request, parent):
            assert json.loads((d/'request.json').read_text()) == request
            assert json.loads((d/'parent-command.json').read_text()) == parent
            closed_ok(json.loads((d/'parent-closed.json').read_text()))
            receipt = json.loads((d/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(d/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            for stream in ('stdout', 'stderr'):
                assert receipt[stream + '_sha256'] == digest(d/(stream + '.txt'))['sha256']
            return dict(exit=0, absence_proof='ECHILD', rescues=0,
                request=digest(d/'request.json'), receipt=digest(d/'receipt.json'), parent_closed=digest(d/'parent-closed.json'),
                stdout=digest(d/'stdout.txt'), stderr=digest(d/'stderr.txt'))
        def stage(name, argv, cpu, wall, cap):
            unchanged(); result['stage'] = name
            public = [public_arg(v) for v in argv]; result['commands'].append(public)
            row = dict(name=name, status='FAILED', argv=public, cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')), stdout=str(d/'stdout.txt'),
                stderr=str(d/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(d/'request.json', request)
            args = [str(tools['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            parent = dict(argv=args, env=env, affinity=cpus, wall_seconds=wall + 25)
            save(d/'parent-command.json', parent)
            closed = processes.run_command(args, env, logs/(name + '.log'), wall + 25, MIB)
            save(d/'parent-closed.json', closed)
            log = (logs/(name + '.log')).read_bytes(); (d/'parent.log').write_bytes(log)
            row.update(receipt_ok(d, request, parent))
            assert json.loads(log) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            unchanged(); row['status'] = 'PASS'
            return d
        def profile(product, test):
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=test, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and product['profile']['test'] is test
            assert product['profile']['debug_assertions'] is product['profile']['overflow_checks'] is True
            assert type(product['fresh']) is bool

        # Mandatory fresh prerequisite; no stored campaign receipt is accepted.
        nested = a.raw/'selected-prerequisite'
        args = [str(tools['python']), '-B', str(repo/modules['selected']), '--revision', a.revision,
            '--raw', str(nested), '--toolchain', str(a.toolchain), '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'selected-prerequisite'; result['prerequisites']['selected']['status'] = 'FAILED'
        result['commands'].append([public_arg(v) for v in args])
        outer = dict(argv=args, env=env, affinity=cpus, wall_seconds=1800, log_bytes=8*MIB)
        save(a.raw/'selected-command.json', outer)
        closed = processes.run_command(args, env, logs/'selected.log', 1800, 8*MIB)
        save(a.raw/'selected-closed.json', closed); closed_ok(closed); unchanged()
        old = json.loads((nested/'result.json').read_text())
        assert old['status'] == 'PASS' and old['stage'] == 'complete' and old['revision'] == a.revision
        assert tuple(r['name'] for r in old['stages']) == selected.STAGES and len(old['commands']) == 19
        assert all(r['status'] == 'PASS' for r in [*old['stages'], *old['qualifications'].values(), *old['prerequisites'].values()])
        assert old['closure'] == dict(owned_stages=18, nested_owned_stages=4, normal_helpers=22, outer_owners=23, rescues=0)
        assert old['tools'] == tool_hashes
        assert old['prerequisites']['ordinary']['short_ret_refusals'] == 1
        assert (old['prerequisites']['ordinary']['state_pairs'], old['prerequisites']['ordinary']['children'],
                old['prerequisites']['ordinary']['originals'], old['prerequisites']['ordinary']['calls']) == (4, 8, 8, 8)
        assert (old['qualifications']['state']['summary']['pairs'], old['qualifications']['state']['summary']['children']) == (4, 8)
        assert (old['qualifications']['work']['summary']['originals'], old['qualifications']['work']['summary']['calls']) == (8, 8)
        old_sources = json.loads((nested/'sources-before.json').read_text())
        assert old_sources == json.loads((nested/'sources-after.json').read_text())
        assert old['sources'] == dict(count=len(old_sources), manifest=digest(nested/'sources-before.json'))
        assert all(before[n] == h for n, h in old_sources.items())
        result.update(tools=tool_hashes, versions=old['versions'], hardware=old['hardware'], sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')))
        def expand(value, raw):
            mapping = dict(REPO=repo, RAW=raw, TOOLCHAIN=a.toolchain, USER_HOME=a.user_home, CARGO_HOME=a.cargo_home,
                           **{n.upper(): p for n, p in tools.items()})
            return re.sub(r'\$([A-Z_]+)', lambda m: str(mapping[m[1]]), value)
        def rejoin_rows(rows, raw):
            for row in rows:
                name = row['name']; d = raw/name
                cpu, wall, cap = ((120, 180, 128*MIB) if name.endswith('-build') and name not in ('selected-c-build', 'c-build') else
                    (90, 90, MIB) if name == 'selected-state' else (10, 15, MIB) if name in ('provenance-controls', 'parser-controls') else (20, 30, MIB))
                assert (row['cpu_seconds'], row['wall_seconds'], row['file_bytes']) == (cpu, wall, cap)
                request = dict(argv=[expand(v, raw) for v in row['argv']], cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                    stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
                parent = dict(argv=[str(tools['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')], env=env, affinity=cpus, wall_seconds=wall + 25)
                join = receipt_ok(d, request, parent)
                assert all(row[k] == v for k, v in join.items())
        rejoin_rows(old['stages'], nested)
        ordinary = nested/'ordinary-prerequisite'
        ordinary_result = json.loads((ordinary/'result.json').read_text())
        assert ordinary_result['revision'] == a.revision and ordinary_result['status'] == ordinary_result['checksum_status'] == 'PASS'
        assert ordinary_result['stage'] == 'complete' and ordinary_result['required_short_ret_refusal'] is ordinary_result['worker_joined'] is True
        assert old['prerequisites']['ordinary']['result'] == digest(ordinary/'result.json')
        assert old['prerequisites']['ordinary']['outer_closed'] == digest(nested/'ordinary-closed.json')
        closed_ok(json.loads((nested/'ordinary-closed.json').read_text()))
        # The selected runner has already authenticated these four exact argv,
        # limits, receipts and parent joins; bind their complete current bytes.
        for row in old['prerequisites']['ordinary']['commands']:
            d = ordinary/row['name']
            assert all(row[k] == digest(d/file) for k, file in (('request', 'request.json'), ('receipt', 'receipt.json'),
                ('parent_closed', 'parent-closed.json'), ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt')))
            closed_ok(json.loads((d/'parent-closed.json').read_text()))
            receipt = json.loads((d/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['absence_proof'] == 'ECHILD'
            assert receipt['inputs_unchanged'] is True and receipt['cleanup_error'] is receipt['aborted'] is None
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert len(old['prerequisites']['ordinary']['commands']) == 4
        binaries = {n: repo/'target/release'/n for n in ('ordinary-interval', 'frontend-native-oracle')}
        messages = [json.loads(line) for line in (ordinary/'build/stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        for name, binary in binaries.items():
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == name]
            assert len(products) == 1
            product = products[0]; profile(product, False)
            assert binary.resolve(strict=True) == binary and product['executable'] == str(binary)
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
            source = 'ordinary-interval/main.rs' if name == 'ordinary-interval' else 'native-interval/main.rs'
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            record = old['artifacts'][name]
            assert product['profile'] == record['profile'] and product['fresh'] == record['cargo_fresh']
            assert type(record['cargo_fresh']) is bool
            assert digest(binary) == record['binary']; artifacts[binary] = record['binary']
        result['artifacts'] = {n: old['artifacts'][n] for n in binaries}
        result['prerequisites']['selected'] = dict(status='PASS', result=digest(nested/'result.json'),
            outer_command=digest(a.raw/'selected-command.json'), outer_closed=digest(a.raw/'selected-closed.json'),
            closure=old['closure'], ordinary_short_ret_refusal=True, ordinary_pairs=4, selected_pairs=4,
            named_originals=8, named_calls=8, selected_originals=8, selected_calls=8)

        for name, script, count in (('provenance-controls', 'test_provenance.py', 8), ('parser-controls', 'test_recipe.py', 9)):
            d = stage(name, [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/strnlen-work'/script)], 10, 15, MIB)
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        def test_group(label, package, target_flags, target_name, source, manifest, kind, crate_types, prefix, expected):
            result['prerequisites'][label]['status'] = 'FAILED'
            d = stage(label + '-build', [str(tools['cargo']), 'test', '--locked', '--offline', '--release', '--jobs', '4', '-p', package,
                *target_flags, '--no-run', '--message-format=json-render-diagnostics'], 120, 180, 128*MIB)
            messages = [json.loads(s) for s in (d/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target_name and m['profile']['test']]
            assert len(products) == 1
            product = products[0]; profile(product, True)
            binary = Path(product['executable'])
            assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
            assert re.fullmatch(re.escape(target_name.replace('-', '_')) + '-[0-9a-f]+', binary.name)
            assert product['manifest_path'] == str(repo/manifest) and product['target']['src_path'] == str(repo/source)
            assert product['target']['kind'] == kind and product['target']['crate_types'] == crate_types
            artifacts[binary] = digest(binary)
            result['artifacts'][label] = dict(binary=artifacts[binary], profile=product['profile'], cargo_fresh=product['fresh'])
            listed = stage(label + '-list', [str(binary), '--list'], 20, 30, MIB)
            inventory = legacy_check.census((listed/'stdout.txt').read_bytes(), (listed/'stderr.txt').read_bytes())
            assert set(n for n in inventory if n.startswith(prefix)) == set(expected)
            observed = stage(label + '-controls', [str(binary), prefix, '--test-threads=1'], 20, 30, MIB)
            result['prerequisites'][label] = legacy_check.controls((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), expected, inventory)
            result['prerequisites'][label]['full_census'] = dict(count=len(inventory), listing=digest(listed/'stdout.txt'))
        test_group('whole-core', 'liteinst2', ['--lib'], 'liteinst2', 'src/lib.rs', 'Cargo.toml', ['lib'], ['lib'], CORE_PREFIX, CORE)
        test_group('whole-front', 'rapid-profiler', ['--lib'], 'rapid_profiler', 'tools/rapid-profiler/src/lib.rs', 'tools/rapid-profiler/Cargo.toml', ['lib'], ['lib'], FRONT_PREFIX, FRONT)
        test_group('state-validator', 'rapid-profiler', ['--test', 'frontend-native-calibrations'], 'frontend-native-calibrations', 'tools/rapid-profiler/native-interval/calibrations.rs', 'tools/rapid-profiler/Cargo.toml', ['test'], ['bin'], STATE_PREFIX, STATE)
        test_group('work-validator', 'rapid-profiler', ['--bin', 'ordinary-interval'], 'ordinary-interval', 'tools/rapid-profiler/ordinary-interval/main.rs', 'tools/rapid-profiler/Cargo.toml', ['bin'], ['bin'], WORK_PREFIX, WORK)

        source = repo/'tools/rapid-profiler/strnlen-work/strnlen.c'
        script = repo/'tools/rapid-profiler/strnlen-work/localize.map'
        assert script.read_bytes() == provenance.VERSION_SCRIPT
        upstream = json.loads((repo/'tools/rapid-profiler/strnlen-work/UPSTREAM.json').read_text())
        assert upstream['source_sha256'] == check.SOURCE_SHA256 and upstream['blob'] == check.SOURCE_BLOB
        assert upstream['source_bytes'] == len(source.read_bytes()) and digest(source)['sha256'] == check.SOURCE_SHA256
        prestrip, final, depfile = a.raw/'prestrip.so', a.raw/'final.so', a.raw/'compiled.d'
        flags = [*shared.CFLAGS, '-Wl,--version-script=' + str(script)]
        d = stage('header-closure', [str(tools['gcc']), *flags, '-M', '-MT', 'strnlen-inputs', str(source)], 20, 30, MIB)
        assert (d/'stderr.txt').read_bytes() == b''
        header_names = check.dependencies((d/'stdout.txt').read_bytes())
        artifacts[d/'stdout.txt'] = digest(d/'stdout.txt')
        assert str(source) in header_names
        headers.update({p: header_record(Path(p)) for p in header_names})
        assert sum(r['content']['bytes'] for r in headers.values()) <= 16*MIB
        save(a.raw/'headers-before.json', headers)
        pre = stage('preprocess', [str(tools['gcc']), *flags, '-E', '-P', str(source)], 20, 30, MIB)
        macros = stage('macros', [str(tools['gcc']), *flags, '-E', '-dM', str(source)], 20, 30, MIB)
        assert (pre/'stderr.txt').read_bytes() == (macros/'stderr.txt').read_bytes() == b''
        abi = check.preprocessing(source.read_bytes(), (pre/'stdout.txt').read_bytes(), (macros/'stdout.txt').read_bytes())
        artifacts[pre/'stdout.txt'] = digest(pre/'stdout.txt'); artifacts[macros/'stdout.txt'] = digest(macros/'stdout.txt')
        d = stage('strnlen-c-build', [str(tools['gcc']), *flags, '-MD', '-MF', str(depfile), '-MT', 'strnlen-inputs', str(source), '-o', str(prestrip)], 20, 30, MIB)
        assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
        assert check.dependencies(depfile.read_bytes()) == header_names
        assert 0 < digest(prestrip)['bytes'] <= MIB
        artifacts[prestrip] = digest(prestrip); artifacts[depfile] = digest(depfile)
        premeta = stage('prestrip-symbols', [str(tools['readelf']), '--wide', '--symbols', str(prestrip)], 20, 30, MIB)
        artifacts[premeta/'stdout.txt'] = digest(premeta/'stdout.txt')
        stripped = stage('strip', [str(tools['strip']), '--strip-all', '-o', str(final), str(prestrip)], 20, 30, MIB)
        assert (stripped/'stdout.txt').read_bytes() == (stripped/'stderr.txt').read_bytes() == b''
        artifacts[final] = digest(final)
        finalmeta = stage('final-symbols', [str(tools['readelf']), '--wide', '--symbols', str(final)], 20, 30, MIB)
        artifacts[finalmeta/'stdout.txt'] = digest(finalmeta/'stdout.txt')
        assert (premeta/'stderr.txt').read_bytes() == (finalmeta/'stderr.txt').read_bytes() == b''
        selection = provenance.validate(prestrip.read_bytes(), final.read_bytes(), (premeta/'stdout.txt').read_bytes(), (finalmeta/'stdout.txt').read_bytes())
        assert selection['prestrip'] == artifacts[prestrip] and selection['final'] == artifacts[final]
        assert selection['label'] == 'freebsd-strnlen-14.1-v1' and 5 <= selection['length'] <= 80
        selection.update(revision=a.revision, source=before['tools/rapid-profiler/strnlen-work/strnlen.c'],
            upstream=before['tools/rapid-profiler/strnlen-work/UPSTREAM.json'], version_script=before['tools/rapid-profiler/strnlen-work/localize.map'],
            compiler_flags=flags[:-1] + ['-Wl,--version-script=$REPO/tools/rapid-profiler/strnlen-work/localize.map'],
            tools=tool_hashes, versions=result['versions'], abi=abi, headers=dict(count=len(headers), before=digest(a.raw/'headers-before.json')),
            preprocessed=digest(pre/'stdout.txt'), macros=digest(macros/'stdout.txt'), compiled_dependencies=artifacts[depfile],
            transformation=[r for r in result['stages'] if r['name'] in STAGES[14:21]])
        save(a.raw/'selection.json', selection); artifacts[a.raw/'selection.json'] = digest(a.raw/'selection.json')
        # Complete final authority is immutable before distinct-inode copies.
        candidate, mutated = a.raw/'candidate.so', a.raw/'mutated.so'
        final_bytes = final.read_bytes()
        for target in (candidate, mutated):
            data = bytearray(final_bytes)
            if target == mutated: data[selection['file_offset']] ^= 1
            with target.open('xb') as out: out.write(data)
            artifacts[target] = digest(target)
        assert len({(p.stat().st_dev, p.stat().st_ino) for p in (prestrip, final, candidate, mutated)}) == 4
        assert candidate.read_bytes() == final_bytes and artifacts[mutated]['bytes'] == len(final_bytes)
        assert [(i, x, y) for i, (x, y) in enumerate(zip(final_bytes, mutated.read_bytes())) if x != y] == [(selection['file_offset'], final_bytes[selection['file_offset']], final_bytes[selection['file_offset']] ^ 1)]
        result['selection'] = dict(manifest=artifacts[a.raw/'selection.json'], label=selection['label'], elf_va=selection['elf_va'],
            length=selection['length'], file_offset=selection['file_offset'], selected_code=selection['selected_code'],
            prestrip=artifacts[prestrip], final=artifacts[final], candidate=artifacts[candidate], changed_byte=artifacts[mutated],
            header_count=len(headers), headers=digest(a.raw/'headers-before.json'), preprocessed=digest(pre/'stdout.txt'), macros=digest(macros/'stdout.txt'), abi=abi)
        va, length = str(selection['elf_va']), str(selection['length'])
        result['qualifications']['refusals']['status'] = 'FAILED'
        d = stage('strnlen-refusals', [str(binaries['ordinary-interval']), 'strnlen-refusals', str(prestrip), str(final), str(mutated), va, length], 20, 30, MIB)
        result['qualifications']['refusals'] = check.refusals((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes())
        result['qualifications']['state']['status'] = 'FAILED'
        output = a.raw/'strnlen-output'
        d = stage('strnlen-state', [str(binaries['frontend-native-oracle']), 'strnlen-state', str(candidate), str(final), va, length, str(output)], 90, 90, MIB)
        table = (output/'strnlen-pairs.csv').read_bytes()
        result['qualifications']['state'] = dict(status='PASS', **check.state(table, (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), selection['length']))
        (a.raw/'strnlen-pairs.csv').write_bytes(table)
        result['qualifications']['work']['status'] = 'FAILED'
        d = stage('strnlen-work', [str(binaries['ordinary-interval']), 'strnlen-work', str(candidate), str(final), va, length], 20, 30, MIB)
        result['qualifications']['work'] = dict(status='PASS', **check.work((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), selection['length']))
        check.join(result['qualifications']['state'], result['qualifications']['work'])
        (a.raw/'strnlen-rows.csv').write_bytes(b'\n'.join((d/'stdout.txt').read_bytes().split(b'\n')[1:-2]) + b'\n')
        unchanged()
        after_headers = {p: header_record(Path(p)) for p in headers}
        assert after_headers == headers
        save(a.raw/'headers-after.json', after_headers); save(a.raw/'sources-after.json', sources())
        assert tuple(r['name'] for r in result['stages']) == STAGES and len(result['commands']) == 25
        assert all(r['status'] == 'PASS' for r in [*result['stages'], *result['prerequisites'].values(), *result['qualifications'].values()])
        result['outputs'] = {n: digest(a.raw/n) for n in ('strnlen-pairs.csv', 'strnlen-rows.csv')}
        result.update(status='PASS', stage='complete', closure=dict(owned_stages=24, nested_owned_stages=22,
            normal_helpers=46, outer_owners=48, rescues=0),
            prior_failures='No prior failure is reclassified or campaign reused; this fresh attempt performs no retries.')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print('strnlen-interval ' + result['status'] + ' stage=' + result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
