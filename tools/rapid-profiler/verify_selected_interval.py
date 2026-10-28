#!/usr/bin/env python3
"""Qualify one hidden/stripped C leaf under the existing bounded owners; no performance run."""
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
STAGES = ('provenance-controls', 'parser-controls',
    'admission-build', 'admission-list', 'admission-controls',
    'state-validator-build', 'state-validator-list', 'state-validator-controls',
    'work-validator-build', 'work-validator-list', 'work-validator-controls',
    'selected-c-build', 'prestrip-symbols', 'strip', 'final-symbols',
    'selected-refusals', 'selected-state', 'selected-work')
ADMISSION_PREFIX = 'frontend_native::module::ordinary::'
ADMISSION = (
    'frontend_native::module::ordinary::tests::complete_scalar_cfg_has_both_returns_and_explicit_padding',
    'frontend_native::module::ordinary::tests::control_edges_must_land_on_local_heads',
    'frontend_native::module::ordinary::tests::stack_system_call_and_noninteger_forms_refuse',
    'frontend_native::module::ordinary::tests::bounds_and_unreachable_code_are_not_coverage_exemptions',
    'frontend_native::module::ordinary::tests::explicit_external_contract_refusals_remain_separate',
    'frontend_native::module::ordinary::tests::complete_elf_symbol_parser_accepts_bounded_synthetic_owner',
    'frontend_native::module::ordinary::tests::elf_owner_symbol_and_runtime_loading_extensions_refuse',
    'frontend_native::module::ordinary::tests::aligned_empty_load_has_no_file_symbol_or_mapping_ownership',
    'frontend_native::module::ordinary::tests::empty_load_fields_and_real_overlaps_still_refuse',
    'frontend_native::module::ordinary::tests::elf_entry_metadata_does_not_replace_selected_symbol_authority',
    'frontend_native::module::ordinary::tests::elf_entry_requires_one_nonempty_executable_file_interval',
    'frontend_native::module::ordinary::tests::full_live_page_comparison_rejects_every_mutation_without_masks',
    'frontend_native::module::ordinary::tests::selection::selection_binds_final_bytes_and_rejects_invalid_descriptor_geometry',
    'frontend_native::module::ordinary::tests::selection::hidden_and_stripped_selection_do_not_change_named_admission',
    'frontend_native::module::ordinary::tests::selection::selection_uses_elf_va_and_complete_rx_file_extent',
    'frontend_native::module::ordinary::tests::selection::known_overlap_and_legacy_refusal_order_remain_strict',
    'frontend_native::module::ordinary::tests::selection::range_selection_keeps_elf_and_complete_cfg_refusals',
    'frontend_native::module::ordinary::tests::selection::missing_symbols_do_not_prove_function_completeness',
    'frontend_native::module::ordinary::tests::selection::resolver_checks_handle_bias_and_containing_object_without_symbol_fallback',
    'frontend_native::module::ordinary::tree::tests::tree_admission_exact_original_call_and_resume_geometry',
    'frontend_native::module::ordinary::tree::tests::tree_admission_changed_call_stack_ret_or_callee_refuses',
    'frontend_native::module::ordinary::tree::tests::tree_admission_complete_elf_owns_both_protected_symbols_and_page',
    'frontend_native::module::ordinary::tree::tests::tree_admission_elf_visibility_alias_geometry_and_envelope_refuse',
    'frontend_native::module::ordinary::tree::tests::tree_admission_external_contract_is_not_inferred_from_bytes',
)
STATE_PREFIX = 'oracle::native_ordinary::selected::tests::'
STATE_CONTROLS = (
    'oracle::native_ordinary::selected::tests::selected_arguments_require_canonical_complete_extent',
    'oracle::native_ordinary::selected::tests::selected_population_requires_order_counts_and_scalar',
    'oracle::native_ordinary::selected::tests::selected_ret_union_requires_all_declared_and_stable_ownership',
    'oracle::native_ordinary::selected::tests::selected_deadline_never_renews_or_accepts_other_profiles',
)
WORK_PREFIX = 'selected::check::tests::'
WORK_CONTROLS = (
    'selected::check::tests::selected_canonical_cli_numbers',
    'selected::check::tests::selected_exact_population_and_real_reports',
    'selected::check::tests::selected_call_owner_and_return_refusals',
    'selected::check::tests::selected_whole_journal_prefix_and_tail_refusals',
    'selected::check::tests::selected_batch_identity_ranges_and_counts_refusals',
    'selected::check::tests::selected_report_full_identity_sequence_and_payload_refusals',
    'selected::check::tests::selected_history_requires_all_four_actual_actions',
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    repo = Path(__file__).resolve().parents[2]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_selected_interval.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
    tools.update(python=Path(sys.executable).resolve(strict=True),
        **{n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'strip')})
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(tools['rustc']), CC=str(tools['gcc']),
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
    # All imported project sources are authenticated before their first import.
    modules = {'shared': 'tools/rapid-profiler/verify_ordinary_interval.py',
        'processes': 'evaluation/admission/processes.py',
        'check': 'tools/rapid-profiler/selected-work/check_output.py',
        'provenance': 'tools/rapid-profiler/selected-work/provenance.py'}
    for name in [*modules.values(), 'tools/rapid-profiler/verify_selected_interval.py']:
        blob = subprocess.check_output([str(tools['git']), 'show', a.revision+':'+name], cwd=repo, timeout=15)
        assert (repo/name).read_bytes() == blob
    shared = load('selected_shared', repo/modules['shared'])
    digest, save = shared.digest, shared.save
    required = set(modules.values()) | {'tools/rapid-profiler/verify_selected_interval.py',
        'tools/rapid-profiler/selected-work/test_recipe.py', 'tools/rapid-profiler/selected-work/test_provenance.py',
        'tools/rapid-profiler/selected-work/localize.map', 'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs',
        'tools/rapid-profiler/native-interval/ordinary/selected.rs', 'tests/support/native_selected.rs',
        'tools/rapid-profiler/ordinary-interval/selected.rs',
        'tools/rapid-profiler/ordinary-interval/selected/check.rs',
        'tools/rapid-profiler/ordinary-interval/selected/check/tests.rs'}
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
        blob = subprocess.check_output([str(tools['git']), 'show', a.revision+':'+n], cwd=repo, timeout=15)
        assert dict(bytes=len(blob), sha256=hashlib.sha256(blob).hexdigest()) == before[n]
    a.raw.mkdir(mode=0o700)
    result = dict(schema=1, revision=a.revision, status='FAILED', stage='setup',
        scope='Fixed selected hidden/stripped scalar leaf only; no discovery, performance, accuracy or full-A5 claim.',
        command=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_selected_interval.py',
            '--revision', a.revision, '--raw', '$RAW', '--toolchain', '$TOOLCHAIN',
            '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        commands=[], stages=[], prerequisites={n: dict(status='UNRUN') for n in ('ordinary', 'admission', 'state-validator', 'work-validator')}, qualifications={n: dict(status='UNRUN') for n in ('refusals', 'state', 'work')})
    artifacts = {}
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]
        assert len(cpus) == 4
        os.sched_setaffinity(0, cpus)
        assert sorted(os.sched_getaffinity(0)) == cpus
        # Resolve the actual GCC driver tools under the exact command environment.
        for name in ('cc1', 'collect2', 'as', 'ld'):
            reported = command([str(tools['gcc']), '-print-prog-name='+name]).strip()
            assert reported and '\n' not in reported
            p = Path(reported) if '/' in reported else Path(shutil.which(reported, path=env['PATH']) or '')
            assert p.is_absolute()
            tools[name] = p.resolve(strict=True)
        tool_hashes = {n: digest(p) for n, p in tools.items()}
        save(a.raw/'sources-before.json', before)
        save(a.raw/'private-environment.json', dict(env=env, affinity=cpus, tools={n: str(p) for n, p in tools.items()}))
        rust_text = command([str(tools['rustc']), '--version', '--verbose'])
        (a.raw/'rustc-version.txt').write_text(rust_text)
        rust = dict(line.split(': ', 1) for line in rust_text.splitlines() if ': ' in line)
        assert rust['host'] == 'x86_64-unknown-linux-gnu' and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release'])
        versions = dict(rust={n: rust[n] for n in ('release', 'commit-hash', 'host')}, python=list(sys.version_info[:3]))
        for name in ('cargo', 'gcc', 'git', 'readelf', 'strip', 'ld'):
            value = command([str(tools[name]), '--version']).splitlines()[0]
            assert value and all(32 <= ord(c) < 127 for c in value) and '/' not in value and '@' not in value
            versions[name] = value
        cpuinfo = [{k.strip(): v.strip() for k, v in (line.split(':', 1) for line in block.splitlines() if ':' in line)}
            for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        selected = [r for r in cpuinfo if int(r['processor']) in cpus]
        assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1
        vendor, family, model, stepping = hardware.pop()
        assert vendor in ('AuthenticAMD', 'GenuineIntel')
        result.update(tools=tool_hashes, versions=versions,
            hardware=dict(architecture='x86_64', vendor=vendor, family=family, model=model, stepping=stepping,
                caller_and_helper_shared_cpus=1, state_allowed_cpus=4, build_cpus=4),
            sources=dict(count=len(before), manifest=digest(a.raw/'sources-before.json')))
        processes = load('selected_processes', repo/modules['processes'])
        check = load('selected_check', repo/modules['check'])
        provenance = load('selected_provenance', repo/modules['provenance'])
        logs_root = repo/'target/evaluation'
        logs_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='selected-interval-', dir=logs_root))
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        def unchanged():
            assert sources() == before
            assert {n: digest(p) for n, p in tools.items()} == tool_hashes
            assert all(digest(p) == expected for p, expected in artifacts.items())
        def public_arg(value):
            value = str(value)
            for n, p in tools.items():
                if value == str(p): return '$'+n.upper()
            for p, token in ((a.raw, '$RAW'), (a.toolchain, '$TOOLCHAIN'),
                    (a.user_home, '$USER_HOME'), (a.cargo_home, '$CARGO_HOME'), (repo, '$REPO')):
                if value == str(p) or value.startswith(str(p)+'/'):
                    return token+value[len(str(p)):]
            marker = '-Wl,--version-script='
            if value.startswith(marker): return marker+public_arg(value[len(marker):])
            assert '/' not in value or not value.startswith('/')
            assert '/home/' not in value and '@' not in value
            return value
        def closed_ok(closed):
            assert closed['exit_code'] == 0 and closed['termination'] is None
            assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
        def receipt_ok(directory, request, parent, parent_command, parent_log=None):
            assert json.loads((directory/'request.json').read_text()) == request
            assert json.loads((directory/'parent-command.json').read_text()) == parent_command
            closed_ok(parent)
            receipt = json.loads((directory/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(directory/'request.json')['sha256']
            assert receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            for stream in ('stdout', 'stderr'):
                assert receipt[stream+'_sha256'] == digest(directory/(stream+'.txt'))['sha256']
            if parent_log is not None:
                assert json.loads(parent_log) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            return dict(exit=0, absence_proof='ECHILD', rescues=0,
                request=digest(directory/'request.json'), receipt=digest(directory/'receipt.json'),
                parent_closed=digest(directory/'parent-closed.json'), stdout=digest(directory/'stdout.txt'), stderr=digest(directory/'stderr.txt'))
        def stage(name, argv, cpu, wall, cap):
            unchanged()
            result['stage'] = name
            command_public = [public_arg(v) for v in argv]
            result['commands'].append(command_public)
            row = dict(name=name, status='FAILED', argv=command_public, cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            result['stages'].append(row)
            d = a.raw/name; d.mkdir(); (d/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(d/'request.json', request)
            argv_parent = [str(tools['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')]
            parent_command = dict(argv=argv_parent, env=env, affinity=cpus, wall_seconds=wall+25)
            save(d/'parent-command.json', parent_command)
            closed = processes.run_command(argv_parent, env, logs/(name+'.log'), wall+25, MIB)
            save(d/'parent-closed.json', closed)
            log = (logs/(name+'.log')).read_bytes(); (d/'parent.log').write_bytes(log)
            row.update(receipt_ok(d, request, closed, parent_command, log))
            unchanged()
            row['status'] = 'PASS'
            return d
        def pure_python(name, filename, count):
            d = stage(name, [str(tools['python']), '-B', str(repo/filename)], 10, 15, MIB)
            assert (d/'stdout.txt').read_bytes() == b''
            assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', (d/'stderr.txt').read_bytes())
        pure_python('provenance-controls', 'tools/rapid-profiler/selected-work/test_provenance.py', 6)
        pure_python('parser-controls', 'tools/rapid-profiler/selected-work/test_recipe.py', 8)

        # Fresh unchanged legacy four-stage qualification. Its bounded children
        # retain 20/30,120/180,90/90,20/30; the existing outer owner supervises
        # their complete runner. This is not an optional performance invocation.
        nested = a.raw/'ordinary-prerequisite'
        argv = [str(tools['python']), '-B', str(repo/modules['shared']), '--revision', a.revision,
            '--raw', str(nested), '--toolchain', str(a.toolchain), '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home)]
        result['stage'] = 'ordinary-prerequisite'
        result['prerequisites']['ordinary']['status'] = 'FAILED'
        result['commands'].append([public_arg(v) for v in argv])
        outer = dict(argv=argv, env=env, affinity=cpus, wall_seconds=600, log_bytes=8*MIB)
        save(a.raw/'ordinary-command.json', outer)
        closed = processes.run_command(argv, env, logs/'ordinary.log', 600, 8*MIB)
        save(a.raw/'ordinary-closed.json', closed); closed_ok(closed); unchanged()
        old = json.loads((nested/'result.json').read_text())
        assert old['status'] == old['checksum_status'] == 'PASS' and old['stage'] == 'complete' and old['revision'] == a.revision
        assert (old['originals'], old['calls'], old['entries'], old['returns'], old['completed'], old['unsampled'], old['reports']) == (8, 8, 8, 8, 6, 2, [4, 2])
        assert len(old['commands']) == 4 and old['required_short_ret_refusal'] is old['worker_joined'] is True
        assert old['sources'] == json.loads((nested/'sources-before.json').read_text()) == json.loads((nested/'sources-after.json').read_text())
        assert all(before[n] == h for n, h in old['sources'].items())
        binaries = {n: repo/'target/release'/n for n in ('ordinary-interval', 'frontend-native-oracle')}
        build_args = ['build', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--bin', 'frontend-native-oracle', '--message-format=json-render-diagnostics']
        nested_commands = [
            ('c-build', [str(tools['gcc']), *shared.CFLAGS, str(repo/'tools/rapid-profiler/native-interval/ordinary_checksum.c'), '-o', str(nested/'trusted.so')], 20, 30, MIB),
            ('build', [str(tools['cargo']), *build_args], 120, 180, 128*MIB),
            ('oracle', [str(binaries['frontend-native-oracle']), 'ordinary-state', str(nested/'candidate.so'), str(nested/'trusted.so'), str(nested/'oracle-output')], 90, 90, MIB),
            ('native', [str(binaries['ordinary-interval']), str(nested/'candidate.so'), str(nested/'trusted.so')], 20, 30, MIB)]
        old_catalog = [
            ['$GCC', *shared.CFLAGS, '$REPO/tools/rapid-profiler/native-interval/ordinary_checksum.c', '-o', '$RAW/trusted.so'],
            ['$CARGO', *build_args],
            ['$REPO/target/release/frontend-native-oracle', 'ordinary-state', '$RAW/candidate.so', '$RAW/trusted.so', '$RAW/oracle-output'],
            ['$REPO/target/release/ordinary-interval', '$RAW/candidate.so', '$RAW/trusted.so']]
        assert old['commands'] == old_catalog
        nested_closures = []
        for name, args, cpu, wall, cap in nested_commands:
            d = nested/name
            assert old[name]['process_exit'] == 0 and old[name]['strict_cleanup'] is True
            assert (old[name]['cpu_seconds'], old[name]['wall_seconds'], old[name]['file_bytes']) == (cpu, wall, cap)
            request = dict(argv=args, cwd=str(repo), env=dict(env, TMPDIR=str(d/'tmp')),
                stdout=str(d/'stdout.txt'), stderr=str(d/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            parent = dict(argv=[str(tools['python']), '-B', str(helper), '--request', str(d/'request.json'), '--receipt', str(d/'receipt.json')], env=env, affinity=cpus, wall_seconds=wall+25)
            nested_closures.append(dict(name=name, argv=[public_arg(v) for v in args], cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap,
                **receipt_ok(d, request, json.loads((d/'parent-closed.json').read_text()), parent)))
        # Join actual Cargo output too; a compact result alone is not artifact authority.
        messages = [json.loads(line) for line in (nested/'build/stdout.txt').read_text().splitlines()]
        assert messages[-1] == dict(reason='build-finished', success=True)
        for name, binary in binaries.items():
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == name]
            assert len(products) == 1
            product = products[0]
            assert product['executable'] == str(binary) and binary.resolve(strict=True) == binary
            assert product['target']['kind'] == product['target']['crate_types'] == ['bin']
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            source = 'ordinary-interval/main.rs' if name == 'ordinary-interval' else 'native-interval/main.rs'
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            record = old['build']['artifacts'][name]
            assert record['profile'] == dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
            assert product['profile'] == record['profile'] and product['fresh'] == record['cargo_fresh']
            assert type(product['profile']['debuginfo']) is int and product['profile']['test'] is False
            assert product['profile']['debug_assertions'] is product['profile']['overflow_checks'] is True
            assert type(product['fresh']) is bool and type(record['cargo_fresh']) is bool and digest(binary) == record['binary']
            artifacts[binary] = record['binary']
        assert (nested/'oracle/stderr.txt').read_bytes() == (nested/'native/stderr.txt').read_bytes() == b''
        old_pairs, _, comparisons = shared.native_output(nested/'oracle-output', (nested/'oracle/stdout.txt').read_bytes())
        old_rows, _ = shared.output((nested/'native/stdout.txt').read_bytes())
        assert old_rows == old['rows'] and old_pairs == old['oracle']['rows'] and comparisons == old['oracle']['comparisons']
        result['prerequisites']['ordinary'] = dict(status='PASS', result=digest(nested/'result.json'), outer_closed=digest(a.raw/'ordinary-closed.json'),
            commands=nested_closures, state_pairs=4, children=8, short_ret_refusals=1, originals=8, calls=8)
        result['artifacts'] = dict(old['build']['artifacts'])

        # Exact release artifacts plus fixed selected method names. --list only
        # supplies the full compiled census used to authenticate filtered counts.
        def test_group(label, target_flags, target_name, source, kind, crate_types, prefix, expected):
            result['prerequisites'][label]['status'] = 'FAILED'
            args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', *target_flags, '--no-run', '--message-format=json-render-diagnostics']
            d = stage(label+'-build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
            messages = [json.loads(s) for s in (d/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == target_name and m['profile']['test']]
            assert len(products) == 1
            product = products[0]; binary = Path(product['executable'])
            assert binary.resolve(strict=True) == binary and binary.parent == repo/'target/release/deps'
            assert re.fullmatch(re.escape(target_name.replace('-', '_'))+'-[0-9a-f]+', binary.name)
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source)
            assert product['target']['kind'] == kind and product['target']['crate_types'] == crate_types
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
            assert all(product['profile'][k] is True for k in ('test', 'debug_assertions', 'overflow_checks'))
            artifacts[binary] = digest(binary)
            result['artifacts'][label] = dict(binary=artifacts[binary], profile=product['profile'], cargo_fresh=product['fresh'])
            listed = stage(label+'-list', [str(binary), '--list'], 20, 30, MIB)
            inventory = check.census((listed/'stdout.txt').read_bytes(), (listed/'stderr.txt').read_bytes())
            assert set(n for n in inventory if n.startswith(prefix)) == set(expected)
            observed = stage(label+'-controls', [str(binary), prefix, '--test-threads=1'], 20, 30, MIB)
            result['prerequisites'][label] = check.controls((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), expected, inventory)
            result['prerequisites'][label]['full_census'] = dict(count=len(inventory), listing=digest(listed/'stdout.txt'))
        test_group('admission', ['--lib'], 'rapid_profiler', 'src/lib.rs', ['lib'], ['lib'], ADMISSION_PREFIX, ADMISSION)
        test_group('state-validator', ['--test', 'frontend-native-calibrations'], 'frontend-native-calibrations',
            'native-interval/calibrations.rs', ['test'], ['bin'], STATE_PREFIX, STATE_CONTROLS)
        test_group('work-validator', ['--bin', 'ordinary-interval'], 'ordinary-interval',
            'ordinary-interval/main.rs', ['bin'], ['bin'], WORK_PREFIX, WORK_CONTROLS)

        prestrip, final = a.raw/'prestrip.so', a.raw/'final.so'
        script = repo/'tools/rapid-profiler/selected-work/localize.map'
        assert script.read_bytes() == provenance.VERSION_SCRIPT
        built = stage('selected-c-build', [str(tools['gcc']), *shared.CFLAGS, '-Wl,--version-script='+str(script),
            str(repo/'tools/rapid-profiler/native-interval/ordinary_checksum.c'), '-o', str(prestrip)], 20, 30, MIB)
        assert (built/'stderr.txt').read_bytes() == b'' and 0 < digest(prestrip)['bytes'] <= MIB
        artifacts[prestrip] = digest(prestrip)
        premeta = stage('prestrip-symbols', [str(tools['readelf']), '--wide', '--symbols', str(prestrip)], 20, 30, MIB)
        stripped = stage('strip', [str(tools['strip']), '--strip-all', '-o', str(final), str(prestrip)], 20, 30, MIB)
        assert (stripped/'stdout.txt').read_bytes() == (stripped/'stderr.txt').read_bytes() == b''
        artifacts[final] = digest(final)
        finalmeta = stage('final-symbols', [str(tools['readelf']), '--wide', '--symbols', str(final)], 20, 30, MIB)
        assert (premeta/'stderr.txt').read_bytes() == (finalmeta/'stderr.txt').read_bytes() == b''
        selection = provenance.validate(prestrip.read_bytes(), final.read_bytes(),
            (premeta/'stdout.txt').read_bytes(), (finalmeta/'stdout.txt').read_bytes())
        assert selection['prestrip'] == artifacts[prestrip] and selection['final'] == artifacts[final]
        selection.update(revision=a.revision, source=before['tools/rapid-profiler/native-interval/ordinary_checksum.c'],
            version_script=before['tools/rapid-profiler/selected-work/localize.map'], tools=tool_hashes, versions=versions,
            transformation=[r for r in result['stages'] if r['name'] in ('selected-c-build', 'prestrip-symbols', 'strip', 'final-symbols')])
        save(a.raw/'selection.json', selection)
        artifacts[a.raw/'selection.json'] = digest(a.raw/'selection.json')
        # Manifest exists and is pinned BEFORE either candidate copy is created.
        candidate, mutated = a.raw/'candidate.so', a.raw/'mutated.so'
        final_bytes = final.read_bytes()
        for target in (candidate, mutated):
            data = bytearray(final_bytes)
            if target == mutated: data[selection['file_offset']] ^= 1
            with target.open('xb') as out: out.write(data)
            assert (target.stat().st_dev, target.stat().st_ino) != (final.stat().st_dev, final.stat().st_ino)
            artifacts[target] = digest(target)
        assert candidate.read_bytes() == final_bytes
        assert [(i, a, b) for i, (a, b) in enumerate(zip(final_bytes, mutated.read_bytes())) if a != b] == [
            (selection['file_offset'], final_bytes[selection['file_offset']], final_bytes[selection['file_offset']] ^ 1)]
        assert artifacts[mutated]['bytes'] == artifacts[final]['bytes']
        result['selection'] = dict(manifest=artifacts[a.raw/'selection.json'], label=selection['label'], elf_va=selection['elf_va'],
            length=selection['length'], file_offset=selection['file_offset'], selected_code=selection['selected_code'],
            prestrip=artifacts[prestrip], final=artifacts[final], candidate=artifacts[candidate], changed_byte=artifacts[mutated])
        va, length = str(selection['elf_va']), str(selection['length'])
        result['qualifications']['refusals']['status'] = 'FAILED'
        d = stage('selected-refusals', [str(binaries['ordinary-interval']), 'selected-refusals', str(prestrip), str(final), str(mutated), va, length], 20, 30, MIB)
        result['qualifications']['refusals'] = check.refusals((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes())
        result['qualifications']['state']['status'] = 'FAILED'
        output = a.raw/'selected-output'
        d = stage('selected-state', [str(binaries['frontend-native-oracle']), 'selected-state', str(candidate), str(final), va, length, str(output)], 90, 90, MIB)
        table = (output/'selected-pairs.csv').read_bytes()
        result['qualifications']['state'] = dict(status='PASS', **check.state(table, (d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes()))
        (a.raw/'selected-pairs.csv').write_bytes(table)
        result['qualifications']['work']['status'] = 'FAILED'
        d = stage('selected-work', [str(binaries['ordinary-interval']), 'selected-work', str(candidate), str(final), va, length], 20, 30, MIB)
        result['qualifications']['work'] = dict(status='PASS', **check.work((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), selection['length']))
        (a.raw/'selected-rows.csv').write_text('\n'.join((d/'stdout.txt').read_text().splitlines()[1:-1])+'\n')
        unchanged()
        save(a.raw/'sources-after.json', sources())
        assert all(row['status'] == 'PASS' for row in result['stages'])
        assert all(row['status'] == 'PASS' for row in result['qualifications'].values())
        assert all(row['status'] == 'PASS' for row in result['prerequisites'].values())
        assert tuple(row['name'] for row in result['stages']) == STAGES and len(result['commands']) == 19
        result.update(status='PASS', stage='complete', closure=dict(owned_stages=18, nested_owned_stages=4,
            normal_helpers=22, outer_owners=23, rescues=0),
            prior_failures='No prior campaign is reused or reclassified. Prior-attempt lineage is outside this fresh receipt.')
    except BaseException as error:
        result['error_type'] = type(error).__name__
        (a.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        save(a.raw/'result.json', result)
    print('selected-interval '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
