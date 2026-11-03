#!/usr/bin/env python3
"""One bounded user-DWARF observation of a retained RO LOOP13 LS failure.

Run from the repository root on the original reserved CPU. No build, counter
substitution, qualified retry, successful-target or performance credit.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True


def need(ok, why):
    if not ok: raise ValueError(why)


def save(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2, allow_nan=False)
        f.write('\n'); f.flush(); os.fsync(f.fileno())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--diagnostic-receipt', type=Path, required=True)
    ap.add_argument('--diagnostic-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    return execute(ap.parse_args())


def execute(a, *, group_descriptor=False):
    need(type(group_descriptor) is bool, 'explicit natural descriptor profile selector')
    root = Path.cwd().resolve()
    sys.path[:0] = [str(root/'evaluation/inprocess'), str(root/'tools/page-entry')]
    from checks import source
    from run import hardware
    from page_selected import fact, interpreter, bridge_check
    from page_selected_shared_decoder import source_key
    from page_selected_process import invoke
    from page_cost_profile import profile, TARGET, PERF
    from persistent_dynamic_profile import observer_libraries
    from persistent_dynamic_profile_read import script_argv, attribute
    from persistent_dynamic import imported_sources, digest, load
    from page_selected_register_time_build import recipe, expand, headers
    from persistent_epoch_build import dynamic_original_image
    if group_descriptor:
        from loop_resident_rx_program import SCHEDULE, BOUNDS
        from profile_storage import SlotGuard
    else:
        from loop_ro_program_release import SCHEDULE, BOUNDS
    from types import SimpleNamespace
    from page_cost_compare import PROGRAM_ENV
    from page_native_pair_performance import namespace_join
    from page_selected_effect_ls import finalize
    import namespace
    subject = [30, 512 << 20, 16 << 20, 60]
    need(not sys.flags.optimize and sys.version_info[:2] == (3, 12) and
         len(os.sched_getaffinity(0)) == 1 and list(TARGET) == subject and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', a.diagnostic_sha256), 'exact source, Python and original subject bounds')
    cpu = next(iter(os.sched_getaffinity(0))); output = a.output.absolute()
    need(output.parent == root/'target/evaluation/inprocess' and not output.exists(), 'fresh private output')
    storage = None
    if group_descriptor:
        need(list(PERF) == [30, 1 << 30, 128 << 20, 80], 'unchanged bounded observer and DWARF child limits')
        storage = SlotGuard(root, output, PERF[2])
        storage.reserve(0, 'initial metadata directory')
    output.mkdir(mode=0o700)
    r = dict(schema=1, profile='loop-group-descriptor-program-user-dwarf-natural-v1' if group_descriptor else 'loop-ro-program-user-dwarf-diagnostic-v1', status='failed',
        cpu=cpu, hardware=hardware(cpu), argv=[sys.executable, '-B', *sys.argv], source=None,
        compiled_source=None, subject_bounds=subject, observer_bounds=list(PERF), unwinder_bounds=list(PERF),
        commands=[], inputs_unchanged=False, source_unchanged=False, cleanup_complete=False,
        qualification_credit=False, performance_credit=False, successful_target_credit=False,
        original_diagnostic_reclassified=False, error=None, final_errors=[], namespace_aliases={},
        scope='One separately observed LS execution from the retained failed case and RO bridge. User-only 99Hz samples and actual wait4 usage; no terminal counts invented. No kernel stack, complete unwind, kill-cause, timing or qualification inference.')
    if group_descriptor:
        r.update(storage_guard=storage.record, matched_timing_credit=False, speedup_credit=False,
            scope='One separately observed LS execution from an exact clean installed descriptor34 failure. '
                  'User-only 99Hz samples and actual wait4 usage; no terminal counts invented, timing, '
                  'kernel-stack, complete-unwind, kill-cause or qualification inference.')
    pins = {}; artifacts = {}; aliases = {}
    def pin(path, expected=None):
        lexical = Path(path).absolute(); p = lexical.resolve(strict=True); v = fact(p)
        if expected is not None:
            need(all(v[k] == expected[k] for k in ('bytes', 'sha256')) and
                 ('mode' not in expected or stat.S_IMODE(p.stat().st_mode) == expected['mode']),
                 'whole recorded input '+str(p))
        need(str(p) not in pins or pins[str(p)] == v, 'stable input bytes')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = v; aliases[str(lexical)] = str(p); return p
    def binary(path):
        p = pin(path); artifacts[str(p)] = dict(pins[str(p)], mode=stat.S_IMODE(p.stat().st_mode)); return p
    def stable():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same observer source and CPU')
        need(all(fact(p) == v for p, v in pins.items()), 'all original and observed inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'all input aliases unchanged')
        need(all(dict(fact(p), mode=stat.S_IMODE(Path(p).stat().st_mode)) == v
                 for p, v in artifacts.items()), 'all retained artifact bytes and modes unchanged')
        finalize(r)
    def run(name, argv, env):
        stable()
        if storage is not None: storage.reserve(2*PERF[2], 'observer child '+name)
        row = dict(name=name, argv=list(map(str, argv)), environment=env,
                   bounds=list(PERF), capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        out, err = invoke(row, output, cpu)
        need(row['exit'] == 0 and row['reaped'] is True and row['timed_out'] is False and
             row['error'] is None and row['cleanup_errors'] == [] and
             all(d['closed'] is True for d in row['descriptors']), 'original bounded observer command')
        return out, err
    try:
        r['source'] = source()
        need(r['source']['revision'] == a.expect_revision, 'exact clean current observer revision')
        pin(__file__); imported_sources(pin)
        if storage is not None: pin(storage.du, storage.du_fact)
        origin = pin(a.diagnostic_receipt)
        need(pins[str(origin)]['sha256'] == a.diagnostic_sha256 and origin.name == 'receipt.json' and
             origin.parent.parent == root/'target/evaluation/inprocess', 'whole closed original receipt')
        old = json.loads(origin.read_bytes()); r['compiled_source'] = old['source']
        need(old['profile'] == ('loop-group-descriptor-program-release-v1' if group_descriptor else 'loop-ro-program-release-v1') and old['status'] == 'failed' and
             old['revision'] == old['source']['revision'] and old['source']['tracked_clean'] is True and
             old['source']['head_sources_match'] is True and old['source_unchanged'] is True and
             old['cleanup_complete'] is True and old['inputs_unchanged'] is True and old['final_errors'] == [] and
             old['qualification_credit'] is old['performance_credit'] is old['full_state_credit'] is False and
             (group_descriptor or (old['cpu'] == cpu and old['hardware'] == r['hardware'])),
             'closed failed development observation on this exact CPU/hardware; no promotion')
        if group_descriptor:
            need(old['source'] == r['source'] and old['source_manifest'] is None and
                 old['source_context'] == 'installed tracked source' and
                 old['whole_profile_qualified'] is False and old['cpu'] == old['hardware']['probe_cpu'] and
                 set(old['hardware']) == set(r['hardware']) and
                 all(old['hardware'][k] == r['hardware'][k] for k in old['hardware'] if k != 'probe_cpu'),
                 'exact natural34 installed source and all hardware fields except explicit reserved CPU number')
            r.update(original_cpu=old['cpu'], original_hardware=old['hardware'], same_cpu=(cpu == old['cpu']),
                hardware_comparison_excludes=['probe_cpu'],
                cpu_scope='Current reserved singleton and original CPU remain separate; no matched timing comparison.')
            need(all(Path(p).is_symlink() and os.readlink(p) == v for p,v in old['namespace_aliases'].items()),
                 'all original descriptor namespace aliases remain exact')
        need(old['bounds'] == BOUNDS and len(SCHEDULE) == 34 and
             [(c['workload'], c['lane']) for c in old['cases']] == [('ls', 'release'), ('true', 'release')] and
             all(c['status'] == 'failed' and c['exit'] == -9 and
                 c['completed_program_measurement'] is False and 'observed' not in c for c in old['cases']),
             'literal original two-subject failure, without completed-program counters')
        for p, v in old['inputs'].items(): pin(p, v)
        for p, v in old['artifacts'].items(): binary(pin(p, v))
        for lexical, actual in old['aliases'].items():
            need(str(Path(lexical).resolve(strict=True)) == actual and
                 (lexical not in aliases or aliases[lexical] == actual), 'original aliases')
            aliases[lexical] = actual
        need(all(os.path.lexists(p) == present for p, present in old['presence'].items()) and
             old['presence']['/etc/ld.so.preload'] is False, 'original loader configuration presence')
        commands = old['commands']
        need(tuple((c['name'], c['profile']) for c in commands) == SCHEDULE and
             len(commands) == len({c['name'] for c in commands}) == 34 and
             [c['exit'] for c in commands] == [0]*32+[-9, -9], 'all original34 command identities and outcomes')
        for c in commands:
            need(type(c['exit']) is int and c['reaped'] is True and c['timed_out'] is False and
                 c['error'] is None and c['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in c['descriptors']) and
                 c['bounds'] == old['bounds'][c['profile']] and c['capture_limit'] == 16 << 20 and
                 c['expected_exit'] == 0, 'whole original command process closure')
            need(json.loads(pin(origin.parent/(c['name']+'.json')).read_bytes()) == c, 'whole original command record')
            for v in c['captures'].values():
                need(Path(v['file']).name == v['file'], 'local original capture')
                pin(origin.parent/v['file'], v)
        prior, = [c for c in commands if c['name'] == 'ls-release']
        need(prior['exit'] == -9 and prior['bounds'] == subject and prior['capture_limit'] == 16 << 20 and
             prior['expected_exit'] == 0 and prior['environment'] == PROGRAM_ENV and
             all(v['bytes'] == 0 for v in prior['captures'].values()), 'exact failed RO LS tuple, without terminal')
        original = pin('/bin/ls', old['system_inputs']['ls']['original'])
        build = old['release_builds']['ls']; binding = build['binding']
        need(build['status'] == 'compiled_diagnostic_only' and
             binding['profile'] == ('persistent-loop-group-descriptor-program-release-v1' if group_descriptor else 'persistent-loop-ro-certificate-release-v1') and binding['mode'] == 'release' and
             binding['archive'] == old['archive'] and binding['capture_version'] is None and
             binding['byte_certificate'] == dict(version=1, sealed_generation=True, source_lease=False,
                 mirror='isolated-anonymous-RO', root='isolated-anonymous-RO', mirror_pages=89, slots=8 if group_descriptor else 2,
                 full_scan_fallback=True, every_hit_full_scan=False, old_capture_compatible=False,
                 qualification_credit=False) and
             binding['history_certificate'] == dict(version=1, cells=9 if group_descriptor else 3, saved_completion='isolated-anonymous-RO',
                 witnesses='isolated-anonymous-RO', complete_live_predicates=True,
                 every_hit_reconstruction=False, qualification_credit=False),
             'actual retained RO release, no test/capture/counter or differential profile')
        if group_descriptor:
            need('oracle' not in binding and 'control' not in binding and binding['rx_lifetime'] == dict(
                 version=2, slots=8, source_release_version=1,
                 continuation='at-most-two-authenticated-original-DIRECT-TF-steps', branch_limit=2,
                 unsafe_handoff='revoke-all-before-original-route', original_domain_preserved=True,
                 old_capture_compatible=False, code_permission_counts='actual-pe_permission-calls',
                 metadata_permission_counts='actual-pe_permission-calls-only', qualification_credit=False),
                 'exact separately typed eight-slot/two-branch production lifetime; no oracle instrumentation')
            need(not any(k in binding for k in ('recurrence','cache8_observer','group_descriptor_observer')) and
                 binding['cache8'] == dict(version=1,slots=8,members=8,completion_cells=9,source_pages=2,
                     placement_banks=2,aggregate_heads=256,aggregate_boundaries=8,rx_receipt_version=2,
                     selection='exact-root-or-head-then-empty-or-oldest-completion',
                     activation='post-publication-DIRECT-connected-claimed-closure',
                     inactive_heads_exposed=False,qualification_credit=False) and
                 binding['cache8_program'] == dict(version=1,fields=63,slots=8,members=8,receipts=9,
                     terminal_only=True,observation_authority=False,qualification_credit=False) and
                 binding['group_descriptor'] == dict(version=1,groups=1,members=8,heads=256,boundaries=8,
                     directory_order='ascending-retained-slot',directory_serial='descriptor-id',
                     activation_claims='fresh-every-entry',raw_exposure='pre-kernel-monotone-epochs',
                     common_proof='existing-LHC-owner',physical_queries='fresh-original-member-checks',
                     old_capture_compatible=False,qualification_credit=False),
                 'exact descriptor/cache8 activation contract and terminal-only reporting')
        stem = 'persistent-loop-group-descriptor-program' if group_descriptor else 'persistent-loop-ro-certificate'
        bridge = pin(build['argv'][-1], build['bridge']); directory = bridge.parent
        need(directory == origin.parent/'ls-build/build' and str(bridge) in old['artifacts'] and
             bridge.name == 'bridge-'+stem+'.so' and bridge_check(bridge) == build['elf'],
             'actual retained bridge and independently checked ELF')
        manifest = pin(directory/(stem.replace('-', '_')+'_binding.json'), build['manifest'])
        need(json.loads(manifest.read_bytes()) == binding, 'whole original generated binding manifest')
        selected = root/'tools/page-entry/selected'
        recipe_path = pin(selected/('build-'+stem+'.sh'), build['recipe'])
        owned = old['build']['artifacts']['decoder.a']; archive = pin(owned['path'], owned)
        need(fact(archive) == old['archive'] and str(archive) in old['artifacts'], 'same fresh producer archive')
        tools = {k: pin(v['path'], v) for k, v in old['build']['tools'].items()}
        need(tools['python'] == Path(sys.executable).resolve(), 'actual retained Python tool')
        builder = SimpleNamespace(tools=tools, environment=old['build']['environment'])
        links = recipe(recipe_path, '"$cc_bin"'); need(len(links) == 1, 'one actual source-owned compiler invocation')
        argv = expand(links[0], {'$cc_bin': tools['cc'], '$selected_dir': selected,
            '$parent_dir': selected.parent, '$archive': archive, '$output': directory})
        need(argv == build['argv'], 'literal whole current recipe equals original compiler argv')
        link, = [c for c in commands if c['name'] == 'ls-build']
        need(link['argv'] == list(map(str, (tools['sh'], recipe_path, archive, original, directory, 'release'))) and
             link['environment'] == dict(builder.environment, LI2_CC=str(tools['cc']), LI2_PYTHON=str(tools['python'])) and
             all(v['bytes'] == 0 for v in link['captures'].values()), 'whole actual source-owned shell link tuple')
        dependencies = ('persistent_epoch_binding', 'persistent_group_binding', 'persistent_retained_two_binding',
            'persistent_active_domain_binding', 'persistent_startup_binding', 'persistent_loop_binding')
        if group_descriptor:
            dependencies += ('persistent_loop_ro_certificate_binding', 'persistent_loop_resident_rx_binding')
        for name in dependencies:
            path = pin(selected/(name+'.py'))
            need(name not in sys.modules or Path(sys.modules[name].__file__).resolve() == path,
                 'canonical selected binder dependency')
        previous = list(sys.path)
        try:
            sys.path.insert(0, str(selected))
            binder = load('profile_descriptor_binding' if group_descriptor else 'profile_ro_binding',
                selected/(stem.replace('-', '_')+'_binding.py'), pin)
        finally:
            sys.path[:] = previous
        need(all(Path(sys.modules[n].__file__).resolve() == selected/(n+'.py') for n in dependencies),
             'complete canonical binder import closure')
        values = [dict(path=name, **fact(pin(selected/name))) for name in binder.LEAVES]
        need(len(values) == len({v['path'] for v in values}) and binding['sources'] == values and
             binding['policy_sha256'] == digest(dict(sources=values, original=binding['original'], mode='release')),
             'every current policy source and exact original policy digest')
        for v in values:
            if v['path'].endswith('.rs'):
                need(old['build']['dep_info'][source_key(root, selected, v['path'])] ==
                     {k: v[k] for k in ('bytes', 'sha256')}, 'current Rust source belongs to actual archive')
        used = []
        def recorded(name, argv, profile, env):
            need(name == 'ls-headers' and not used, 'one original compiler-M replay, no execution')
            row, = [c for c in commands if c['name'] == name]
            need(row['argv'] == list(map(str, argv)) and row['profile'] == profile and row['environment'] == env,
                 'exact original compiler-M invocation')
            used.append(name)
            return row, *( (origin.parent/row['captures'][k]['file']).read_bytes() for k in ('stdout', 'stderr'))
        observed = {}
        headers('ls-headers', argv, [x for x in argv if x.endswith(('.c', '.S'))],
                archive, builder, pin, aliases, recorded, observed)
        need(used == ['ls-headers'] and observed['headers'] == build['headers'], 'whole current compiler include closure')
        for v in values:
            if v['path'].endswith(('.c', '.h', '.inc')):
                need(observed['headers'][str((selected/v['path']).resolve())] ==
                     {k: v[k] for k in ('bytes', 'sha256')}, 'every bound C source is actually compiled')
        need(set(binding['headers']) == {'linked_epoch_config.h', 'persistent_group_config.h', 'loop_ro_certificate_config.h'},
             'all three actual source binding headers')
        for name, value in binding['headers'].items():
            need(fact(pin(directory/name, value)) == observed['headers'][str(directory/name)], 'whole compiled generated header')
        need((directory/'loop_ro_certificate_config.h').read_text() == (sys.modules['persistent_loop_resident_rx_binding'] if group_descriptor else binder).certificate_header('release'),
             'literal RO release selector, with maintained maps and no differential or test hook')
        r['retained_build'] = dict(binding=binding, bridge=build['bridge'], recipe=build['recipe'],
            manifest=build['manifest'], compiler_argv=argv, headers=observed['headers'],
            original_link=link['name'], metadata_replays=used, rebuilt=False)
        interp = pin(interpreter(original), old['system_inputs']['ls']['interpreter'])
        carrier = pin(origin.parent/'ls-carrier', old['carriers']['ls'])
        tool = pin(root/'tools/page-entry/carrier.py'); python = pin(sys.executable)
        need(interpreter(carrier) == bridge and binding['original'] == dynamic_original_image(original),
             'whole exact original ELF and retained carrier interpreter')
        argv = [str(python), '-B', str(tool), 'exec-loader', '--library-root', '/usr/lib64',
                '--namespace', str(origin.parent/'ls-release-namespace'), str(carrier),
                str(original), '--', str(original), '-d', '.']
        need(prior['argv'] == argv, 'whole original launcher argv before sole namespace substitution')
        objects, description = namespace.plan(original, [Path('/usr/lib64')],
            bytes.fromhex(fact(original)['sha256']), bytes.fromhex(fact(interp)['sha256']))
        for item in objects: pin(item['path'], dict(bytes=len(item['bytes']), sha256=hashlib.sha256(item['bytes']).hexdigest()))
        system = dict(original=fact(original), interpreter=fact(interp),
            dependencies=[dict(names=x['names'], **fact(x['path'])) for x in objects])
        need(description == old['namespace_plans']['ls'] and system == old['system_inputs']['ls'],
             'independently rebuilt exact original dependency plan')
        fresh_ns = output/'namespace'; argv[7] = str(fresh_ns)
        state = dict(objects=objects, description=description, carrier=carrier, argv=[str(original), '-d', '.'])
        row = dict(name='ls-release-user-dwarf', argv=argv, environment=PROGRAM_ENV,
                   cwd=str(origin.parent), bounds=subject, capture_limit=16 << 20, expected_exit=0)
        r.update(target=row, original_receipt=fact(origin), original_subject=prior,
                 bridge=fact(bridge), carrier=fact(carrier), compiled_inputs_equal_current=True)
        perf = pin('/usr/bin/perf'); perfinterp = pin(interpreter(perf))
        listed, errors = run('perf-libraries', [perfinterp, '--list', perf], PROGRAM_ENV)
        need(not errors, 'actual observer dependency listing')
        libs = observer_libraries(listed, perfinterp, pin)
        r['observer_libraries'] = {str(p): fact(p) for p in libs}
        imported_sources(pin); stable(); capture = output/'capture'
        if storage is not None:
            storage.reserve(3*PERF[2]+2*TARGET[2], 'target and perf children')
            storage.install()
        out, err, owner = profile(row, capture, cpu, bridge, fact(bridge), perf=str(perf), user_dwarf=True)
        r['diagnostic'] = owner
        need(owner['sampling']['full_exec_exit_envelope'] and owner['sampling']['loss_free'],
             'unchanged complete raw sampling envelope and zero loss')
        namespace_join(state, fresh_ns, binary, r, namespace)
        row['captures'] = {k: dict(file=str(p.relative_to(output)), **fact(binary(p))) for k, p in
                           (('stdout', capture/'target.stdout'), ('stderr', capture/'target.stderr'))}
        symfs = output/'symfs'; copy = symfs/str(bridge).lstrip('/'); copy.parent.mkdir(parents=True)
        copy.write_bytes(bridge.read_bytes()); copy.chmod(0o444); pin(copy, fact(bridge))
        env = dict(owner['perf']['environment'], DEBUGINFOD_CACHE_PATH=str(capture/'cache'))
        text, unwind_err = run('user-dwarf-unwind', script_argv(perf, capture/'perf.data', symfs), env)
        r['unwinder_stderr'] = fact(output/'user-dwarf-unwind.stderr')
        r['attribution'] = attribute(capture, bridge, text, row['pid'])
        details = json.loads((capture/'unwound.json').read_bytes()); bins = {}
        for x in details:
            second = (x['time_ns']-owner['release_ns'])//1_000_000_000
            need(0 <= second < 60, 'actual sample in original wall interval')
            bucket = bins.setdefault(second, collections.Counter()); bucket[x['leaf']] += x['period']
        r['timeline'] = [dict(second=s, period=sum(v.values()), leaf_periods=dict(v)) for s, v in sorted(bins.items())]
        need(sum(x['period'] for x in r['timeline']) == r['attribution']['period'], 'all sampled periods conserved')
        r['target_outcome'] = 'exit_zero_unqualified' if row['exit'] == 0 else 'failed_prefix'
        r['status'] = 'observed_user_dwarf_diagnostic_only'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        if storage is not None:
            try: storage.restore()
            except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        owner_path = output/'capture/owner.json'
        if owner_path.exists(): r['diagnostic'] = json.loads(owner_path.read_bytes())
        try:
            imported_sources(pin); stable(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for p in output.rglob('*'):
                if p.is_file() and not p.is_symlink(): binary(p)
        except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = r.get('diagnostic', {}).get('closed') is True and all(
            c.get('reaped') is True and c.get('timed_out') is False and c.get('error') is None and
            c.get('cleanup_errors') == [] and all(d.get('closed') is True for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases)
        if storage is not None: storage.receipt(r)
        save(output/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], target_exit=r.get('target', {}).get('exit'),
                         receipt=str(output/'receipt.json'))), flush=True)
    return int(r['status'] != 'observed_user_dwarf_diagnostic_only')


if __name__ == '__main__':
    raise SystemExit(main())
