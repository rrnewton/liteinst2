#!/usr/bin/env python3
"""One bounded user-DWARF observation of a retained plain LOOP13 LS failure.

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
    a = ap.parse_args(); root = Path.cwd().resolve()
    sys.path[:0] = [str(root/'evaluation/inprocess'), str(root/'tools/page-entry')]
    from checks import source
    from run import hardware
    from page_selected import fact, interpreter
    from page_selected_process import invoke
    from page_cost_profile import profile, TARGET, PERF
    from persistent_dynamic_profile import observer_libraries
    from persistent_dynamic_profile_read import script_argv, attribute
    from persistent_dynamic import imported_sources
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
    output.mkdir(mode=0o700)
    r = dict(schema=1, profile='loop-effects-program-user-dwarf-diagnostic-v1', status='failed',
        cpu=cpu, hardware=hardware(cpu), argv=[sys.executable, '-B', *sys.argv], source=None,
        compiled_source=None, subject_bounds=subject, observer_bounds=list(PERF), unwinder_bounds=list(PERF),
        commands=[], inputs_unchanged=False, source_unchanged=False, cleanup_complete=False,
        qualification_credit=False, performance_credit=False, successful_target_credit=False,
        original_diagnostic_reclassified=False, error=None, final_errors=[], namespace_aliases={},
        scope='One separately observed LS execution from the retained failed case and plain bridge. User-only 99Hz samples and actual wait4 usage; no terminal counts invented. No kernel stack, complete unwind, kill-cause, timing or qualification inference.')
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
        origin = pin(a.diagnostic_receipt)
        need(pins[str(origin)]['sha256'] == a.diagnostic_sha256 and origin.name == 'receipt.json' and
             origin.parent.parent == root/'target/evaluation/inprocess', 'whole closed original receipt')
        old = json.loads(origin.read_bytes()); r['compiled_source'] = old['source']
        need(old['profile'] == 'loop-effects-program-diagnostic-v1' and old['status'] == 'failed' and
             old['revision'] == old['source']['revision'] and old['source']['tracked_clean'] is True and
             old['source']['head_sources_match'] is True and old['source_unchanged'] is True and
             old['cleanup_complete'] is True and old['final_errors'] == [] and
             old['qualification_credit'] is old['performance_credit'] is old['full_state_credit'] is False and
             old['cpu'] == cpu and old['hardware'] == r['hardware'],
             'closed failed development observation on this exact CPU/hardware; no promotion')
        order = [('ls', 'native'), ('ls', 'release'), ('true', 'native'), ('true', 'release')]
        need([(c['workload'], c['lane']) for c in old['cases']] == order and
             [c['status'] for c in old['cases']] == ['passed', 'failed', 'passed', 'failed'] and
             [c['exit'] for c in old['cases']] == [0, -9, 0, -9], 'literal original four-subject failure')
        for p, v in old['inputs'].items(): pin(p, v)
        for p, v in old['artifacts'].items(): binary(pin(p, v))
        for lexical, actual in old['aliases'].items():
            need(str(Path(lexical).resolve(strict=True)) == actual and
                 (lexical not in aliases or aliases[lexical] == actual), 'original aliases')
            aliases[lexical] = actual
        need(all(os.path.lexists(p) == present for p, present in old['presence'].items()) and
             old['presence']['/etc/ld.so.preload'] is False, 'original loader configuration presence')
        commands = old['commands']
        need(len(commands) == len({c['name'] for c in commands}) and
             [c['name'] for c in commands if c['name'] in ('ls-native','ls-release','true-native','true-release')] ==
             ['ls-native','ls-release','true-native','true-release'], 'all original command identities')
        for c in commands:
            need(type(c['exit']) is int and c['reaped'] is True and c['timed_out'] is False and
                 c['error'] is None and c['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in c['descriptors']) and
                 c['bounds'] == old['bounds'][c['profile']], 'whole original command process closure')
            need(json.loads(pin(origin.parent/(c['name']+'.json')).read_bytes()) == c, 'whole original command record')
            for v in c['captures'].values():
                need(Path(v['file']).name == v['file'], 'local original capture')
                pin(origin.parent/v['file'], v)
        prior, = [c for c in commands if c['name'] == 'ls-release']
        need(prior['exit'] == -9 and prior['bounds'] == subject and prior['capture_limit'] == 16 << 20 and
             prior['expected_exit'] == 0 and prior['environment'] == PROGRAM_ENV and
             all(v['bytes'] == 0 for v in prior['captures'].values()), 'exact failed plain LS tuple, without terminal')
        build = old['release_builds']['ls']['release_build']
        need(build['status'] == 'passed' and build['profile'] == 'persistent-loop-effects-release-v1' and
             build['capture'] is False and 'counter_schema' not in build and 'capture_config' not in build and
             'counters' not in build and 'retained_counters' not in build and
             build['active_domain']['differential'] is False and build['archive'] == old['archive'] and
             build['persistent_binding']['mode'] == 'release', 'actual retained uninstrumented maintained bridge')
        bridge = pin(build['argv'][-1], build['bridge'])
        link, = [c for c in commands if c['name'] == 'ls-persistent-group-release-link']
        need(link['argv'] == build['argv'] and link['exit'] == 0 and
             str(bridge) in old['artifacts'], 'actual completed link owns the retained bridge')
        original = pin('/bin/ls', old['system_inputs']['ls']['original'])
        interp = pin(interpreter(original), old['system_inputs']['ls']['interpreter'])
        carrier = pin(origin.parent/'ls-carrier', old['carriers']['ls'])
        tool = pin(root/'tools/page-entry/carrier.py'); python = pin(sys.executable)
        need(interpreter(carrier) == bridge and build['persistent_binding']['original']['image'] == fact(original),
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
        save(output/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], target_exit=r.get('target', {}).get('exit'),
                         receipt=str(output/'receipt.json'))), flush=True)
    return int(r['status'] != 'observed_user_dwarf_diagnostic_only')


if __name__ == '__main__':
    raise SystemExit(main())
