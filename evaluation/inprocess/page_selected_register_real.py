#!/usr/bin/env python3
"""Bounded real-program register-run experiment; failed applications remain failed."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys

sys.dont_write_bytecode = True
import page_selected_generic as base
from page_selected_generic_build import Build
from page_selected_process import invoke
import page_selected_register_connected_build as link
import page_selected_register_connected_compare as finite
import page_selected_repeat_compare as repetition

ROOT, HERE, ENV = base.ROOT, base.HERE, dict(base.ENV, LD_BIND_NOW='1')
PROFILES = dict(base.PROFILES, program=[30, 512 << 20, 16 << 20, 60])
need, fact, save, digest = base.need, base.fact, base.save, base.digest
ZERO = ('status', 'failure_code', 'detail_abs', 'detail_negative')


def reports(data):
    lines = data.splitlines()
    need(len(lines) in (2, 3) and all(len(x)+1 <= 4096 for x in lines) and
         lines[0].startswith(b'LI2_LOADER ') and lines[-1].startswith(b'LI2_RUN '), 'bounded explicit reports')
    decode = lambda b: json.loads(b, object_pairs_hook=finite.generic.unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite report')))
    loader = decode(lines[0][11:])
    need(type(loader) is dict and set(loader) == finite.generic.KEYS and
         loader['scope'] == 'partial_selected_register_run', 'actual opt-in loader schema')
    projected = dict(loader, scope=finite.generic.SCOPE)
    projected_bytes = b'LI2_LOADER '+json.dumps(projected).encode()+b'\n'
    checked, repeat = repetition.parse(projected_bytes+(lines[1]+b'\n' if len(lines) == 3 else b''))
    need(checked == projected, 'unchanged loader and optional REP parser')
    run = decode(lines[-1][8:])
    need(type(run) is dict and run.get('cache_present') in (0, 1) and
         run.get('publication_present') in (0, 1), 'reported optional owner presence')
    arrays = {k: n for k, n in finite.ARRAYS.items() if k not in ('cache', 'initialization', 'attempt', 'publication')}
    if run['cache_present']:
        arrays.update({k: finite.ARRAYS[k] for k in ('cache', 'initialization', 'attempt')})
    if run['publication_present']:
        arrays['publication'] = finite.ARRAYS['publication']
    need(set(run) == finite.SCALARS | set(arrays), 'exact present-owner RUN schema')
    for k in finite.SCALARS:
        need(type(run[k]) is int and 0 <= run[k] < 1 << 64, 'unsigned RUN scalar '+k)
    for k, n in arrays.items():
        need(type(run[k]) is list and len(run[k]) == n and all(type(x) is int and 0 <= x < 1 << 64 for x in run[k]),
             'exact unsigned RUN array '+k)
    need(run['version'] == 1 and all(run[k] == loader[k] for k in ZERO) and
         run['route'] == loader['step_route'], 'same actual terminal outcome')
    return loader, repeat, run


def completed(loader, repeat, run):
    """General last-owner closure; finite loop count predicates are unchanged elsewhere."""
    need(all(loader[k] == run[k] == 0 for k in ZERO) and run['pending'] == run['route'] == 0 and
         loader['source_syscalls'] == loader['syscalls'] == loader['forwarded'], 'actual successful whole process')
    finite.generic.check_completed_owner(loader)
    if repeat is not None:
        repetition.completed(repeat)
        need(repeat['route'] == repeat['pending'] == 0, 'no pending REP owner')
    need(run['cache_present'] == 1 and run['completed_runs'] > 0, 'actual cache use required for cache completion credit')
    c = run['cache']; slots, attempts, hits, full = c[4], c[6], c[7], c[8]
    need(c[:4] == [2, 0, 0, 0] and 1 <= slots == c[5] <= 64 and c[9:] == [0]*5 and
         attempts == slots+hits+full and run['completed_runs'] == slots+hits and
         2*run['completed_runs'] <= run['copied_instructions'] <= 14*run['completed_runs'],
         'complete actual cache/history accounting')
    i = run['initialization']
    need(i[:7] == [1]*7 and i[7] > 0 and i[7] % 4096 == 0 and i[8] == 64*4096 and i[9] > 0 and
         i[10] == i[7] and i[11:16] == [0]*5 and i[16:] == [1, 1, 64], 'real complete fixed arena')
    a = run['attempt']
    need(a[0] == attempts and a[1] > 0 and a[2:5] == [1]*3 and a[5] in (0, 1) and a[6] in (0, 1) and
         a[5]+a[6] <= 1 and a[7:11] == [1, 0, 0, 0] and a[11] in (1, 2) and a[13:] == [1, 1, 0],
         'exact last held source/plan/attempt closure')
    if a[6]:
        need(full > 0 and slots == 64 and a[12] == 64 and run['publication_present'] == 0,
             'only actual full capacity can leave publication absent after a complete attempt')
    else:
        need(run['publication_present'] == 1 and 0 <= a[12] < slots and
             (hits > 0 if a[5] else a[12] == slots-1), 'actual hit or final new publication')
        p = run['publication']
        need(p[:4] == [2, 0, 0, 0] and p[4:6] == [1, a[12]+1] and 0 < p[6] <= a[1] and
             (a[5] or p[6] == a[1]) and p[7] == i[7]+a[12]*4096 and p[8] == p[10] == 4096 and
             16 <= p[9] <= 29 and p[11:16] == [1]*5 and p[16:27] == [0]*11 and
             p[27:] == [1, 1, 1, 1, 0, 0], 'complete exact W^X/sync/full-page publication prefix')
    h = run['last_complete']
    need(h[:6] == [1, 1, 0, 0, 0, 7] and 0 < h[6] < h[7] <= h[6]+15 and 2 <= h[8] <= 14 and
         h[9:17] == [1]*8 and h[17:19] == [0, 1] and 0 < h[19] <= a[1] and
         run['active'] == [0]*10 and run['interrupted'] == [0]*9, 'actual last NX guard/reset/query/release; no active failure')
    need(h[19] < a[1] if a[6] else h[19] == a[1], 'exact last completed attempt or earlier owner before full miss')
    b = run['private_brk']
    if not b[0]:
        need(b == [0]*10, 'no invented private brk observation')
    else:
        need(b[:2] == [1, 1] and b[2] > 0 and b[3] == b[6] > 0 and b[7:] == [0, 0, 0],
             'actual completed protected brk preflight')
        need(b[4:6] == ([(b[2]+4095)&~4095, (b[3]+4095)&~4095] if b[2] < b[3] else [0, 0]),
             'exact observed shrink interval or no shrink')


def resolved_libraries(data, expected, interpreter, pin):
    """Authenticate the native loader's actual listing against the sealed plan."""
    actual, names, vdso = set(), set(), 0
    for line in data.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line):
            vdso += 1
            continue
        m = re.fullmatch(r'\s*(\S+)(?: => (\/\S+))? \(0x[0-9a-f]+\)', line)
        need(m is not None, 'closed actual loader dependency listing')
        name, path = m.group(1), m.group(2) or m.group(1)
        need(name not in names and path.startswith('/'), 'unique resolved native dependency')
        names.add(name)
        path = pin(path)
        need(path in expected and ((Path(name).resolve() == interpreter and path == interpreter)
             if name.startswith('/') else name in expected[path]), 'actual native/namespace library identity')
        need(path not in actual, 'one actual listing per resolved object')
        actual.add(path)
    need(vdso == 1 and actual == set(expected), 'complete native loader closure including interpreter')


def publish(path, r, private):
    fields = ('status', 'failure_code', 'detail_abs', 'detail_negative', 'nx_faults', 'main_faults',
        'interpreter_faults', 'dependency_faults', 'selected_steps', 'generic_tf_attempts', 'generic_tf_steps',
        'cpuid', 'rdtsc', 'rdtscp', 'rdrand', 'rdseed', 'rdpid', 'source_syscalls', 'syscalls', 'forwarded',
        'admissions', 'sync_core', 'tf_code', 'tf_error', 'tf_phase', 'tf_length', 'step_route')
    cases = []
    for c in r['cases']:
        loader, run = c.get('loader', {}), c.get('register', {})
        cases.append(dict(name=c['name'], status=c['status'], environment=c['environment'],
            native_exit=c.get('native_exit'), gated_exit=c.get('gated_exit'), stdout=c.get('stdout'),
            counters={k: loader[k] for k in fields if k in loader},
            register={k: run[k] for k in ('completed_runs', 'copied_instructions', 'plan_misses') if k in run},
            cache_counts=run.get('cache', [])[4:9], last_opcode=c.get('last_opcode'),
            repeat={k: c['repeat'][k] for k in ('attempts', 'completed', 'traces', 'queries')} if c.get('repeat') else None,
            whole_process_ns=c.get('whole_process_ns'), first_touch_ns=None, steady_state_ns=None,
            namespace=c.get('namespace'), actual_launch_environment_sha256=c.get('launch_environment_sha256')))
    build = r.get('build', {})
    result = {k: r.get(k) for k in ('schema', 'profile', 'scope', 'status', 'expected_revision', 'started_utc',
        'source', 'source_unchanged', 'cpu', 'hardware', 'bounds', 'reproduce')}
    result.update(cases=cases, required_cases=4, completed_cases=sum(c['status'] == 'completed' for c in cases),
        command_count=len(r['commands']), command_rows_sha256=digest(r['commands']),
        case_rows_sha256=digest(r['cases']), private_receipt=fact(private/'receipt.json'),
        input_manifest_sha256=digest(r['inputs_before']), artifact_manifest_sha256=digest(r['artifacts_before']),
        build_status=build.get('status'), register_build_status=r.get('register_build', {}).get('status'),
        tool_versions=build.get('numeric_versions'), tool_bindings_sha256=digest(build.get('tools', {})),
        build_evidence_sha256=digest(build), register_build_sha256=digest(r.get('register_build')),
        final_error_count=len(r['final_errors']), failure_type=r['error'].split(':', 1)[0] if r['error'] else None,
        timing_scope='One native then gated fresh exec per workload, after dependency preflight. Gated time includes Python namespace copy/sealing and exec. Build time separate; no cold-filesystem, steady-cache or instrumentation-only ratio.',
        command_recipe=dict(build=['sh', 'tools/page-entry/selected/build.sh'],
            opt_in='Exact committed C link recipe with the same freshly retained archive',
            program_bounds=PROFILES['program'], native=['/bin/true', '/bin/ls -d .'],
            gated='carrier.py exec-loader, with --disable-rseq only for explicitly named rseq-disabled workloads',
            environment='LD_BIND_NOW=1 in both lanes. Only rseq-disabled workloads add GLIBC_TUNABLES=glibc.pthread.rseq=0. Actual sealed namespace and dependency FDs remain explicit identity differences.'))
    text = json.dumps(result, sort_keys=True, indent=2, allow_nan=False)+'\n'
    need(not any(x and len(x) > 1 and x in text for x in
         (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'private publication data')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:
        f.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1 and
         re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact source, assertions and reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp+'-page-selected-register-real-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True, exist_ok=False)
    public = HERE/'results'/(stem+'.json')
    need(not public.exists(), 'unique public receipt')
    pins, binaries = {}, {}
    r = dict(schema=1, profile='page-selected-register-real-v1', status='failed',
        scope='Four named real-program/environment pairs with the opt-in cache; no full B2/B3, transparent namespace or steady-state performance claim.',
        expected_revision=args.expect_revision, started_utc=stamp, source=None, source_unchanged=False,
        cpu=cpu, bounds=PROFILES, commands=[], cases=[], error=None, final_errors=[],
        reproduce=['python3', 'evaluation/inprocess/page_selected_register_real.py', '--expect-revision', args.expect_revision])
    def pin(path):
        p = Path(path).resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'input changed')
        pins[str(p)] = value
        return p
    def artifact(path):
        p = Path(path)
        return dict(fact(p), mode=p.stat().st_mode & 0o777)
    def binary(path):
        p = Path(path).resolve(strict=True); value = artifact(p)
        need(str(p) not in binaries or binaries[str(p)] == value, 'artifact changed')
        binaries[str(p)] = value
        return p
    stage = 'build'
    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()) and all(artifact(p) == v for p, v in binaries.items()),
             'input/artifact changed before command')
        row = dict(name=label, stage=stage, profile=profile, argv=list(map(str, argv)), bounds=PROFILES[profile],
            capture_limit=65536 if profile in ('native', 'program') else 4 << 20,
            expected_exit=expected, environment=dict(ENV if env is None else env))
        r['commands'].append(row)
        out, err = invoke(row, private, cpu)
        need(type(row['exit']) is int and (expected is None or row['exit'] == expected), 'actual process outcome')
        return row, out, err
    builder = Build(r, private, pin, binary, run)
    try:
        r['source'] = base.source(); need(r['source']['revision'] == args.expect_revision, 'exact committed source')
        r['hardware'] = base.hardware(cpu)
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, out, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], profile='metadata')
        need(not err, 'source enumeration stderr')
        for p in out.split(b'\0'):
            if p and not os.fsdecode(p).startswith('evaluation/inprocess/results/'):
                pin(ROOT/os.fsdecode(p))
        spec = importlib.util.spec_from_file_location('li2_real_namespace', pin(ROOT/'tools/page-entry/namespace.py'))
        namespace_api = importlib.util.module_from_spec(spec); spec.loader.exec_module(namespace_api)
        for module in tuple(sys.modules.values()):
            p = getattr(module, '__file__', None)
            if p and Path(p).resolve().is_relative_to(ROOT):
                pin(p)
        built = builder.prepare()
        bridge = link.build(builder, built, ROOT, private, pin, binary, run, r)
        python = builder.tools['python']
        stage = 'program'
        for disabled in (False, True):
            for program_name, extra, expected_stdout in (('true', [], b''), ('ls', ['-d', '.'], b'.\n')):
                name = program_name+('-rseq-disabled' if disabled else '-default')
                env = dict(ENV, **({'GLIBC_TUNABLES': 'glibc.pthread.rseq=0'} if disabled else {}))
                c = dict(name=name, status='failed', environment=env)
                r['cases'].append(c)
                original = pin('/bin/'+program_name); interp = pin(base.interpreter(original))
                objects, description = namespace_api.plan(original, [Path('/usr/lib64')],
                    bytes.fromhex(fact(original)['sha256']), bytes.fromhex(fact(interp)['sha256']))
                expected = {interp: set()}
                c['planned_dependencies'] = []
                for item in objects:
                    p = pin(item['path']); expected.setdefault(p, set()).update(item['names'])
                    need(fact(p)['sha256'] == base.hashlib.sha256(item['bytes']).hexdigest(), 'actual planned dependency bytes')
                    c['planned_dependencies'].append(dict(source=str(p), names=item['names'], needed=item['info']['needed'], **fact(p)))
                _, listing, err = run('libraries-'+name, [interp, '--list', original], profile='metadata', env=env)
                need(not err, 'native loader listing stderr')
                resolved_libraries(listing, expected, interp, pin)
                carrier = private/('carrier-'+name)
                run('make-'+name, [python, ROOT/'tools/page-entry/carrier.py', 'make', original, bridge, carrier])
                binary(carrier); need(base.interpreter(carrier) == bridge, 'actual opt-in interpreter')
                native, stdout, err = run('native-'+name, [original, *extra], profile='program', env=env)
                c['native_exit'] = native['exit']
                need(stdout == expected_stdout and not err, 'exact genuine native baseline')
                directory = private/('namespace-'+name)
                argv = [python, ROOT/'tools/page-entry/carrier.py', 'exec-loader', '--library-root', '/usr/lib64', '--namespace', directory]
                if disabled:
                    argv.append('--disable-rseq')
                gated, actual, stderr = run('gated-'+name, [*argv, carrier, original, '--', original, *extra],
                                             expected=None, profile='program', env=env)
                c.update(gated_exit=gated['exit'], stdout=dict(bytes=len(actual), sha256=base.hashlib.sha256(actual).hexdigest()))
                ns = json.loads(binary(directory/'namespace.json').read_bytes())
                launch = json.loads(binary(directory/'launch.json').read_bytes())
                need(len(ns['objects']) == len(objects) and ns['original_sha256'] == fact(original)['sha256'] and
                     ns['interpreter_sha256'] == fact(interp)['sha256'], 'exact actual namespace roots')
                wanted = {str(x['path']): x for x in objects}
                need({x['source'] for x in ns['objects']} == set(wanted), 'complete actual sealed object set')
                for item in ns['objects']:
                    before = wanted[item['source']]
                    need(item['seals'] == 15 and fact(pin(item['source']))['sha256'] == item['sha256'] and
                         item['names'] == before['names'] and item['needed'] == before['info']['needed'], 'sealed dependency identity')
                target_env = {k: env[k] for k in ('PATH', 'LANG', 'LC_ALL', 'TZ', 'LD_BIND_NOW')}
                target_env.update(LD_LIBRARY_PATH=str(directory), LI2_DEPENDENCY_FDS=','.join(str(x) for x in launch['dependency_fds']))
                if disabled:
                    target_env['GLIBC_TUNABLES'] = env['GLIBC_TUNABLES']
                need(launch['environment'] == target_env and launch['argv'] == list(map(str, [original, *extra])) and
                     launch['carrier_sha256'] == fact(carrier)['sha256'] and
                     launch['dependency_fds'] == [x['fd'] for x in ns['objects']], 'actual target environment/argv/carrier/FD join')
                c.update(namespace={n: fact(directory/n) for n in ('namespace.json', 'launch.json')},
                         launch_environment_sha256=digest(target_env))
                loader, repeat, cache = reports(stderr)
                c.update(loader=loader, repeat=repeat, register=cache)
                need(gated['exit'] == loader['status'], 'actual process exit equals report')
                if loader['tf_length']:
                    packed = struct.pack('<QQ', loader['tf_bytes_lo'], loader['tf_bytes_hi'])
                    need(1 <= loader['tf_length'] <= 15 and packed[loader['tf_length']:] == bytes(16-loader['tf_length']), 'retained opcode extent')
                    c['last_opcode'] = packed[:loader['tf_length']].hex()
                if gated['exit'] == 0:
                    need(actual == stdout == expected_stdout, 'exact completed application output')
                    completed(loader, repeat, cache)
                    c.update(status='completed', whole_process_ns=dict(native=native['duration_ns'], gated=gated['duration_ns']))
                # Nonzero exits stay failed. Reports/captures remain actual;
                # they are not an expected-refusal pass or timing sample.
        need(len(r['cases']) == 4, 'all default and separately named tuned workloads attempted')
        if all(c['status'] == 'completed' for c in r['cases']):
            r['status'] = 'passed_whole_program_cohort'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        try:
            r['final_errors'] += builder.finish()
        except BaseException as exc:
            r['final_errors'].append('build finalization: '+repr(exc))
        try:
            if (private/'bridge-register-run.so').is_file():
                binary(private/'bridge-register-run.so')
        except BaseException as exc:
            r['final_errors'].append('opt-in retention: '+repr(exc))
        r['inputs_before'], r['artifacts_before'] = pins, binaries
        for name, before, observe in (('inputs_after', pins, fact), ('artifacts_after', binaries, artifact)):
            after = r[name] = {}
            for p, value in before.items():
                try:
                    after[p] = observe(p); need(after[p] == value, 'final exact byte/mode identity')
                except BaseException as exc:
                    r['final_errors'].append(p+': '+repr(exc))
        try:
            r['source_unchanged'] = base.source() == r['source']; need(r['source_unchanged'], 'source closure')
        except BaseException as exc:
            r['final_errors'].append('source closure: '+repr(exc))
        if r['error'] or r['final_errors'] or r['build']['status'] != 'passed' or r.get('register_build', {}).get('status') != 'passed':
            r['status'] = 'failed'
        save(private/'receipt.json', r); publish(public, r, private)
    print(json.dumps(dict(status=r['status'], attempted=len(r['cases']), receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status'] == 'passed_whole_program_cohort' else 1


if __name__ == '__main__':
    raise SystemExit(main())
