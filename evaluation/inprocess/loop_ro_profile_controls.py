#!/usr/bin/env python3
"""Three positive and fifty refusal controls for the actual LOOP RO headers.

Run from the clean repository root on one reserved CPU with Python 3.12 -B.
The supplied closed positive-driver receipt provides two successful real builds,
their compiler, exact recipe flags and generated headers. Its later subjects may
have failed; no native, owner, archive-rebuild or qualification credit is reused.
Each fresh preprocessor has 5 CPU / 15 wall seconds, 512 MiB AS and 16 MiB output.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import types

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import fact, need, save
from page_selected_process import invoke
from page_selected_register_time_build import recipe, expand

SELECTED = ROOT/'tools/page-entry/selected'
LIMITS = [5, 512 << 20, 16 << 20, 15]
BUILD_LIMITS = {'release_build': [30, 512 << 20, 16 << 20, 60],
                'metadata': [30, 512 << 20, 64 << 20, 60],
                'inspect': [10, 256 << 20, 4 << 20, 20]}
REQUIRED = ('LI2_LOOP_RO_CERTIFICATE', 'LI2_SEALED_BYTE_CERTIFICATE',
    'LI2_PERSISTENT_SEALED_GENERATION', 'LI2_PERSISTENT_LOOP_EFFECTS',
    'LI2_PERSISTENT_LOOP_RUNTIME', 'LI2_PERSISTENT_RETAINED_TWO',
    'LI2_PERSISTENT_ACTIVE_DOMAIN', 'LI2_INITIAL_CODE_PROTECTION',
    'LI2_RSEQ_INACTIVE', 'LI2_PG_LOOP_RO_BINDING_VERSION')
FORBIDDEN = ('LI2_RESIDENT_SOURCE_LEASE', 'LI2_RESIDENT_THREE',
    'LI2_SEALED_BYTE_CERTIFICATE_OBSERVE', 'LI2_PERSISTENT_LOOP_CAPTURE',
    'LI2_PERSISTENT_LOOP_EFFECTS_CAPTURE', 'LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE',
    'LI2_PERSISTENT_LOOP_EFFECTS_LIFECYCLE_CAPTURE')
# Each identity is the actual source header and its literal #error message.
ERRORS = {
    'required': ('loop_ro_profile.h', 'LOOP RO byte certificates require the exact serialized two-member owner'),
    'forbidden': ('loop_ro_profile.h', 'separate RO mirror layout: no old source-lease or capture-schema cast'),
    'binding': ('loop_ro_profile.h', 'LOOP RO certificate requires its separately bound complete source policy'),
    'implicit': ('persistent_loop_runtime.h', 'loop runtime has a distinct capture and no implicit certificate/generation composition'),
    'loop': ('persistent_loop_runtime.h', 'loop runtime explicitly composes policy12 with exact policy11 fallback'),
    'effects': ('persistent_loop_runtime.h', 'explicit byte-store/register-multiply LOOP composition'),
    'effects_plan': ('persistent_loop_effects_plan.h', 'policy13 and its separate decoder/byte-guard APIs must be explicitly selected'),
    'pf': ('persistent_fused_runtime.h', 'PF runtime selects one exact version11 observed-root two-active owner'),
    'pf_forbidden': ('persistent_fused_runtime.h', 'PF NONE/MOV/direct runtime does not borrow another instruction or resident policy'),
    'fused': ('persistent_fused_plan.h', 'fused policy requires its explicit direct-directory and MOV-guard profile'),
    'direct': ('linked_direct_dispatch.h', 'direct frontiers require their distinct two-active cross-pair profile'),
    'directory': ('linked_jmp_domain.h', 'distinct active-domain cold code and directory required'),
    'capture_pair': ('persistent_loop_runtime.h', 'loop capture requires both its own selector and the original callback lifecycle'),
    'capture': ('persistent_loop_runtime.h', 'exact separate policy14 capture selection'),
}
H = lambda raw: hashlib.sha256(raw).hexdigest()


def digest(value):
    return H(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def roster():
    rows = [dict(name='ro-release', mode='release', changes=[], errors=[]),
            dict(name='ro-differential', mode='differential', changes=[], errors=[]),
            dict(name='old-loop13', mode='release', changes=[(n, None) for n in
                ('LI2_LOOP_RO_CERTIFICATE', 'LI2_SEALED_BYTE_CERTIFICATE',
                 'LI2_PERSISTENT_SEALED_GENERATION', 'LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL')], errors=[])]
    for macro in REQUIRED:
        for value in (None, 0, 2):
            errors = ['binding' if macro == REQUIRED[-1] else 'required']
            if macro == 'LI2_LOOP_RO_CERTIFICATE' and value is None: errors = ['implicit']
            if macro == 'LI2_PERSISTENT_LOOP_RUNTIME': errors += ['loop']
            if macro == 'LI2_PERSISTENT_RETAINED_TWO': errors += ['pf']
            if macro == 'LI2_PERSISTENT_ACTIVE_DOMAIN':
                errors += ['direct', 'fused', 'pf']
                if value is not None: errors += ['directory']
            if macro == 'LI2_PERSISTENT_LOOP_EFFECTS' and value is not None:
                errors += ['effects', 'effects_plan']
            rows.append(dict(name=macro.lower()+'-'+('absent' if value is None else str(value)),
                             mode='release', changes=[(macro, value)], errors=errors))
    for macro in FORBIDDEN:
        for value in (0, 1):
            errors = ['forbidden']
            if macro == 'LI2_RESIDENT_THREE': errors += ['pf_forbidden']
            if macro == 'LI2_PERSISTENT_LOOP_CAPTURE': errors += ['capture_pair', 'capture']
            rows.append(dict(name=macro.lower()+'-'+str(value), mode='release',
                             changes=[(macro, value)], errors=errors))
    for macro in ('LI2_PERSISTENT_FUSED_CAPTURE', 'LI2_RESIDENT_STABLE_GENERATION'):
        for value in (0, 1):
            rows.append(dict(name=macro.lower()+'-'+str(value), mode='release',
                             changes=[(macro, value)], errors=['implicit']))
    for value in (0, 1):
        rows.append(dict(name='implicit-sbc-'+str(value), mode='release',
            changes=[('LI2_LOOP_RO_CERTIFICATE', None), ('LI2_SEALED_BYTE_CERTIFICATE', value)],
            errors=['implicit']))
    need(len(rows) == len({r['name'] for r in rows}) == 53 and
         sum(not r['errors'] for r in rows) == 3, 'fixed three positive and fifty negative controls')
    return rows


def complete(row, bounds, expected):
    need(row['bounds'] == bounds and row['capture_limit'] == 16 << 20 and
         row['expected_exit'] == row['exit'] == expected and row['timed_out'] is False and
         row['error'] is None and row['reaped'] is True and row['cleanup_errors'] == [] and
         type(row['descriptors']) is list and all(d['closed'] is True for d in row['descriptors']),
         'exact child bounds, outcome and descriptor/process closure: '+row['name'])


def imported_sources(pin):
    pending = [m for m in sys.modules.values() if isinstance(m, types.ModuleType)]
    pending.extend(v for v in globals().values() if isinstance(v, types.ModuleType))
    seen = set()
    while pending:
        module = pending.pop()
        if id(module) in seen: continue
        seen.add(id(module)); path = getattr(module, '__file__', None)
        if path and Path(path).is_file(): pin(Path(path))
        pending.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))


def retained_builds(path, sha, record, pin):
    """Authenticate the closed build subset; do not replay any subject or command."""
    path = pin(path)
    need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess'
         and fact(path)['sha256'] == sha, 'supplied whole closed build receipt')
    old = json.loads(path.read_bytes()); directory = path.parent
    need(old['schema'] == 1 and old['profile'] == 'loop-ro-native-positive-v1' and
         old['revision'] == old['source']['revision'] and re.fullmatch('[0-9a-f]{40}', old['revision']) and
         old['source']['tracked_clean'] is True and old['source']['head_sources_match'] is True and
         all(old[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')) and
         old['final_errors'] == [], 'closed exact-source producer; later subject outcome remains literal')
    rows = {row['name']: row for row in old['commands']}
    need(len(rows) == len(old['commands']), 'unique retained command rows')

    def retained(raw):
        p = pin(raw); key = str(p); value = fact(p)
        need(key in old['inputs'] or key in old['artifacts'], 'producer owns each reused file')
        if key in old['inputs']: need(value == old['inputs'][key], 'whole recorded input identity')
        if key in old['artifacts']:
            need(dict(value, mode=p.stat().st_mode & 0o777) == old['artifacts'][key],
                 'whole recorded artifact identity and mode')
        return p

    def closed(name, profile):
        row = rows[name]
        need(row['profile'] == profile, 'original build command profile')
        complete(row, BUILD_LIMITS[profile], 0)
        need(json.loads(retained(directory/(name+'.json')).read_bytes()) == row,
             'whole actual retained command record')
        streams = {}
        need(set(row['captures']) == {'stdout', 'stderr'}, 'build command has exactly two captures')
        for stream, value in row['captures'].items():
            p = retained(directory/value['file'])
            need(p.parent == directory and p.name == name+'.'+stream and
                 fact(p) == {k: value[k] for k in ('bytes', 'sha256')} and value['bytes'] <= 16 << 20,
                 'exact complete bounded build capture')
            streams[stream] = p.read_bytes()
        return row, streams

    result = {}
    for mode in ('release', 'differential'):
        state = old['builds'][mode]; binding = state['binding']
        need(state['status'] == 'compiled_diagnostic_only' and binding['mode'] == mode and
             binding['profile'] == 'persistent-loop-ro-certificate-'+mode+'-v1' and
             binding['capture_version'] is None, 'separate successfully compiled RO build')
        build, captures = closed(mode+'-build', 'release_build')
        need(captures == {'stdout': b'', 'stderr': b''} and len(build['argv']) == 6 and
             build['argv'][-1] == mode, 'actual successful recipe without diagnostics')
        shell, script, archive, original, output, _ = build['argv']
        script = retained(script); output = Path(output)
        need(script == SELECTED/'build-persistent-loop-ro-certificate.sh' and
             output == directory/(mode+'-build/build') and state['recipe'] == fact(script),
             'actual source-owned recipe and generated directory')
        retained(shell); archive = retained(archive); original = retained(original)
        need(fact(archive) == binding['archive'] and fact(original) == binding['original']['image'],
             'actual retained archive/image identity, no archive rebuilt here')
        env = build['environment']; compiler = retained(env['LI2_CC'])
        need(Path(sys.executable).resolve() == retained(env['LI2_PYTHON']) and
             env['PATH'] == '/usr/bin:/bin' and env['LC_ALL'] == env['LANG'] == 'C' and
             not set(env) & {'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'GCC_EXEC_PREFIX',
                             'COMPILER_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH'}, 'actual tools and closed compiler environment')
        cc1 = [Path(p) for p in old['inputs'] if Path(p).name == 'cc1']
        need(len(cc1) == 1, 'one actual compiler frontend'); retained(cc1[0])
        commands = recipe(script, '"$cc_bin"')
        need(len(commands) == 1, 'one literal actual compiler recipe')
        argv = expand(commands[0], {'$cc_bin': compiler, '$selected_dir': SELECTED,
            '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
        need(argv == state['argv'] and argv[-2:] == ['-o', str(output/'bridge-persistent-loop-ro-certificate.so')],
             'whole compiler argv equals actual current recipe expansion')
        manifest = retained(output/'persistent_loop_ro_certificate_binding.json')
        need(fact(manifest) == state['manifest'] and json.loads(manifest.read_bytes()) == binding and
             digest(dict(sources=binding['sources'], original=binding['original'], mode=mode)) == binding['policy_sha256'],
             'whole manifest and original source/image/mode digest')
        values = binding['sources']
        need(len(values) == len({v['path'] for v in values}) and
             {'loop_ro_profile.h', 'persistent_loop_runtime.h', 'persistent_loop_ro_certificate_binding.py'} <=
             {v['path'] for v in values}, 'unique source binding includes actual guard producers')
        for value in values:
            p = retained(SELECTED/value['path'])
            need((p.is_relative_to(SELECTED) or
                  (value['path'] == '../bridge.c' and p == SELECTED.parent/'bridge.c') or
                  (value['path'] in ('../../../crates/liteinst-x86/Cargo.toml',
                                     '../../../crates/liteinst-x86/src/lib.rs') and
                   p == ROOT/'crates/liteinst-x86'/value['path'].split('liteinst-x86/', 1)[1])) and
                 fact(p) == {k: value[k] for k in ('bytes', 'sha256')},
                 'each compiled bound source still equals current source')
        need(set(binding['headers']) == {'linked_epoch_config.h', 'persistent_group_config.h',
                                        'loop_ro_certificate_config.h'}, 'exact three generated headers')
        for name, value in binding['headers'].items():
            need(fact(retained(output/name)) == value, 'whole actual generated header')
        config = ('#ifndef LI2_LOOP_RO_CERTIFICATE_CONFIG_H\n#define LI2_LOOP_RO_CERTIFICATE_CONFIG_H\n'
            '#define LI2_LOOP_RO_CERTIFICATE 1\n#define LI2_SEALED_BYTE_CERTIFICATE 1\n'
            '#define LI2_PERSISTENT_SEALED_GENERATION 1\n'+
            ('#define LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL 1\n' if mode == 'differential' else '')+'#endif\n').encode()
        need((output/'loop_ro_certificate_config.h').read_bytes() == config and
             (output/'persistent_group_config.h').read_bytes().count(b'#define LI2_PG_LOOP_RO_BINDING_VERSION 1\n') == 1,
             'actual certificate mode and binding macro')
        units = [x for x in argv if x.endswith(('.c', '.S'))]
        need(units and argv.count(str(archive)) == 1, 'actual linked source units and archive')
        flags = [x for x in argv[1:-2] if x not in units and x != str(archive) and not x.startswith('-Wl,')]
        row, captures = closed(mode+'-headers', 'metadata')
        need(row['environment'] == env and row['argv'] == [str(compiler), *flags, '-M', '-MT', 'li2_timing', *units]
             and captures['stderr'] == b'', 'exact actual conditional-header command')
        rules = captures['stdout'].decode().replace('\\\n', ' ').splitlines()
        need(len(rules) == len(units) and all(x.startswith('li2_timing: ') for x in rules),
             'one complete actual dependency rule per translation unit')
        actual = {}
        for rule in rules:
            for token in shlex.split(rule.split(':', 1)[1]):
                p = retained(Path(token).absolute()); actual[str(p)] = fact(p)
        need(actual == state['headers'] and set(units) <= set(actual), 'whole compiler-observed dependency closure')
        for value in values:
            if value['path'].endswith(('.c', '.h', '.inc')):
                need(actual[str((SELECTED/value['path']).resolve())] == {k: value[k] for k in ('bytes', 'sha256')},
                     'every bound C input was actually compiled')
        for name, value in binding['headers'].items():
            need(actual[str(output/name)] == value, 'actual compiler consumed each bound generated header')
        bridge = retained(argv[-1]); need(fact(bridge) == state['bridge'], 'whole resulting bridge')
        for suffix, options in (('undefined', ['-u']), ('symbols', ['-S', '--defined-only'])):
            row, captures = closed(mode+'-'+suffix, 'inspect')
            nm = retained(row['argv'][0])
            need(row['environment'] == env and row['argv'] == [str(nm), *options, str(bridge)] and
                 captures['stderr'] == b'' and (bool(captures['stdout']) if suffix == 'symbols' else captures['stdout'] == b''),
                 'closed actual ELF symbol/import inspection')
        result[mode] = dict(compiler=str(compiler), flags=flags, environment=env,
                           headers=binding['headers'], policy_sha256=binding['policy_sha256'])
    record['retained_build'] = dict(file=str(path), **fact(path), revision=old['revision'],
        source=old['source'], status=old['status'], error=old['error'], cpu=old['cpu'],
        build_modes=['release', 'differential'], compiled_sources_equal_current=True,
        subjects_replayed=0, archive_rebuilt=False, qualification_credit=False)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expect-revision', required=True)
    p.add_argument('--build-receipt', type=Path, required=True)
    p.add_argument('--build-receipt-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', a.build_receipt_sha256), 'exact Python/assertions/revision/receipt digest')
    cpu, = os.sched_getaffinity(0)
    out = a.output.resolve(); need(out.parent == ROOT/'target/evaluation/inprocess', 'fresh fixed output parent')
    out.mkdir(exist_ok=False)
    r = dict(schema=1, profile='loop-ro-profile-controls-v1', status='failed', revision=a.expect_revision,
        cpu=cpu, hardware=hardware(cpu), argv=[sys.executable, '-B', str(Path(__file__).resolve()), *sys.argv[1:]],
        bounds=LIMITS, commands=[], cases=roster(), inputs={}, artifacts={}, aliases={}, input_modes={},
        error=None, final_errors=[], source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        native_subjects=0, owner_validated=False, qualification_credit=False, performance_credit=False)

    def pin(raw):
        lexical = Path(raw).absolute(); q = lexical.resolve(strict=True); key = str(q)
        need(q.is_file(), 'regular input')
        value = fact(q); mode = q.stat().st_mode & 0o777
        need(str(lexical) not in r['aliases'] or r['aliases'][str(lexical)] == key, 'stable lexical alias')
        need(key not in r['inputs'] or (r['inputs'][key] == value and r['input_modes'][key] == mode), 'stable whole input/mode')
        r['aliases'][str(lexical)] = key; r['inputs'][key] = value; r['input_modes'][key] = mode
        return q

    def artifact(q):
        q = pin(q); r['artifacts'][str(q)] = dict(fact(q), mode=q.stat().st_mode & 0o777); return q

    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'current clean expected revision')
        r['driver'] = fact(pin(Path(__file__))); pin(Path(sys.executable)); imported_sources(pin)
        builds = retained_builds(a.build_receipt, a.build_receipt_sha256, r, pin)
        locations = {}
        for key, (name, message) in ERRORS.items():
            header = pin(SELECTED/name)
            lines = [i for i, line in enumerate(header.read_text().splitlines(), 1) if line == '#error '+json.dumps(message)]
            need(len(lines) == 1, 'one actual literal source guard '+key)
            locations[key] = (str(header), lines[0], message)
        for case in r['cases']:
            case.update(status='not_run', actual_errors=None)
        save(out/'receipt.json', r)
        for case in r['cases']:
            build = builds[case['mode']]
            text = '#include "persistent_group_config.h"\n'
            for macro, value in case['changes']:
                text += '#undef '+macro+'\n'
                if value is not None: text += '#define '+macro+' '+str(value)+'\n'
            text += '#include "persistent_loop_runtime.h"\nLI2_RO_PROFILE_ACCEPTED\n'
            tu = out/(case['name']+'.c'); tu.write_text(text); artifact(tu)
            expected = sorted(locations[k] for k in case['errors'])
            row = dict(name=case['name'], profile='preprocessor', bounds=LIMITS, expected_exit=int(bool(expected)),
                capture_limit=16 << 20, environment=build['environment'],
                argv=[build['compiler'], *build['flags'], '-fdiagnostics-color=never', '-E', '-P', '-x', 'c', str(tu)])
            r['commands'].append(row)
            try:
                stdout, stderr = invoke(row, out, cpu)
                complete(row, LIMITS, int(bool(expected)))
                diagnostics = []
                for line in stderr.decode('utf-8', errors='strict').splitlines():
                    m = re.match(r'^(.*):(\d+):(\d+): (fatal error|error|warning): (.*)$', line)
                    if m:
                        file, number, _, severity, payload = m.groups()
                        need(severity == 'error' and payload.startswith('#error "') and payload.endswith('"'),
                             'only intended preprocessor guard errors')
                        diagnostics.append((str(Path(file).resolve(strict=True)), int(number), json.loads(payload[7:])))
                    else:
                        need(not re.search(r'(?:^|: )(?:fatal error|error|warning):', line),
                             'no extra unlocated compiler diagnostic')
                need(sorted(diagnostics) == expected and (bool(stderr) if expected else stderr == b''),
                     'complete exact source-located guard diagnostic set')
                need(stdout.splitlines()[-1:] == [b'LI2_RO_PROFILE_ACCEPTED'] and
                     stdout.splitlines().count(b'LI2_RO_PROFILE_ACCEPTED') == 1, 'complete actual header preprocessing')
                case.update(status='passed', actual_errors=[list(x) for x in diagnostics])
            except Exception as exc:
                case.update(status='failed', error=type(exc).__name__+': '+str(exc))
            finally:
                for suffix in ('json', 'stdout', 'stderr'):
                    path = out/(case['name']+'.'+suffix)
                    if path.is_file(): artifact(path)
                save(out/'receipt.json', r)
            need(row.get('reaped') is True and row.get('cleanup_errors') == [], 'stop after unsafe child cleanup')
        need(len(r['commands']) == 53 and all(c['status'] == 'passed' for c in r['cases']),
             'all three positive and fifty intended refusal controls pass')
        r['status'] = 'observed_compile_contract_controls'
    except Exception as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        for label, action in (
            ('source', lambda: need(source() == r.get('source'), 'unchanged clean source')),
            ('inputs', lambda: need(all(fact(Path(k)) == v and Path(k).stat().st_mode & 0o777 == r['input_modes'][k]
                 for k, v in r['inputs'].items()) and all(str(Path(k).resolve(strict=True)) == v
                 for k, v in r['aliases'].items()), 'whole inputs, artifact modes and aliases unchanged'))):
            try:
                action(); r[label+'_unchanged'] = True
            except Exception as exc: r['final_errors'].append(label+': '+repr(exc))
        r['cleanup_complete'] = all(c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in c.get('descriptors', [])) for c in r['commands'])
        if r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        save(out/'receipt.json', r)
        with (out/'outcomes.csv').open('x', newline='') as stream:
            writer = csv.writer(stream); writer.writerow(('case', 'mode', 'expected_exit', 'actual_exit', 'status', 'duration_ns', 'expected_guard_messages'))
            rows = {x['name']: x for x in r['commands']}
            for case in r['cases']:
                row = rows.get(case['name'], {})
                writer.writerow((case['name'], case['mode'], int(bool(case['errors'])), row.get('exit'),
                    case.get('status', 'not_run'), row.get('duration_ns'), '|'.join(ERRORS[k][1] for k in case['errors'])))
        hw = r['hardware']
        summary = dict(schema=1, profile=r['profile'], status=r['status'], revision=r['revision'],
            source=r.get('source'), driver=r.get('driver'), receipt=fact(out/'receipt.json'), outcomes=fact(out/'outcomes.csv'),
            hardware={k: v for k, v in hw.items() if not k.startswith('runner_') and k != 'isa_flags'},
            isa_flags_sha256=digest(hw['isa_flags']), bounds=LIMITS, cpu=cpu,
            build_receipt=fact(a.build_receipt), build_revision=r.get('retained_build', {}).get('revision'),
            retained_producer_status=r.get('retained_build', {}).get('status'),
            inputs_sha256=digest(r['inputs']), command_records_sha256=digest(r['commands']),
            commands=len(r['commands']), positive_passed=sum(not c['errors'] and c.get('status') == 'passed' for c in r['cases']),
            negative_passed=sum(bool(c['errors']) and c.get('status') == 'passed' for c in r['cases']),
            failed_cases=[c['name'] for c in r['cases'] if c.get('status') == 'failed'],
            unlaunched_cases=[c['name'] for c in r['cases'] if c.get('status', 'not_run') == 'not_run'],
            source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'], cleanup_complete=r['cleanup_complete'],
            reproduction_argv=['python3.12', '-B', 'evaluation/inprocess/loop_ro_profile_controls.py',
                '--expect-revision', a.expect_revision, '--build-receipt', 'CLOSED_BUILD/receipt.json',
                '--build-receipt-sha256', a.build_receipt_sha256, '--output', 'FRESH_TARGET_OUTPUT'],
            native_subjects=0, archive_rebuilt=False, owner_validated=False, qualification_credit=False, performance_credit=False)
        save(out/'summary.json', summary)
    print(json.dumps(dict(status=r['status'], commands=len(r['commands']), receipt=str(out/'receipt.json')), sort_keys=True))
    return int(r['status'] != 'observed_compile_contract_controls')


if __name__ == '__main__':
    raise SystemExit(main())
