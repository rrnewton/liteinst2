#!/usr/bin/env python3
"""Four bounded anonymous-reset component commands; no guest qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from checks import source
from page_selected import ENV, elf, fact, interpreter, need, save
from page_selected_process import invoke
from run import hardware

SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/maps_anon_reset'
BOUNDS = [5, 512 << 20, 16 << 20, 15]
NAMES = ['maintained-build', 'maintained-run', 'differential-build', 'differential-run']
LEAVES = {
    'maps_view.h': {'bytes':1474, 'sha256':'cafc0e86b1779b4cb592f11f4db2d108de75252724e7f2cf80f464dd3d43853b'},
    'maps_view.inc': {'bytes':27010, 'sha256':'d9e5381a362dc5e14310809e8ce3d9d228ef5963ed99b891d67845f526f33fb7'},
    'sealed_generation.inc': {'bytes':13954, 'sha256':'104c70649366411e64b2f397ecf7e0db8ea840db2168d7a3a0bf89db8c572740'},
    'tests/maps_anon_reset/oracle.c': {'bytes':11652, 'sha256':'abc1da4220bfa20c96594598846ce0813a3154f810653808457dbf97e5a0672d'},
    'tests/maps_anon_reset/build.sh': {'bytes':951, 'sha256':'1c2b250abbf7466cab7444bc58c7dc0f18aac9c8efcf726c688da72e1e3a7bd4'},
    'tests/maps_anon_reset/EXPECTED.json': {'bytes':299, 'sha256':'6e115a025fb75bfe4fcd500409c66cd27fbe52321caa0b283fdf5319dbab8d58'},
}


def observed(path):
    p = Path(path).resolve(strict=True)
    return dict(fact(p), mode=p.stat().st_mode & 0o777)


def build_child(output, profile):
    """Tool discovery and the unchanged recipe share the parent's 5/15 bound."""
    inputs, aliases, queries = {}, {}, []
    state = dict(status='failed', profile=profile, inputs=inputs, aliases=aliases,
                 queries=queries, error=None, source_dependencies={})
    def pin(path):
        p = Path(path).absolute(); resolved = p.resolve(strict=True); value = observed(resolved)
        need(str(p) not in aliases or aliases[str(p)] == str(resolved), 'stable build alias')
        need(str(resolved) not in inputs or inputs[str(resolved)] == value, 'stable build input')
        aliases[str(p)] = str(resolved); inputs[str(resolved)] = value
        return resolved
    def tool(name):
        p = shutil.which(name, path=ENV['PATH']); need(p is not None, 'actual tool '+name)
        return pin(p)
    def query(argv):
        result = subprocess.run(list(map(str, argv)), env=dict(ENV), cwd=output,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
        need(len(result.stdout) <= 65536 and len(result.stderr) <= 65536, 'bounded metadata output')
        queries.append(dict(argv=list(map(str, argv)), exit=result.returncode,
                            stdout=result.stdout.decode(), stderr=result.stderr.decode()))
        need(result.returncode == 0 and result.stderr == b'', 'actual tool metadata')
        return result.stdout
    def stable():
        need(all(str(Path(a).resolve(strict=True)) == p for a,p in aliases.items()), 'build aliases')
        need(all(observed(p) == v for p,v in inputs.items()), 'whole build inputs/modes')
    try:
        cc, shell = tool('cc'), tool('sh')
        for name in ('as', 'ld', 'mkdir', 'dirname'): tool(name)
        pin(sys.executable); pin(__file__)
        for path, expected in LEAVES.items():
            need(fact(pin(SELECTED/path)) == expected, 'exact installed component leaf '+path)
        state['compiler'] = dict(path=str(cc), **fact(cc))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            path = query([cc, '-print-prog-name='+name]).decode().strip()
            need(path and '\n' not in path, 'single compiler subtool path')
            pin(path if '/' in path else tool(path))
        for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o',
                     'crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a',
                     'libc.so.6','libgcc_s.so.1'):
            path = query([cc, '-print-file-name='+name]).decode().strip()
            need(path != name and Path(path).is_absolute(), 'resolved compiler link input '+name)
            pin(path)
        state['compiler_version'] = query([cc, '-dumpfullversion', '-dumpversion']).decode().strip()
        state['compiler_target'] = query([cc, '-dumpmachine']).decode().strip()
        for p in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            if Path(p).exists(): pin(p)
        state['configuration_presence'] = {p:os.path.lexists(p) for p in ('/etc/ld.so.cache','/etc/ld.so.preload')}
        need(not state['configuration_presence']['/etc/ld.so.preload'], 'no implicit preload')
        recipe = (FIXTURE/'build.sh').read_text()
        marker = '"$cc_bin" -std=gnu11'
        need(recipe.count(marker) == 1, 'one whole compiler command in the pinned recipe')
        words = shlex.split(recipe[recipe.index(marker):].replace('\\\n',' '))
        replacements = {'$cc_bin':str(cc),'$selected_dir':str(SELECTED),
                        '$parent_dir':str(SELECTED.parent),'$fixture_dir':str(FIXTURE),
                        '$output_dir':str(output)}
        compiler_argv = []
        for word in words:
            if word == '$@':
                compiler_argv.extend(['-DLI2_MAPS_DIFFERENTIAL=1'] if profile == 'differential' else [])
            else:
                for old,new in replacements.items(): word = word.replace(old,new)
                need('$' not in word, 'complete literal recipe substitution')
                compiler_argv.append(word)
        state['compiler_argv'] = compiler_argv
        preprocessing = []; skip = False
        for word in compiler_argv:
            if skip: skip = False; continue
            if word in ('-o','-MF'): skip = True; continue
            if word == '-MD' or word.startswith('-Wl,'): continue
            preprocessing.append(word)
        include_raw = query(preprocessing+['-M','-MT','maps-anon-inputs']).decode().replace('\\\n',' ')
        target,separator,body = include_raw.partition(':')
        need(separator and target == 'maps-anon-inputs', 'actual pre-build whole-TU include closure')
        for p in shlex.split(body):
            need(Path(p).is_absolute(), 'absolute actual pre-build include')
            resolved = pin(p); state['source_dependencies'][str(resolved)] = observed(resolved)
        stable()
        argv = [shell, FIXTURE/'build.sh', SELECTED, output, profile]
        state['recipe_argv'] = list(map(str, argv))
        result = subprocess.run(state['recipe_argv'], env=dict(ENV, LI2_CC=str(cc)), cwd=output, check=False)
        state['recipe_exit'] = result.returncode
        need(result.returncode == 0, 'actual unchanged component recipe')
        executable = output/'maps-anon-reset'
        dep = output/'maps-anon-reset.d'
        raw = dep.read_text().replace('\\\n', ' ')
        target, separator, body = raw.partition(':')
        need(separator and shlex.split(target) == [str(executable)], 'one actual dependency target')
        dependencies = shlex.split(body)
        need(dependencies and len(dependencies) == len(set(dependencies)), 'unique actual compiler dependencies')
        compiled = {}
        for p in dependencies:
            need(Path(p).is_absolute(), 'absolute actual include path')
            resolved = pin(p); compiled[str(resolved)] = observed(resolved)
        need(compiled == state['source_dependencies'], 'emitted dependency closure equals whole pre-build inputs')
        required = [FIXTURE/'oracle.c', SELECTED/'lifecycle_loader.c', SELECTED/'lifecycle_loader.h',
                    SELECTED/'maps_phase.inc', SELECTED/'maps_phase.h', SELECTED/'maps_view.inc',
                    SELECTED/'maps_view.h', SELECTED/'private_code_query.inc']
        need(all(str(p.resolve()) in state['source_dependencies'] for p in required),
             'actual complete lifecycle TU and maps implementation')
        data, header, segments = elf(executable)
        need(header[1] in (2,3) and header[2:4] == (62,1) and
             all(s[2]+s[5] <= len(data) and s[5] <= s[6] and s[1]&3 != 3 for s in segments if s[0] == 1) and
             any(s[0] == 0x6474e551 and not s[1]&1 for s in segments), 'actual non-WX executable and stack')
        loader = pin(interpreter(executable))
        listing = query([loader, '--list', executable]).decode()
        libraries, vdso = {}, 0
        for line in listing.splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)', line): vdso += 1; continue
            match = re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)', line)
            need(match is not None, 'whole actual loader listing')
            p = pin(match[1]); need(p.name not in libraries, 'unique actual runtime object')
            libraries[p.name] = dict(path=str(p), **observed(p))
        need(vdso == 1 and set(libraries) == {'libc.so.6', loader.name} and
             libraries[loader.name]['path'] == str(loader), 'complete actual libc/interpreter graph')
        state['runtime_libraries'] = libraries
        stable()
        need(all(os.path.lexists(p) == v for p,v in state['configuration_presence'].items()), 'loader configuration closure')
        state['status'] = 'passed'
    except BaseException as exc:
        state['error'] = type(exc).__name__+': '+str(exc)
    finally:
        save(output/'build.json', state)
    return int(state['status'] != 'passed')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision')
    ap.add_argument('--attempt')
    ap.add_argument('--build-child', choices=('maintained','differential'))
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    if args.build_child:
        need(args.output is not None and args.output.is_absolute() and args.output.is_dir() and
             args.expect_revision is None and args.attempt is None, 'private bounded build invocation')
        return build_child(args.output, args.build_child)
    need(args.output is None and re.fullmatch('[0-9a-f]{40}', args.expect_revision or '') and
         re.fullmatch('[a-z0-9][a-z0-9-]{0,80}', args.attempt or '') and
         len(os.sched_getaffinity(0)) == 1 and not sys.flags.optimize, 'exact revision, fresh attempt and singleton')
    os.chdir(ROOT); cpu, = os.sched_getaffinity(0)
    output = ROOT/'target/evaluation/inprocess'/args.attempt; output.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(args.attempt+'.json')
    need(not public.exists(), 'fresh public result')
    before = source()
    r = dict(schema=1, profile='maps-anonymous-reset-component-v1', status='failed',
             argv=[sys.executable,'-B',*sys.argv], source=before, hardware=hardware(cpu), cpu=cpu,
             bounds=BOUNDS, commands=[], inputs={}, aliases={}, artifacts={}, results=[], builds={},
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
             error=None, final_errors=[], guest_executions=0, qualification_credit=False, performance_credit=False,
             timing_scope='whole supervised validation command, including build metadata; not runtime performance')
    def pin(p):
        alias = str(Path(p).absolute()); path = Path(alias).resolve(strict=True); value = observed(path)
        need(alias not in r['aliases'] or r['aliases'][alias] == str(path), 'stable input alias')
        need(str(path) not in r['inputs'] or r['inputs'][str(path)] == value, 'whole current input')
        r['aliases'][alias] = str(path); r['inputs'][str(path)] = value; return path
    def artifact(p):
        p = Path(p).resolve(strict=True); value = observed(p)
        need(str(p) not in r['artifacts'] or r['artifacts'][str(p)] == value, 'stable artifact')
        r['artifacts'][str(p)] = value
    def closure():
        need(source() == before and os.sched_getaffinity(0) == {cpu}, 'same clean source and CPU')
        need(all(str(Path(a).resolve(strict=True)) == p for a,p in r['aliases'].items()), 'all input aliases')
        need(all(observed(p) == v for p,v in r['inputs'].items()), 'whole inputs/modes')
        need(all(observed(p) == v for p,v in r['artifacts'].items()), 'whole artifacts/modes')
    def run(name, argv):
        closure(); need(name == NAMES[len(r['commands'])], 'fixed four-command order')
        row = dict(name=name, argv=list(map(str,argv)), environment=dict(ENV), profile='finite',
                   bounds=BOUNDS, capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row); stdout, stderr = invoke(row, output, cpu)
        need(type(row['exit']) is int and row['exit'] == 0, 'actual bounded zero exit')
        return stdout, stderr
    try:
        need(before['revision'] == args.expect_revision, 'exact requested clean revision')
        pin(__file__); pin(sys.executable)
        for module in tuple(sys.modules.values()):
            p = getattr(module, '__file__', None)
            if p and Path(p).is_file(): pin(p)
        for p, expected in LEAVES.items(): need(fact(pin(SELECTED/p)) == expected, 'reviewed installed leaf '+p)
        expected = json.loads((FIXTURE/'EXPECTED.json').read_bytes())
        need(expected == [dict(version=1,differential=i,positives=5,fallback_controls=20,row_refusals=6,guest_executions=0)
                          for i in (0,1)], 'fixed complete component population')
        for i, profile in enumerate(('maintained','differential')):
            directory = output/profile; directory.mkdir()
            stdout, stderr = run(profile+'-build', [sys.executable,'-B',Path(__file__).resolve(),
                                                   '--build-child',profile,'--output',directory])
            need(stdout == stderr == b'', 'quiet complete build and metadata')
            state = json.loads((directory/'build.json').read_bytes())
            r['builds'][profile] = state
            need(state['status'] == 'passed' and state['error'] is None and state['profile'] == profile,
                 'whole current build/metadata closure')
            for alias,path in state['aliases'].items(): need(str(pin(alias)) == path, 'actual build input aliases')
            for p,value in state['inputs'].items(): need(observed(pin(p)) == value, 'actual whole build inputs')
            for name in ('build.json','maps-anon-reset','maps-anon-reset.d'): artifact(directory/name)
            stdout, stderr = run(profile+'-run', [directory/'maps-anon-reset'])
            need(stderr == b'' and stdout == json.dumps(expected[i],separators=(',',':')).encode()+b'\n',
                 'exact complete component output and all 31 cases')
            r['results'].append(expected[i])
        need([x['name'] for x in r['commands']] == NAMES, 'complete four-command schedule')
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        for profile in ('maintained','differential'):
            manifest = output/profile/'build.json'
            try:
                if manifest.exists():
                    state = json.loads(manifest.read_bytes()); r['builds'][profile] = state
                    for alias,path in state['aliases'].items(): need(str(pin(alias)) == path, 'final build alias')
                    for p,value in state['inputs'].items(): need(observed(pin(p)) == value, 'final build input')
                    need(all(os.path.lexists(p) == v for p,v in state.get('configuration_presence',{}).items()),
                         'final loader configuration')
            except BaseException as exc: r['final_errors'].append('build closure: '+repr(exc))
            for name in ('build.json','maps-anon-reset','maps-anon-reset.d'):
                p = output/profile/name
                try:
                    if p.exists(): artifact(p)
                except BaseException as exc: r['final_errors'].append('artifact: '+repr(exc))
        try:
            closure(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(row['reaped'] and row['cleanup_errors'] == [] and row['descriptors'] == [],
                     'actual child process and descriptor closure')
                need(json.loads((output/(row['name']+'.json')).read_bytes()) == row, 'whole saved command')
                need(set(row['captures']) == {'stdout','stderr'}, 'both actual captures')
                for stream,v in row['captures'].items():
                    need(v['file'] == row['name']+'.'+stream and 0 <= v['bytes'] <= 16 << 20 and
                         fact(output/v['file']) == {k:v[k] for k in ('bytes','sha256')}, 'whole capture closure')
            r['cleanup_complete'] = True
        except BaseException as exc: r['final_errors'].append('closure: '+repr(exc))
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        save(output/'receipt.json', r)
    host = dict(r['hardware']); flags = host.pop('isa_flags')
    host['isa_flags_sha256'] = hashlib.sha256(json.dumps(flags,separators=(',',':')).encode()).hexdigest()
    compact = dict(schema=1, profile=r['profile'], status=r['status'], source=before, hardware=host, bounds=BOUNDS,
                   driver=fact(__file__), private_receipt=fact(output/'receipt.json'), results=r['results'],
                   commands=[{k:row[k] for k in ('name','exit','timed_out','duration_ns','captures')} for row in r['commands']],
                   source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'],
                   cleanup_complete=r['cleanup_complete'], error_type=r['error'].split(':',1)[0] if r['error'] else None,
                   final_error_count=len(r['final_errors']), old_six_mode_fixture='separate mandatory population, not rerun here',
                   guest_executions=0, qualification_credit=False, performance_credit=False,
                   reproduce=['python3.12','-B','evaluation/inprocess/maps_anon_reset.py',
                              '--expect-revision',args.expect_revision,'--attempt',args.attempt])
    text = json.dumps(compact,sort_keys=True,separators=(',',':'))+'\n'
    need(len(text.encode()) < 12 << 10 and '/home/' not in text and str(ROOT) not in text,
         'compact public result without host paths or raw logs')
    public.parent.mkdir(parents=True,exist_ok=True)
    with public.open('x') as f: f.write(text)
    print(json.dumps(dict(status=r['status'], commands=len(r['commands']), results=r['results'],
                          receipt=str((output/'receipt.json').relative_to(ROOT)))), flush=True)
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())

