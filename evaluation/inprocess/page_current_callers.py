"""Run two unchanged current() caller oracles using a closed lookup provider.

First run page_current_lookup.py at the intended revision, then supply its whole
receipt hash and source revision. The fixed eight commands retain the original
five-CPU/15-wall-second bounds; this is component evidence only.
"""
import argparse, json, os, re, shlex, sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from checks import source
from page_selected import elf, fact, interpreter, need, save
from page_selected_process import invoke
from run import hardware
import persistent_active_domain as active

SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = [5, 512 << 20, 16 << 20, 15]
GUARD_STDOUT = b'{"status":"component_passed","checks":1110,"backing_bytes":176,"raw_calls":0,"native_executed":false,"qualification":false}\n'
NAMES = ['native-probe-headers','native-probe-build','native-probe-libraries','native-probe-run',
         'source-guard-headers','source-guard-build','source-guard-libraries','source-guard-run']
PRIOR_NAMES = ['resolve-cc1','resolve-collect2','resolve-as','resolve-ld',
    'version-cc','version-nm','version-objdump','version-ld','version-as','version-python',
    'link-input-crt1.o','link-input-Scrt1.o','link-input-crti.o','link-input-crtn.o',
    'link-input-crtbegin.o','link-input-crtbeginS.o','link-input-crtend.o','link-input-crtendS.o',
    'link-input-libgcc.a','link-input-libgcc_s.so','link-input-libc.so','link-input-libc_nonshared.a',
    'runtime-input-libc.so.6','runtime-input-libgcc_s.so.1','cc-specs','headers','fixture-link',
    'symbols','body','libraries','native']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--attempt', required=True)
    ap.add_argument('--provider-receipt', type=Path, required=True)
    ap.add_argument('--provider-sha256', required=True)
    ap.add_argument('--provider-revision', required=True)
    args = ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[a-z0-9][a-z0-9-]{0,80}', args.attempt) and
         len(os.sched_getaffinity(0)) == 1 and not sys.flags.optimize, 'exact source/attempt/singleton')
    need(re.fullmatch('[0-9a-f]{64}', args.provider_sha256) and
         re.fullmatch('[0-9a-f]{40}', args.provider_revision), 'explicit whole provider/source identities')
    os.chdir(ROOT); cpu, = os.sched_getaffinity(0)
    prior_path = args.provider_receipt.resolve(strict=True)
    need(prior_path.is_relative_to(ROOT/'target/evaluation/inprocess') and
         prior_path.name == 'receipt.json' and prior_path.is_file(), 'retained evaluation provider receipt')
    private = ROOT/'target/evaluation/inprocess'/args.attempt
    private.mkdir(parents=True, exist_ok=False)
    r = dict(schema=1, profile='current-absence-gap-caller-oracles-v1', status='failed',
        argv=[sys.executable,'-B',*sys.argv], driver=fact(__file__), source=source(),
        hardware=hardware(cpu), cpu=cpu, bounds=BOUNDS, commands=[], inputs={}, artifacts={},
        native_probe_component={}, source_guard={}, error=None, final_errors=[],
        source_unchanged=False, cleanup_complete=False,
        scope='Two unchanged supplied-state C oracles; no application, timing, native-policy or qualification credit.')
    before = r['source']; aliases = {}; prior = None; pending = []

    def pin(path):
        alias = str(Path(path).absolute()); p = Path(alias).resolve(strict=True); value = fact(p)
        need(alias not in aliases or aliases[alias] == str(p), 'stable input alias')
        aliases[alias] = str(p)
        need(str(p) not in r['inputs'] or r['inputs'][str(p)] == value, 'immutable whole input')
        r['inputs'][str(p)] = value; return p

    def binary(path):
        p = Path(path); need(p.is_file() and not p.is_symlink(), 'regular actual artifact')
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in r['artifacts'] or r['artifacts'][str(p)] == value, 'immutable whole artifact')
        r['artifacts'][str(p)] = value; return p

    def closure():
        need(os.sched_getaffinity(0) == {cpu}, 'same singleton')
        need(all(str(Path(a).resolve(strict=True)) == p for a,p in aliases.items()), 'input aliases')
        need(all(fact(p) == v for p,v in r['inputs'].items()), 'whole inputs')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p,v in r['artifacts'].items()), 'whole artifacts/modes')
        if prior:
            need(all(Path(p).exists() == v for p,v in prior['configuration_presence'].items()), 'loader configuration')

    def closed(row, directory, successful=True, capture_limit=16 << 20):
        need(row.get('reaped') is True and row.get('cleanup_errors') == [] and row.get('descriptors') == [],
             'actual process and descriptor closure')
        need(row['bounds'] == BOUNDS and row['capture_limit'] == capture_limit and
             type(row['expected_exit']) is int and row['expected_exit'] == 0, 'original exact child bounds')
        need(json.loads((directory/(row['name']+'.json')).read_bytes()) == row, 'whole actual command row')
        for name,value in row['captures'].items():
            need(name in ('stdout','stderr') and value['file'] == row['name']+'.'+name and
                 type(value['bytes']) is int and 0 <= value['bytes'] <= capture_limit and
                 fact(directory/value['file']) == {k:value[k] for k in ('bytes','sha256')}, 'whole actual capture')
        need(set(row['captures']) == {'stdout','stderr'}, 'both complete captures')
        if successful:
            need(type(row['exit']) is int and row['exit'] == 0 and row['timed_out'] is False and
                 row['error'] is None, 'actual bounded zero exit')

    def run(name, argv, profile='finite', env=None):
        closure(); need(name == NAMES[len(r['commands'])], 'fixed eight-command order')
        row = dict(name=name, argv=list(map(str,argv)), profile=profile, bounds=BOUNDS,
                   capture_limit=16 << 20, expected_exit=0, environment=dict(env or builder.environment))
        r['commands'].append(row)
        out, err = invoke(row, private, cpu); closed(row, private)
        return row, out, err

    def libraries(out, executable):
        loader = pin(interpreter(executable)); values = {}; vdso = 0
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)', line): vdso += 1; continue
            match = re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)', line)
            need(match is not None, 'whole actual library row')
            p = pin(match[1]); need(p.name not in values, 'unique library basename')
            values[p.name] = dict(path=str(p), **fact(p))
        expected = {Path(v['path']).name:{k:v[k] for k in ('path','bytes','sha256')}
                    for v in prior['libraries']['objects'].values()}
        need(vdso == 1 and values == expected and str(loader) in {v['path'] for v in values.values()},
             'exact complete retained libc/interpreter objects')
        return values

    try:
        need(before['revision'] == args.expect_revision and before['tracked_clean'] and before['head_sources_match'],
             'clean installed reviewed source')
        prior_fact = fact(pin(prior_path))
        need(prior_fact['sha256'] == args.provider_sha256, 'exact closed current-lookup provider')
        prior = json.loads(prior_path.read_bytes())
        need(prior['status'] == 'passed' and prior['profile'] == 'page-current-lookup-v1' and
             prior['source']['revision'] == args.provider_revision and
             prior['source']['tracked_clean'] is True and prior['source']['head_sources_match'] is True and
             prior['source_after'] == prior['source'] and prior['source_unchanged'] is True and
             prior['error'] is None and prior['final_errors'] == [] and len(prior['commands']) == 31 and
             prior['result']['queries'] == 3716 and 0 < prior['body']['bytes'] <= 512,
             'unchanged historical producer source and original oracle, no metadata rerun')
        r['retained_provider'] = dict(path=str(prior_path.relative_to(ROOT)), **prior_fact,
            cpu=prior['cpu'], source=prior['source'], result=prior['result'], reused_commands=31)
        need([row['name'] for row in prior['commands']] == PRIOR_NAMES and
             [row['profile'] == 'native' for row in prior['commands']] == [False]*30+[True],
             'literal original 30 metadata/build rows followed by one native oracle')
        for i,row in enumerate(prior['commands']):
            closed(row, prior_path.parent, capture_limit=(4 << 20) if i < 30 else 65536)
        for path,value in prior['inputs'].items(): need(fact(pin(path)) == value, 'retained whole input')
        for alias,target in prior['input_aliases'].items(): need(str(pin(alias)) == target, 'retained whole alias')
        for path,value in prior['artifacts'].items():
            binary(path); need(r['artifacts'][path] == value, 'retained artifact/mode')
        tools = {name:value['path'] for name,value in prior['tools'].items()}
        for name,value in prior['tools'].items():
            need(fact(pin(value['path'])) == {k:value[k] for k in ('bytes','sha256')}, 'retained tool '+name)
        environment = prior['commands'][0]['environment']
        need(all(row['environment'] == environment for row in prior['commands']), 'retained exact environment')
        builder = SimpleNamespace(tools=tools, environment=environment)
        pin(__file__); pin(sys.executable)
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT): pin(path)
        # Invoke the original callback itself; all recipe, dependency, ELF,
        # output, and 25/5/6/27/5/6 population assertions remain in that body.
        pending.append(private/'native-probe-component/linked-native-probe-oracle')
        active.native_probe_component(builder, private, pin, binary, run, r)
        probe = r['native_probe_component']
        loader_row = r['commands'][2]
        need(libraries((private/loader_row['captures']['stdout']['file']).read_bytes(), pending[0]) ==
             probe['runtime_libraries'], 'original callback library graph matches retained actual objects')
        fixture = SELECTED/'tests/loop_source_guard'; script = pin(fixture/'build.sh')
        oracle = pin(fixture/'oracle.c'); shell = pin('/bin/sh')
        output = private/'loop-source-guard'; output.mkdir(); exe = output/'loop-source-guard'; pending.append(exe)
        script_env = dict(environment, LI2_CC=tools['cc'])
        _, out, err = run('source-guard-headers', [shell,script,SELECTED,output,'headers'], env=script_env)
        lines = out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(lines) == 1 and lines[0].startswith('oracle.o: '), 'one actual source-guard include rule')
        headers = {str(pin(p)):fact(pin(p)) for p in shlex.split(lines[0].split(':',1)[1])}
        need({str(oracle),str(SELECTED/'lifecycle_loader.c'),str(SELECTED/'persistent_group_source.inc')} <= set(headers),
             'whole actual source-guard implementation')
        r['source_guard'].update(recipe=fact(script), headers=headers, compiler=prior['tools']['cc'])
        _, out, err = run('source-guard-build', [shell,script,SELECTED,output,'build'], env=script_env)
        need(out == err == b'', 'quiet actual source-guard build')
        binary(exe); data,head,segments = elf(exe)
        need(head[1] in (2,3) and head[2:4] == (62,1) and
             all(s[2]+s[5] <= len(data) and s[5] <= s[6] and s[1]&3 != 3 for s in segments if s[0] == 1) and
             any(s[0] == 0x6474e551 and not s[1]&1 for s in segments), 'whole source-guard non-WX ELF/stack')
        loader = pin(interpreter(exe))
        _, out, err = run('source-guard-libraries', [loader,'--list',exe], env=script_env)
        need(not err, 'source-guard loader stderr'); r['source_guard']['libraries'] = libraries(out,exe)
        row, out, err = run('source-guard-run', [exe], env=script_env)
        need(out == GUARD_STDOUT and err == b'', 'all 1109 preceding checks plus final assertion, whole exact output')
        r['source_guard'].update(status='passed', counts=json.loads(out), artifact=fact(exe), duration_ns=row['duration_ns'])
        need([x['name'] for x in r['commands']] == NAMES, 'complete eight-command schedule')
        r['status'] = 'passed'
    except BaseException as exc: r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        for path in pending:
            try:
                if path.exists(): binary(path)
            except BaseException as exc: r['final_errors'].append('partial artifact: '+repr(exc))
        try:
            closure(); need(source() == before, 'unchanged whole source'); r['source_unchanged'] = True
            for row in r['commands']: closed(row, private, successful=False)
            r['cleanup_complete'] = True
        except BaseException as exc: r['final_errors'].append('closure: '+repr(exc))
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r['input_aliases'] = aliases; save(private/'receipt.json',r)
    print(json.dumps(dict(status=r['status'], error=r['error'], commands=len(r['commands']),
        probe=r['native_probe_component'].get('counts'), source_guard=r['source_guard'].get('counts'),
        receipt=str((private/'receipt.json').relative_to(ROOT)))), flush=True)
    return int(r['status'] != 'passed')


if __name__ == '__main__': raise SystemExit(main())
