#!/usr/bin/env python3
"""Additive byte-helper/component diagnostic from a fresh scalar receipt; no owner credit."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV, save, elf as load_elf
from page_selected_process import invoke
from loop_components import run as component
from scalar_span_trace_build import fast_bytes, fast_bytes_completed, recipe, expand

need, fact = component.need, component.fact
SELECTED = ROOT/'tools/page-entry/selected'
FAST = ['-DLI2_SCALAR_SPAN_TRACE=1', '-DLI2_SPAN_FAST_BYTES=1']
BOUNDS = dict(metadata=[30,512<<20,64<<20,60], release_build=[30,512<<20,16<<20,60], finite=[5,512<<20,16<<20,15])
SIZE_ROW = b'{"version":1,"profile":"loop-plan-fast-bytes-sizes-v1","status":0,"plan_bytes":981320,"witness_bytes":83320,"lengths":2,"placements":14,"mismatches":42,"zero_access":32,"prefix_mismatches":98,"overlaps":0,"fp_cases":0}\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision', 'component-receipt-sha256'): ap.add_argument('--'+name, required=True)
    for name in ('component-receipt', 'output'): ap.add_argument('--'+name, required=True, type=Path)
    args = ap.parse_args(); cpus = sorted(os.sched_getaffinity(0)); private = args.output.resolve()
    need(sys.version_info >= (3,11) and not sys.flags.optimize and len(cpus) == 1, 'one reserved CPU; Python3.11+ assertions')
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct private output')
    private.mkdir(); cpu = cpus[0]; pins, aliases, artifacts, commands = {}, {}, {}, []
    r = dict(profile='loop-fast-bytes-supplement-v1', status='failed', cpu=cpu, source=None, results={}, error=None,
             final_errors=[], qualification_credit=False, owner_credit=False, performance_credit=False, archive_source_provenance_verified=False)
    baseline = None

    def pin(path):
        alias = str(Path(path).absolute()); p = Path(alias).resolve(strict=True); value = fact(p)
        need(alias not in aliases or aliases[alias] == str(p), 'stable alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input')
        aliases[alias] = str(p); pins[str(p)] = value; return p

    def binary(path):
        p = Path(path); need(p.is_relative_to(private), 'private output containment'); value = fact(p)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'immutable completed artifact')
        artifacts[str(p)] = value; return p

    def closure():
        need(all(fact(p) == v for p,v in pins.items()) and all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'whole input closure')
        need(all(fact(p) == v for p,v in artifacts.items()) and sorted(os.sched_getaffinity(0)) == [cpu], 'artifact and CPU closure')
        if baseline is not None: need(all(Path(p).exists() == v for p,v in baseline['loader_presence'].items()), 'loader configuration presence')

    def run(name, argv, profile='metadata', env=ENV):
        closure(); need(name not in [x['name'] for x in commands], 'one command, no retry')
        row = dict(name=name, argv=list(map(str,argv)), profile=profile, environment=dict(env), bounds=BOUNDS[profile], capture_limit=16<<20, expected_exit=0)
        commands.append(row)
        try: out, err = invoke(row, private, cpu)
        finally:
            for v in row.get('captures',{}).values():
                p = binary(private/v['file']); need(all(artifacts[str(p)][k] == v[k] for k in ('bytes','sha256')), 'whole command capture')
            if (private/(name+'.json')).is_file(): binary(private/(name+'.json'))
        need(row['exit'] == 0 and row['reaped'] and not row['timed_out'] and row['error'] is None and
             not row['cleanup_errors'] and all(d['closed'] for d in row['descriptors']), 'exact exit and complete cleanup')
        return row, out, err

    def headers(label, argv, required, profile='release_build'):
        units = [x for x in argv if x.endswith(('.c','.S'))]
        flags = [x for x in argv[1:-2] if x not in units and not x.endswith('.a') and not x.startswith(('-Wl,','-l'))]
        _, out, err = run(label+'-headers', [argv[0],*flags,'-M','-MT','call_component',*units],profile=profile)
        rows = out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rows) == len(units) and all(x.startswith('call_component: ') for x in rows), 'complete actual compiler-M rules')
        deps = {str(pin(x)) for line in rows for x in shlex.split(line.split(':',1)[1])}
        need({str(Path(x).resolve()) for x in units+required} <= deps, 'all actual source and typed headers')

    def executable(path, expected):
        p = binary(path); _, h, ph = load_elf(p)
        need(h[1] in (2,3) and any(x[0] == 1 and x[1] == 5 and x[3] <= h[4] < x[3]+x[6] for x in ph) and
             all(not(x[1]&1 and x[1]&2) for x in ph if x[0] in (1,0x6474e551)), 'actual ELF entry and W^X')
        need(component.elf(p) == expected, 'unchanged interpreter and all dynamic edges to pinned baseline runtime')
        return p

    try:
        r['source'] = source(); need(r['source']['revision'] == args.expect_revision, 'clean exact requested revision')
        p = pin(args.component_receipt); need(re.fullmatch('[0-9a-f]{64}',args.component_receipt_sha256) and fact(p)['sha256'] == args.component_receipt_sha256, 'explicit complete baseline receipt')
        need(p.name == 'receipt.json' and p.parent.parent == ROOT/'target/evaluation/inprocess', 'retained direct baseline receipt')
        baseline = json.loads(p.read_bytes()); r['baseline_receipt'] = fact(p)
        need(baseline['profile'] == 'experimental-loop-components-v1' and baseline['status'] == 'components_passed' and
             baseline['source'] == r['source'] and baseline['revision'] == args.expect_revision and baseline['cpu'] == cpu and
             baseline['hardware'] == hardware(cpu) and baseline['bounds'] == component.BOUNDS and baseline['error'] is None and
             baseline['final_errors'] == [] and all(baseline[k] is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete')) and
             len(baseline['commands']) == 60 and set(baseline['components']) == set(component.CASES), 'complete unchanged five-component baseline')
        for group in ('inputs','artifacts'):
            for path, expected in baseline[group].items(): need(fact(pin(path)) == expected, 'whole baseline '+group)
        for alias, target in baseline['aliases'].items(): need(str(pin(alias)) == target, 'all baseline aliases')
        for row in baseline['commands']:
            need(row['exit'] == row['expected_exit'] == 0 and row['reaped'] and not row['timed_out'] and row['error'] is None and
                 not row['cleanup_errors'] and all(d['closed'] for d in row['descriptors']), 'all baseline commands closed')
            need(json.loads(pin(p.parent/(row['name']+'.json')).read_bytes()) == row, 'whole baseline command record')
            for capture in row['captures'].values():
                need(Path(capture['file']).name == capture['file'], 'local baseline capture')
                actual = fact(pin(p.parent/capture['file']))
                need(all(actual[k] == capture[k] for k in ('bytes','sha256')), 'whole baseline capture identity')
        for name, old in baseline['components'].items():
            out = pin(p.parent/(name+'-component.stdout')).read_bytes(); err = pin(p.parent/(name+'-component.stderr')).read_bytes()
            need(old['status'] == 'passed' and component.component_result(name,out,err) == old['result'], 'all five original output predicates')
        builder = SimpleNamespace(tools=baseline['tools'], environment=dict(ENV)); r['archive'] = baseline['archive']
        host = dict(baseline['hardware']); flags = host.pop('isa_flags')
        host['isa_flags_sha256'] = component.digest(component.canonical(flags)); r['hardware'] = host
        r['script'] = fact(pin(__file__)); r['python'] = fact(pin(sys.executable))
        r['reproduce'] = ['python3','-B','evaluation/inprocess/loop_fast_bytes.py','--expect-revision',args.expect_revision,
                          '--component-receipt',str(p.relative_to(ROOT)),'--component-receipt-sha256',args.component_receipt_sha256,
                          '--output','target/evaluation/inprocess/loop-fast-bytes-supplement-fresh']
        recipe_path = pin(SELECTED/'tests/loop_plan/build.sh')
        need(fact(recipe_path)['sha256'] == component.CASES['loop_plan']['recipe_sha256'], 'unchanged loop macro recipe')
        macros = [x for x in recipe(recipe_path,'"$cc_bin"')[0] if x.startswith('-D')]
        need(macros == [x for x in baseline['components']['loop_plan']['original_argv'] if x.startswith('-D')] and
             len(macros) == 10 and not set(macros)&set(FAST), 'whole original full loop-plan macro profile')
        for module in tuple(sys.modules.values()):
            name = getattr(module,'__file__',None)
            if name and Path(name).is_file(): pin(name)
        pin(__file__); pin(sys.executable); pin('/usr/bin/git')
        build = {}; fast_bytes(builder,private,pin,binary,aliases,run,build); fast_bytes_completed(build,commands,binary)
        r['results']['original_byte_oracle'] = json.loads((private/'span-bytes-oracle.stdout').read_bytes())
        a = build['fast_bytes']['header_observations'][0]['argv']; old_unit = str(SELECTED/'tests/span_fast_bytes/oracle.c')
        unit = str(pin(SELECTED/'tests/span_fast_bytes/loop_sizes.c')); output = private/'loop-sizes'
        argv = [unit if x == old_unit else x for x in a[:-2]]+macros+['-o',str(output)]
        headers('loop-sizes',argv,[old_unit,str(SELECTED/'persistent_loop_plan.h'),str(SELECTED/'span_fast_bytes.h')],profile='metadata')
        _, out, err = run('loop-sizes-build',argv,profile='release_build'); need(out == err == b'', 'strict size-wrapper build')
        executable(output,component.elf(build['fast_bytes']['path']))
        _, out, err = run('loop-sizes-oracle',[output],profile='finite'); need(out == SIZE_ROW and not err, 'all full-size guarded byte cases')
        r['results']['full_size_byte_oracle'] = json.loads(out)
        for name in ('loop_envelope','bounded_fusion_plan','loop_plan'):
            case = component.CASES[name]; old = baseline['components'][name]; a = old['original_argv']
            fixture = SELECTED/'tests'/case.get('recipe_fixture',name); script = pin(fixture/'build.sh')
            need(old['status'] == 'passed' and fact(script) == old['recipe'] and fact(script)['sha256'] == case['recipe_sha256'], 'unchanged exact component recipe')
            archive = pin(next(x for x in a if x.endswith('.a'))); need(fact(archive) == baseline['archive'] and archive.read_bytes().startswith(b'!<arch>\n'), 'whole same supplied archive')
            units = [str(SELECTED/x) for x in case['units']]; directory = private/name; directory.mkdir(); output = directory/'component'
            values = {'$cc_bin':builder.tools['cc'],'$fixture':fixture,'$selected':SELECTED,'$archive':archive,'$output':Path(a[-1]).parent if case.get('output_directory') else a[-1],'$root':ROOT,'$chooser':SELECTED,'$scalar':SELECTED,'$overlay':SELECTED,'$kind':'metadata','$support':SELECTED/'tests/decoder/support.c'}
            rows = recipe(script,'"$cc_bin"'); need(len(rows) == 1 and expand(rows[0],values) == a and a[-2] == '-o' and not set(FAST)&set(a), 'whole original compiler argv')
            argv = a[:-2]+FAST+['-o',str(output)]
            headers(name,argv,[str(SELECTED/x) for x in case['headers']+['span_fast_bytes.h']])
            argv = argv[:-2]+['-save-temps=obj','-Wl,--trace']+argv[-2:]
            _, out, err = run(name+'-build',argv,profile='release_build'); need(not err, 'unchanged strict component diagnostics')
            objects = {str(directory/(output.name+'-'+Path(x).stem+'.o')) for x in units}
            old_objects = {str(Path(a[-1]).parent/(Path(a[-1]).name+'-'+Path(x).stem+'.o')) for x in units}
            trace = out.decode().splitlines(); need(trace and all(Path(x).is_absolute() for x in trace), 'whole actual link trace')
            linked = {str(Path(x).resolve(strict=True)) for x in trace}
            need(objects <= linked and linked-objects == set(old['link_inputs'])-old_objects, 'all generated objects and exact baseline external link inputs')
            for x in units:
                for suffix in ('.i','.s','.o','.su'): binary(directory/(output.name+'-'+Path(x).stem+suffix))
            executable(output,old['elf'])
            need(all(component.elf(path) == expected for path,expected in old['runtime_objects'].items()), 'whole prebound runtime ELF closure')
            _, out, err = run(name+'-oracle',[output],profile='finite'); value = component.component_result(name,out,err)
            scalar = p.parent/(name+'-component.stdout'); need(out == pin(scalar).read_bytes() and value == old['result'], 'whole scalar/fast equality with unchanged component comparator')
            r['results'][name] = value
        need(len(r['results']) == 5, 'both byte oracles and all three supplemental components'); r['status'] = 'observed_fast_byte_components'
    except BaseException as exc: r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        try: closure(); need(source() == r['source'], 'whole clean source before/after'); r['closure_complete'] = True
        except BaseException as exc: r['final_errors'].append(repr(exc)); r['closure_complete'] = False
        if r['error'] or r['final_errors']: r['status'] = 'failed'
        save(private/'custody.json',dict(inputs={k:v for k,v in pins.items() if baseline is None or k not in baseline['inputs'] and k not in baseline['artifacts']},aliases=aliases,artifacts=artifacts))
        r['custody'] = fact(private/'custody.json')
        r['commands'] = [dict(name=c['name'],exit=c.get('exit'),bounds=c['bounds'],duration_ns=c.get('duration_ns'),record=fact(private/(c['name']+'.json')) if (private/(c['name']+'.json')).is_file() else None) for c in commands]
        save(private/'receipt.json',r)
        public = dict(r); public['error'] = None if r['error'] is None else r['error'].split(':',1)[0]; public['final_errors'] = len(r['final_errors'])
        public['receipt'] = fact(private/'receipt.json'); public['baseline_profile_unchanged'] = True
        text = json.dumps(public,sort_keys=True,indent=2)+'\n'; need('/home/' not in text and len(text) < 32768, 'compact path-free public summary')
        (private/'summary.json').write_text(text); print(json.dumps(dict(status=r['status'],summary=str((private/'summary.json').relative_to(ROOT)))))
    return int(r['status'] != 'observed_fast_byte_components')


if __name__ == '__main__':
    raise SystemExit(main())
