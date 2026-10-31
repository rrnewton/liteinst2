#!/usr/bin/env python3
"""One before-registration loader loop under original native and two gated modes."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
import shlex
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from persistent_dynamic import BOUNDS
from startup_loop_helpers import cohort
from startup_loop_build import inspect_application
from page_selected_effect_ls import program_invoke
import persistent_active_domain as component
from page_selected_process import invoke
from page_selected_register_time_build import recipe, expand, headers
from page_selected_oneshot_build import before_default

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
PROFILES = dict(BOUNDS)
ELF_SHA = '34c232018a619b0091e97add6805072d00db3250937fc049a1ef968cecfa99c9'
PAIR_SHA = 'd581910c998f52887ed76623d2280e52d178a4d25d46001d64586bd2c8ddf7ab'


def extract(path, output):
    data = path.read_bytes()
    need(len(data) == 939216 and hashlib.sha256(data).hexdigest() == ELF_SHA,
         'exact reference interpreter; a different ELF needs separate qualification')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:3] == (3, 62), 'reference ELF64 ET_DYN')
    ph = [struct.unpack_from('<IIQQQQQQ', data, h[5]+i*h[9]) for i in range(h[10])]
    need(sum(p[0] == 1 and p[1] == 5 and p[2] == p[3] and
             p[3] <= 0x10000 and p[3]+p[5] >= 0x12000 for p in ph) == 1,
         'whole file-backed executable source pair')
    rows = 0
    for i in range(h[12]):
        s = struct.unpack_from('<IIQQQQIIQQ', data, h[6]+i*h[11])
        if s[1] in (4, 9):
            need(s[9] in (16, 24) and s[5] % s[9] == 0, 'complete relocation rows')
            for at in range(s[4], s[4]+s[5], s[9]):
                need(not 0x10000 <= struct.unpack_from('<Q', data, at)[0] < 0x12000,
                     'no ELF relocation target in the source pair')
                rows += 1
    pair = data[0x10000:0x12000]
    need(rows == 143 and hashlib.sha256(pair).hexdigest() == PAIR_SHA, 'exact complete pair')
    output.write_bytes(pair)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--interpreter', type=Path, default=Path('/usr/lib64/ld-linux-x86-64.so.2'))
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-startup-loop-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    receipt = private/'receipt.json'
    r = dict(schema=1, status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, cleanup_complete=False, commands=[], cases=[dict(label='subject-'+lane+'-2-0',lane=lane,mode=2,control=0,expected_exit=0,status='unexecuted',launched=False) for lane in ('native','maintained','differential')],
             error=None, final_errors=[], hardware=hardware(cpu), bounds=PROFILES,
             scope='one before-registration original loader-loop activation; no whole-program or performance credit')
    r.update(cpu=cpu, namespace_aliases={}, terminal_reports={}, lanes={},
        maps_parse_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        native_probe_component=dict(status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False),
        component_oracles=[dict(name=n,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['finite'],
            emitted_instruction_execution=0,hardware_subjects=0,performance_credit=False)for n in component.COMPONENT_ORDER],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=PROFILES['seed'],
            owner_subjects=0,completed_applications=0,performance_credit=False))
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);value=fact(p)
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        pins[str(p)]=value;aliases[str(alias)]=str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=PROFILES[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)

    def compile_subject():
        fixture=SELECTED/'tests/persistent_interpreter_loop_app'
        output=private/'application';output.mkdir()
        script=pin(fixture/'extract.py');interpreter=pin(args.interpreter)
        # The source-owned assembly extractor and an independent complete ELF
        # extraction must agree before the actual compiler consumes any bytes.
        expected=private/'expected-pair.bin';extract(interpreter,expected);binary(expected)
        run('app-extract',[builder.tools['python'],'-I','-B',script,interpreter,output],env=builder.environment)
        pair=binary(output/'interpreter-pair.bin');pin(pair)
        need(pair.read_bytes()==expected.read_bytes(),'whole independently extracted interpreter pair')
        generated=pin(binary(output/'pair.S'))
        script=pin(fixture/'build.sh');linker=pin(fixture/'pure.ld')
        rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual application recipe')
        argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':fixture,'$output':output})
        units=[str(pin(fixture/n))for n in ('main.c','pure.c','machine.S')]+[str(generated)]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and
             argv[-2:]==['-o',str(output/'persistent-interpreter-loop-app')] and
             '-Wl,-T,'+str(linker) in argv and '-DLI2_FAST_EQUAL=1' in argv and
             all(f in argv for f in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only',
                 '-mcmodel=large','-fno-pie','-no-pie','-fno-builtin','-fno-strict-aliasing')),
             'exact whole source and no-FP full-range release recipe')
        state=r['application_build']=dict(recipe=fact(script),argv=argv,pair=fact(pair),
            interpreter=fact(interpreter),linker=fact(linker),qualification_credit=False)
        flags=[x for x in argv[1:-2] if x not in units and not x.startswith('-Wl,')]
        _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*units],env=builder.environment)
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==4 and all(x.startswith('li2_app: ') for x in rules),
             'one complete include rule for each actual application translation unit')
        includes={}
        for rule in rules:
            for name in shlex.split(rule.split(':',1)[1]):
                path=Path(name).absolute();resolved=str(pin(path));aliases[str(path)]=resolved
                includes[resolved]=fact(resolved)
        need(set(units)|{str(fixture/'app.h')}<=set(includes),'all actual source/header inputs')
        state['headers']=includes
        _,out,err=run('app-link',argv,profile='release_build',env=builder.environment)
        need(out==err==b'','strict actual application build')
        image=binary(argv[-1]);state['artifact']=fact(image)
        return inspect_application(builder,private,pin,binary,run,state,image,units)

    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean revision')
        # Freeze all tracked implementation and reader inputs before imports or launch.
        _,names,err=run('tracked-input-list',['git','ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err, 'complete tracked input list')
        for raw in names.split(b'\0'):
            if raw:
                name=os.fsdecode(raw)
                if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        products=builder.prepare()
        original=compile_subject()
        cohort(builder,products,private,pin,binary,aliases,run,r,original)
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            closure()
            need(source() == r['source'], 'exact source unchanged')
            r['source_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['inputs'] = pins
        r['artifacts'] = artifacts
        save(receipt, r)
        summary = {k: r[k] for k in ('schema', 'status', 'revision', 'source', 'source_unchanged',
            'cleanup_complete', 'hardware', 'bounds', 'scope')}
        summary['cases']=[{k:c[k] for k in ('lane','mode','status','expected_exit','exit','whole_process_ns',
            'timed_out','launched','captures','pair','owner_summary','error_type') if k in c} for c in r['cases']]
        for compact,actual in zip(summary['cases'],r['cases'],strict=True):
            compact['controls']={name:dict(count=len(actual[name]['refusals']),
                sha256=hashlib.sha256(json.dumps(actual[name],sort_keys=True,separators=(',',':')).encode()).hexdigest())
                for name in ('application_controls','owner_reader_controls','pair_controls',
                             'terminal_controls','repeat_tls_controls','native_probe_controls') if name in actual}
        summary['copy_oracle']={k:r.get('application_build',{}).get('copy_oracle',{}).get(k)
            for k in ('status','counts','body','exit','duration_ns')}
        summary['closure']=dict(inputs=len(pins),artifacts=len(artifacts),commands=len(r['commands']),
            captures=sum(len(c.get('captures',{})) for c in r['commands']),final_error_count=len(r['final_errors']))
        summary.update(receipt=fact(receipt), application=r.get('application_build',{}).get('artifact'),
            reproduce=['python3', 'evaluation/inprocess/startup_loop.py', '--expect-revision', args.expect_revision,
                       '--interpreter', 'REFERENCE_INTERPRETER'],
            tool_versions=builder.record.get('numeric_versions'), error_type=r['error'].split(':', 1)[0] if r['error'] else None,
            commands=[{k: c.get(k) for k in ('name', 'exit', 'duration_ns', 'timed_out', 'reaped')}
                      for c in r['commands']])
        payload = (json.dumps(summary, sort_keys=True)+'\n').encode()
        need(len(payload) <= 32768 and b'/home/' not in payload, 'compact public receipt without host paths')
        public.write_bytes(payload)
        with public.with_suffix('.csv').open('w', newline='') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
            for c in r['commands']:
                w.writerow((args.expect_revision, c['name'], c.get('exit'), c.get('duration_ns'), r['status']))
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
