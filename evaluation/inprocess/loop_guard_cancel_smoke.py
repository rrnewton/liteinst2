#!/usr/bin/env python3
"""Six-command case0/placement0 runtime diagnostic; no owner qualification."""
import argparse, hashlib, json, os, platform, re, subprocess, sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import imported_sources
from direct_frontier_loop_helpers import prepare_inputs
from persistent_loop_native_build import preparation
from persistent_loop_counter_terminal import split
from persistent_fused_counter_terminal import counters

SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = [30, 512 << 20, 16 << 20, 60]
LANES = (('maintained', 'capture'), ('differential', 'differential'))
H = lambda b: hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    for n in ('native-receipt', 'prior-command'):
        ap.add_argument('--'+n, type=Path, required=True); ap.add_argument('--'+n+'-sha256', required=True)
    a = ap.parse_args(); affinity = os.sched_getaffinity(0)
    need(not sys.flags.optimize and sys.version_info[:2] == (3,12) and len(affinity) == 1 and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision), 'assertions, Python3.12, exact revision and reserved singleton')
    cpu = next(iter(affinity)); private = a.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct-child output')
    private.mkdir(); pins, aliases, artifacts = {}, {}, {}
    r = dict(schema=1, profile='loop-guard-cancel-smoke-v1', status='failed', revision=a.expect_revision,
        cpu=cpu, hardware=hardware(cpu), argv=[sys.executable,'-B',*sys.argv], bounds=BOUNDS,
        source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        commands=[], lanes=[], namespace_aliases={}, error=None, final_errors=[],
        owner_credit=False, qualification_credit=False, performance_credit=False)
    def pin(path):
        lexical = Path(path).absolute(); p = lexical.resolve(strict=True); value = fact(p)
        need(p.is_file() and (str(p) not in pins or pins[str(p)] == value), 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p
    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact bytes/mode')
        artifacts[str(p)] = value; return p
    def guard():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same clean whole source and CPU')
        need(all(fact(p) == v for p,v in pins.items()) and
             all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'whole inputs and aliases unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode & 0o777) == v for p,v in artifacts.items()), 'whole artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p,v in r['namespace_aliases'].items()), 'namespace aliases unchanged')
    def run(name, argv, profile='release_build', expected=0, env=None, record=False):
        guard(); need(len(r['commands']) < 6 and expected == 0, 'six fixed commands, expected exit zero')
        row = dict(name=name, argv=list(map(str,argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS, capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if record else invoke)(row, private, cpu, record=record)
            if not record: need(row['exit'] == 0, 'actual build/carrier exit zero')
            return row, out, err
        finally:
            save(private/'receipt.json',r)
            print(json.dumps(dict(command=name,exit=row.get('exit'),timed_out=row.get('timed_out'))),flush=True)
    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean checkout')
        pin(__file__); imported_sources(pin)
        names = subprocess.check_output(['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false',
            'ls-files','-z','tools/page-entry','evaluation/inprocess'],cwd=ROOT)
        for n in names.split(b'\0'):
            if n and not n.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(n))
        native_path = pin(a.native_receipt); prior_path = pin(a.prior_command)
        need(fact(native_path)['sha256'] == a.native_receipt_sha256 and fact(prior_path)['sha256'] == a.prior_command_sha256,
             'exact closed native owner and original failed command')
        n = json.loads(native_path.read_bytes()); prior = json.loads(prior_path.read_bytes())
        need(n['profile'] == 'persistent-loop-native-v2' and n['status'] == 'observed_native_references' and
             n['source_unchanged'] is n['inputs_unchanged'] is n['cleanup_complete'] is True and
             n['error'] is None and n['final_errors'] == [], 'closed native inputs; no current-head native credit')
        b = n['build']; app = n['application_build']; archive = binary(b['artifacts']['decoder.a']['path'])
        original = binary(app['argv'][-1]); interp = binary(app['interpreter']['path'])
        need(b['status'] == app['status'] == 'passed' and b['command_completed'] is True and len(b['dep_info']) == 11 and
             archive == native_path.parent/'artifacts/decoder.a' and archive.read_bytes()[:8] == b'!<arch>\n' and
             b['decoder_features'] == ['scalar-region','scalar-span','linked-epoch','mov-guard','scalar-read'], 'actual eleven-source scalar-read archive')
        for p,v in b['dep_info'].items(): need(fact(pin(ROOT/p)) == v, 'whole current decoder sources equal reused archive inputs')
        for mapping in (app['headers'],app['interpreter_headers']):
            for p,v in mapping.items(): need(fact(pin(p)) == v, 'whole original fixture compiler inputs unchanged')
        need(fact(pin(SELECTED/'tests/tunables_loop_paired_app/build.sh')) == app['recipe'] and
             fact(pin(SELECTED/'tests/persistent_direct_frontier_app/app.ld')) == app['linker'], 'unchanged actual fixture recipe and linker source')
        for p,v in ((archive,b['artifacts']['decoder.a']),(original,app['artifact']),(interp,app['interpreter'])):
            need(fact(p) == {k:v[k] for k in ('bytes','sha256')} and artifacts[str(p)] == n['artifacts'][str(p)], 'native receipt joins actual retained product')
        tools = {}
        for k in ('sh','cc','cc1','collect2','as','ld','python'):
            v = b['tools'][k]; tools[k] = pin(v['path']); need(fact(tools[k]) == {q:v[q] for q in ('bytes','sha256')}, 'same actual tool '+k)
        need(Path(sys.executable).resolve() == tools['python'], 'same actual Python tool')
        r['reused_inputs'] = dict(native_receipt=fact(native_path), native_revision=n['revision'], native_cpu=n['cpu'],
            archive=fact(archive), original=fact(original), interpreter=fact(interp), prior_command=fact(prior_path),
            prior_exit=prior['exit'], prior_expected_exit=prior['expected_exit'], current_native_credit=False)
        launch = pin(SELECTED/'tests/tunables_loop_paired_app/launch.py'); olddir = prior_path.parent/'subject-maintained-0-0'
        oldargv = [str(tools['python']),'-B',str(launch),'--root',str(ROOT),'--role','gated','--case','0','--placement','0',
            '--control','0','--original',str(original),'--preparation',str(olddir/'preparation.json'),'--library-root',str(original.parent),
            '--carrier',str(prior_path.parent/'maintained-build/carrier'),'--namespace',str(olddir/'namespace'),'--record-fd',prior['argv'][-1]]
        need(prior['name'] == 'subject-maintained-0-0' and prior['argv'] == oldargv and prior['environment'] == ENV and
             prior['bounds'] == BOUNDS and prior['capture_limit'] == 16 << 20 and prior['expected_exit'] == 0 and prior['exit'] == 125 and
             prior['reaped'] is True and prior['timed_out'] is False and prior['error'] is None and prior['cleanup_errors'] == [] and
             all(d['closed'] is True for d in prior['descriptors']), 'whole original closed failed launch contract')
        environment = dict(ENV,LI2_CC=str(tools['cc']),LI2_PYTHON=str(tools['python']))
        for lane,mode in LANES:
            state = dict(lane=lane,status='failed',terminal=None,error=None); r['lanes'].append(state)
            directory = private/lane; directory.mkdir(); generated = directory/'build'; generated.mkdir()
            def lane_run(name,argv,profile='metadata',expected=0,env=None,record=False):
                return run(lane+'-'+name,argv,profile,expected,env,record)
            try:
                recipe = pin(SELECTED/('build-persistent-loop-'+mode+'.sh'))
                _,out,err = lane_run('build',[tools['sh'],recipe,archive,original,generated],env=environment)
                need(out == err == b'', 'strict actual recipe diagnostics')
                for p in generated.iterdir(): binary(p)
                bridge = binary(generated/('bridge-persistent-loop-'+mode+'.so'))
                _,roots,objects,description,_,_,carrier = prepare_inputs(original,bridge,SimpleNamespace(tools=tools),
                    directory,pin,binary,lane_run,state,app)
                subject = directory/'subject'; subject.mkdir(); argv = list(oldargv)
                for key,value in (('--carrier',carrier),('--namespace',subject/'namespace'),('--preparation',subject/'preparation.json'),('--record-fd','{record_fd}')):
                    argv[argv.index(key)+1] = str(value)
                row,out,err = run('subject-'+lane+'-0-0',argv,profile='program',record=True)
                preparation(dict(lane=1,mode=0,placement=0,control=0),row,subject,original,roots,objects,description,carrier,private,binary,r)
                loop,old = split(err); raw = counters(old); group = raw['LI2_PERSISTENT_UNREGISTERED']
                need(loop['status'] == group['status'] == row['exit'] and loop['failure_code'] == group['failure_code'], 'typed terminal outcome agrees with actual process exit')
                state['terminal'] = dict(loop={k:loop[k] for k in ('status','failure_code','route','scope','choice_complete')},
                    owner={k:group[k] for k in ('status','failure_code','detail_abs','detail_negative','phase','busy')})
                need(row['exit'] == 0 and loop['failure_code'] == group['detail_abs'] == group['detail_negative'] == 0, 'both diagnostic subjects must exit zero')
                state['status'] = 'exit_zero_diagnostic_only'
            except Exception as e: state['error'] = type(e).__name__+': '+str(e)
            guard(); need(all(x.get('reaped') is True and x.get('cleanup_errors') == [] and
                type(x.get('descriptors')) is list and
                all(d.get('closed') is True for d in x['descriptors']) for x in r['commands']), 'closed child and descriptors before next lane')
        need(len(r['commands']) == 6 and all(s['status'] == 'exit_zero_diagnostic_only' for s in r['lanes']), 'entire six-command diagnostic')
        r['status'] = 'exit_zero_diagnostic_only'
    except BaseException as e: r['error'] = type(e).__name__+': '+str(e)
    finally:
        try:
            imported_sources(pin); guard(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'whole retained command record')
                for c in row.get('captures',{}).values(): need(fact(binary(private/c['file'])) == {k:c[k] for k in ('bytes','sha256')}, 'whole retained capture')
        except BaseException as e: r['final_errors'].append(type(e).__name__+': '+str(e))
        r['cleanup_complete'] = all(x.get('reaped') is True and x.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in x.get('descriptors',[])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts); save(private/'receipt.json',r)
        public = {k:r[k] for k in ('schema','profile','status','revision','cpu','bounds','source_unchanged','inputs_unchanged','cleanup_complete','owner_credit','qualification_credit','performance_credit')}
        public.update(receipt=fact(private/'receipt.json'), reused_inputs=r.get('reused_inputs'),
            hardware={k:v for k,v in r['hardware'].items() if k not in ('isa_flags','runner_euid','runner_cap_eff')},
            isa_flags_sha256=H(json.dumps(r['hardware']['isa_flags'],separators=(',',':')).encode()),
            commands=[{k:x.get(k) for k in ('name','exit','timed_out','duration_ns','expected_exit')} for x in r['commands']],
            lanes=[{k:s[k] for k in ('lane','status','terminal')} for s in r['lanes']],
            reproduction_argv=['python3.12','-B','evaluation/inprocess/loop_guard_cancel_smoke.py',
                '--expect-revision',a.expect_revision,'--output','target/evaluation/inprocess/<fresh-smoke-output>',
                '--native-receipt','<retained-native-receipt.json>','--native-receipt-sha256',a.native_receipt_sha256,
                '--prior-command','<retained-prior-command.json>','--prior-command-sha256',a.prior_command_sha256],
            scope='Two runtime exits and typed reported terminal outcomes only; no full-state, cancellation, owner, qualification or timing credit.')
        public_text = json.dumps(public, indent=2, sort_keys=True)+'\n'
        need(len(public_text.encode()) <= 32 << 10 and all(not value or value not in public_text
            for value in (str(ROOT), str(Path.home()), '/home/', platform.node())), 'bounded public summary without host paths or hostname')
        save(private/'summary.json',public)
    print(json.dumps(dict(status=r['status'],receipt=str((private/'receipt.json').relative_to(ROOT)))),flush=True)
    return int(r['status'] != 'exit_zero_diagnostic_only')


if __name__ == '__main__': raise SystemExit(main())
