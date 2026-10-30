#!/usr/bin/env python3
"""Explicit fixed E9 production OR output execution; never LiteInst dispatch.

Run under the existing external command owner. The caller pins this source and
an actual completed preparation plan. `outputs` is a separate selected native
execution action, requiring exact production and independently admitted N01
closure hashes. Structural acceptance alone never selects that phase.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import types

MIB = 1048576
SOURCES = {
    'prepare': ('evaluation/offline-corpus/full_startup_e9.py', 'c3b4a4bb09bb428105e037d72733d76990bcaf524cfa25b029a7bb5b9e028666'),
    'custody': ('evaluation/adjacent-b2/artifact-verifier/startup_custody.py', '6c236204101fb5950f955eb0540a51756bcf27d0a09860a9feab5f041d51f8c5'),
    'collector': ('evaluation/offline-corpus/adjacent_whole.py', 'b8e61360056220b1e2a60f93f32844b36e483d08a354bccbf6b03f1a8288c4a3'),
    'n01': ('evaluation/offline-router-native/n01.py', '0f09b1ea2bb211f94d709d99c759abc90ed1fa51da567b6470220f731c87fe56'),
    'corpus': ('evaluation/offline-corpus/corpus.py', '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07'),
    'adapter': ('tools/elf-rewrite/e9-sites.py', 'c53543d226f89437c8dc8912c55f67b604486683a09eed923a25f723f83e8db9'),
    'compare': ('tools/elf-rewrite/compare-sites.py', '797b396392ec3459a21a37f4a41b15a47b9f478dfe92c5d2cf436041d282876f')}
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CONTROL = ('request.json', 'command.json', 'parent-closed.json', 'receipt.json',
           'stdout.txt', 'stderr.txt', 'helper.stdout', 'helper.stderr')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'


def write(path, value, mode=0o600):
    raw = value if type(value) is bytes else encode(value)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)


def request_command(root, directory, argv, env, tools):
    """Exact existing request_and_command/invoke schema and fixed limits."""
    request = dict(argv=argv, cwd=str(root), env=env, cpu_seconds=20, wall_seconds=30,
        file_bytes=16*MIB, stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'))
    command = dict(argv=[tools['timeout']['path'], '--signal=TERM', '--kill-after=10s', '40s',
        tools['python']['path'], '-B', tools['helper']['path'], '--request', str(directory/'request.json'),
        '--receipt', str(directory/'receipt.json')], cwd=str(root), env=env, parent_seconds=55, cleanup_seconds=10)
    return request, command


def source_revision(value):
    need(re.fullmatch('[0-9a-f]{40}', value) is not None, 'exact 40-hex source revision')
    return value


def arguments(argv=None):
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('phase', choices=('produce', 'outputs'))
    p.add_argument('--source-revision', type=source_revision, required=True)
    for name in ('root', 'plan'):
        p.add_argument('--'+name, type=Path, required=True)
    for name in ('plan-sha256', 'executor-sha256'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--production-sha256')
    p.add_argument('--n01-closed', type=Path)
    p.add_argument('--n01-closed-sha256')
    values = list(sys.argv[1:] if argv is None else argv)
    options = [v.split('=',1)[0] for v in values if v.startswith('--')]
    need(len(options) == len(set(options)), 'no repeated option')
    a = p.parse_args(values)
    extras = (a.production_sha256, a.n01_closed, a.n01_closed_sha256)
    need(all(v is None for v in extras) if a.phase == 'produce' else all(v is not None for v in extras),
         'outputs requires all three actual result inputs; produce accepts none')
    return a


class Inputs:
    """Existing custody and readers; no new process owner or authority class."""
    def __init__(self, args):
        self.root = args.root; self.directory = args.plan.parent
        self.source_revision = args.source_revision
        need(self.root.is_absolute() and self.root.resolve(strict=True) == self.root
             and Path.cwd() == self.root, 'canonical source root/current directory')
        need(args.plan.name == 'plan.json' and self.directory.is_relative_to(self.root/'ignored')
             and self.directory.resolve(strict=True) == self.directory, 'actual private preparation plan')
        # Authenticate the first existing reader without importing unpinned bytes.
        path = self.root/SOURCES['prepare'][0]
        raw = path.read_bytes(); need(len(raw) <= MIB and sha(raw) == SOURCES['prepare'][1], 'initial preparer source')
        prepare = types.ModuleType('_e9_prepare'); prepare.__file__ = str(path)
        exec(compile(raw, str(path), 'exec'), prepare.__dict__)
        self.m = {'prepare': prepare}
        for role, (relative, digest) in SOURCES.items():
            if role != 'prepare': self.m[role] = prepare.module(self.root/relative, digest)
        self.store = self.m['custody'].Store(2*1024*MIB)
        self.readers = []; self.members = []
        for relative, digest in SOURCES.values():
            need(sha(self.store.read(self.root/relative, MIB)) == digest, 'pinned executor dependency')
        need(sha(self.store.read(Path(__file__).absolute(), MIB)) == args.executor_sha256, 'externally pinned executor')
        self.plan_raw = self.store.read(args.plan, MIB)
        need(sha(self.plan_raw) == args.plan_sha256, 'external preparation plan hash')
        self.plan = self.m['adapter'].loads(self.plan_raw)
        self.reference = dict(path=str(args.plan), sha256=args.plan_sha256)
        self.tools = self.plan['execution_tools']
        self.validate_plan()

    def read(self, path, cap=16*MIB):
        return self.store.read(Path(path), cap)

    def value(self, path, digest=None):
        raw = self.read(path, MIB)
        need(digest is None or sha(raw) == digest, 'exact saved result hash')
        return self.m['adapter'].loads(raw)

    def stable(self):
        self.store.verify()
        for reader in self.readers: reader.verify()
        for path, record in self.members:
            need(self.store.members(path) == record, 'closed command directory changed')

    def close(self):
        errors = []
        for owner in [*self.readers, self.store]:
            try: owner.close()
            except BaseException as error: errors.append(str(error))
        need(not errors, 'owner close: '+repr(errors))

    def retain_command(self, directory):
        record = self.store.members(directory)
        expected = sorted(CONTROL)
        need(record['members'] == expected, 'whole exact raw command closure: actual='
             + repr(record['members']) + ' expected=' + repr(expected))
        self.members.append((directory, record))

    def validate_plan(self):
        f, a, corpus, p = self.m['prepare'], self.m['adapter'], self.m['corpus'], self.plan
        need(p['profile'] == f.PROFILE and p['source_revision'] == self.source_revision
             and tuple(p['programs']) == f.PROGRAMS, 'current full-startup source and both programs')
        need(p['source'] == dict(adapter=dict(path=str(self.root/SOURCES['adapter'][0]), sha256=SOURCES['adapter'][1]),
            comparator=dict(path=str(self.root/SOURCES['compare'][0]), sha256=SOURCES['compare'][1]),
            preparer_sha256=SOURCES['prepare'][1], corpus_sha256=SOURCES['corpus'][1]), 'exact prepared source dispatch')
        need(all(p[key] is False for key in ('qualification_complete', 'application_outputs_checked',
             'native_execution_authorized', 'performance_eligible')), 'preparation is not native authority')
        need(set(self.tools) == {'python', 'timeout', 'helper'}
             and self.tools['helper']['sha256'] == self.m['n01'].HELPER_SHA
             and self.tools['helper']['path'] == str(self.root/'tools/unwind-oracle/bounded_command.py'), 'unchanged execution tools')
        need(set(p['tools']) == {role for roles in f.E9.values() for role in roles}, 'exact E9 tools')
        for pin in [*self.tools.values(), *p['tools'].values()]: self.store.read(pin['path'], 16*MIB, pin)
        for lane, roles in f.E9.items():
            need(tuple(p['tools'][r]['sha256'] for r in roles) == a.PRODUCERS[lane], 'exact E9 lane bytes')
        ref = p['main_joins']; self.value(Path(ref['directory'])/'closed.json', ref['sha256'])
        for pin in p['retained_history']: self.store.read(pin['path'], 16*MIB, pin)
        commands, rows = [], []
        for program in f.PROGRAMS:
            info = p['programs'][program]; folder = self.directory/program
            need((info['heads'], info['selected']) == f.COUNTS[program], 'complete 187-head/42-site denominator')
            originals = {role:self.read(folder/file) for role,file in
                (('original','original.elf'),('selection','selection.txt'),('report','report.tsv'),('policy','policy.json'))}
            for role, raw in originals.items(): need(sha(raw) == info[role+'_sha256'], 'prepared whole input identity')
            sites, _ = a.selection_absolute_startup(originals['selection'], originals['original'], originals['policy'])
            need(len(sites) == info['selected'], 'complete selected geometry')
            common = ['--action=asm=j.*:passthru', '--executable', '--compression=9', '--start=0x401000', '--end=0x403001']
            for lane, roles in f.E9.items():
                base = folder/lane
                for phase, argv in (
                    ('transport', [p['tools']['transport_frontend']['path'], *common, '--format=json', '--output=-', str(folder/'original.elf')]),
                    ('producer', [p['tools'][roles[0]]['path'], *common, '--format=binary', '--output='+str(base/'candidate.elf'),
                        '--backend='+p['tools'][roles[1]]['path'], '--option=--debug', str(folder/'original.elf')])):
                    row = dict(program=program, lane=lane, phase=phase, directory=str(base/phase), argv=argv, limits=[20,30,16], attempts=1)
                    commands.append(row)
                    req, cmd = request_command(self.root, base/phase, argv, ENV, self.tools)
                    need(self.read(base/phase/'request.json', MIB) == encode(req)
                         and self.read(base/phase/'command.json', MIB) == encode(cmd), 'whole prepared request/command bytes')
            for name, data in corpus.datasets().items():
                want = corpus.expected(program, data)
                need(self.read(self.directory/'datasets'/name, 65536) == data
                     and self.read(folder/'expected'/name, 196616) == want, 'all exact datasets/expected outputs')
                for lane in f.LANES:
                    rows.append(dict(program=program, dataset=name, lane=lane, status='UNRUN', attempts=0,
                        input_sha256=sha(data), expected_sha256=sha(want), selected_sites=info['selected']))
        need(commands == p['commands'] and len(commands) == 8 and rows == p['cases'] and len(rows) == 80,
             'fixed whole commands/population; no substitutions or subsets')
        self.stable()


def invoke(inputs, directory, argv, env, *, cwd, prepared=False):
    """Use the existing collector; prepared writes must equal frozen bytes."""
    expected = request_command(cwd, directory, argv, env, inputs.tools)
    def checked_write(path, value):
        if prepared and Path(path).name in ('request.json', 'command.json'):
            need(inputs.read(path, MIB) == encode(value), 'prepared request mutation')
        else: write(path, value)
    ctx = types.SimpleNamespace(ROOT=cwd, B=types.SimpleNamespace(write=checked_write))
    got = inputs.m['collector'].invoke(ctx, directory, argv, env, inputs.tools)
    need(got == expected, 'existing command invocation schema')
    return got


def structural(inputs, program, lane, *, publish):
    f, adapter, compare = (inputs.m[x] for x in ('prepare', 'adapter', 'compare'))
    folder = inputs.directory/program/lane
    envelope = f.envelope(inputs.plan, inputs.directory, program, lane, adapter, inputs.store)
    envelope_raw = encode(envelope)
    blobs = {role:inputs.read(row['path']) for role,row in envelope['files'].items()}
    tsv, binding = adapter._validate(envelope, blobs, f.PROFILE)
    binding.update(envelope_sha256=sha(envelope_raw), input_files=envelope['files'],
        input_owners={role:inputs.store.pin(Path(row['path']),16*MIB)['stat'] for role,row in envelope['files'].items()})
    manifest = inputs.read(inputs.directory/program/'selection.txt')
    report = inputs.read(inputs.directory/program/'report.tsv')
    policy = inputs.read(inputs.directory/program/'policy.json')
    result = compare.compare(manifest, report.decode(), tsv.decode(), policy, inputs.plan['programs'][program]['policy_sha256'])
    result['input_sha256'] = [sha(x) for x in (manifest, report, tsv)]
    files = {'envelope.json':envelope_raw, 'inventory/sites.tsv':tsv,
             'inventory/producer-binding.json':encode(binding), 'comparison.json':encode(result)}
    inputs.stable()
    if publish: (folder/'inventory').mkdir(mode=0o700)
    for name, raw in files.items():
        if publish: write(folder/name, raw)
        need(inputs.read(folder/name) == raw, 'reconstructed real structural artifact')
    need(not result['lost_e9_trampoline_sites'], 'unchanged comparator: lost E9 trampoline site')
    return dict(program=program, lane=lane, status='PASS', files={n:sha(b) for n,b in files.items()},
                candidate=inputs.store.pin(folder/'candidate.elf',16*MIB), selected_sites=result['selected_sites'])


def production_ready(inputs):
    for row in inputs.plan['commands']:
        folder = Path(row['directory'])
        need(inputs.store.members(folder)['members'] == ['command.json','request.json'], 'one attempt; command must be unrun')
    for program in inputs.m['prepare'].PROGRAMS:
        for lane in inputs.m['prepare'].E9:
            folder = inputs.directory/program/lane
            need(not any(os.path.lexists(folder/name) for name in ('candidate.elf','inventory','envelope.json','comparison.json')),
                 'fresh entire production population')


def produce(inputs, result):
    result['commands'] = [dict(row, status='UNRUN', attempted=False) for row in inputs.plan['commands']]
    result['products'] = [dict(program=p,lane=l,status='UNRUN') for p in inputs.m['prepare'].PROGRAMS for l in inputs.m['prepare'].E9]
    for row in result['commands']:
        inputs.stable(); row.update(status='FAILED', attempted=True)
        folder = Path(row['directory'])
        req, cmd = invoke(inputs, folder, row['argv'], ENV, cwd=inputs.root, prepared=True)
        code, _ = inputs.m['custody'].closed(inputs.store, folder, req, cmd, inputs.tools['helper']['sha256'])
        row.update(exit=code, closure_complete=True)
        inputs.retain_command(folder); inputs.stable()
        row.update(status='PASS' if code == 0 else 'FAILED')
        need(code >= 0, 'signal termination stops fixed production campaign')
    for row in result['products']:
        pair = [r for r in result['commands'] if (r['program'],r['lane']) == (row['program'],row['lane'])]
        if any(r['status'] != 'PASS' for r in pair):
            row.update(status='FAILED', reason='actual tool failure; no inventory claimed'); continue
        try: row.update(structural(inputs, row['program'], row['lane'], publish=True))
        except (ValueError, AssertionError, OSError, UnicodeError) as error:
            row.update(status='FAILED', reason=type(error).__name__+': '+str(error))
        inputs.stable()
    result['structural_complete'] = all(r['status'] == 'PASS' for r in result['products'])


def checked_production(inputs, digest):
    previous = inputs.value(inputs.directory/'production.json', digest)
    need(previous['plan'] == inputs.reference and previous['error'] is None and previous['structural_complete'] is True,
         'actual completed whole production')
    need(previous['cases'] == inputs.plan['cases'], 'production never executes application cases')
    need(len(previous['commands']) == 8 and len(previous['products']) == 4, 'whole saved production')
    for row, actual in zip(inputs.plan['commands'], previous['commands']):
        need(all(actual[k] == v for k,v in row.items()) and actual['status'] == 'PASS'
             and actual['attempted'] is True and actual['closure_complete'] is True and actual['exit'] == 0, 'exact actual tool result')
        folder = Path(row['directory']); req, cmd = request_command(inputs.root,folder,row['argv'],ENV,inputs.tools)
        code, _ = inputs.m['custody'].closed(inputs.store,folder,req,cmd,inputs.tools['helper']['sha256'])
        need(code == 0, 'saved raw tool success'); inputs.retain_command(folder)
    for row,(p,l) in zip(previous['products'],((p,l) for p in inputs.m['prepare'].PROGRAMS for l in inputs.m['prepare'].E9)):
        need(row == structural(inputs,p,l,publish=False), 'exact saved four products')
    inputs.stable()


def joined_n01(inputs, closed_path, digest, rows):
    n, collector, f = (inputs.m[x] for x in ('n01','collector','prepare'))
    need(closed_path.name == 'closed.json' and closed_path.parent.is_relative_to(inputs.root/'ignored'), 'actual private N01 closure')
    directory = closed_path.parent; closed = inputs.value(closed_path,digest)
    saved = {name:inputs.value(directory/(name+'.json'),closed[name+'_sha256']) for name in ('summary','invocations','pairs')}
    summary, native = saved['summary'], saved['invocations']
    need(len(native) == 40 and saved['pairs'] == n.pairs(native), 'all twenty independently admitted pairs')
    need(summary['profile'] == 'offline-router-N01-full-output-v1' and summary['invocation_count'] == 40
         and summary['pair_count'] == 20 and all(summary[k] == 0 for k in ('producer_dispatches','build_dispatches','ptrace_dispatches')),
         'ordinary complete N01 population')
    ref = summary['final_profile']; profile = inputs.value(Path(ref['path']),ref['sha256'])
    need(inputs.value(directory/'final-profile.json') == ref
         and profile['arguments']['main_joins'] == inputs.plan['main_joins']['directory']
         and profile['arguments']['main_joins_sha256'] == inputs.plan['main_joins']['sha256']
         and profile['native_sources'][SOURCES['n01'][0]] == SOURCES['n01'][1], 'same independently admitted current mains and N01 source')
    need(all(summary[k] is False for k in ('qualification_complete','performance_eligible','route_coverage_complete'))
         and closed['performance_eligible'] is False, 'no promotion of N01 scope')
    readers = {p:collector.OutputReader(directory/p) for p in f.PROGRAMS}; inputs.readers.extend(readers.values())
    baselines = {}; by_key = {(r['program'],r['dataset'],r['lane']):r for r in rows}
    for p in f.PROGRAMS:
        for lane,key in (('original','original_sha256'),('candidate','candidate_sha256')):
            need(sha(inputs.read(directory/p/('run-'+lane))) == inputs.plan['programs'][p][key], 'exact independently admitted executable bytes')
    # Keep original failure labels before checking any individual raw closure.
    for record in native:
        lane = 'native' if record['lane'] == 'original' else 'liteinst'
        target = by_key[record['program'],record['dataset'],lane]
        target['recorded_n01_status'] = record['status']
        target['recorded_n01_reason'] = record['reason']
        if record['status'] == 'FAILED':
            target.update(status='FAILED', attempts=int(record['attempted']))
    need(summary['fatal'] is None and summary['attempted'] == 40, 'N01 has a complete terminal population')
    for record in native:
        p,d,lane = record['program'],record['dataset'],record['lane']; row = by_key[p,d,'native' if lane=='original' else 'liteinst']
        need(record['attempted'] is True and record['closure_complete'] is True and record['status'] in ('PASS','FAILED'), 'actual closed N01 invocation')
        folder = directory/p/(d+'-'+lane); command_dir = folder/'importer'
        data = inputs.read(inputs.directory/'datasets'/d,65536); want = inputs.read(inputs.directory/p/'expected'/d,196616)
        need(inputs.read(directory/'datasets'/d,65536) == data and inputs.read(directory/p/'expected'/d,196616) == want,
             'N01 exact dataset/expected bytes')
        req,cmd = request_command(folder,command_dir,[str(directory/p/('run-'+lane)),str(directory/'datasets'/d)],{},inputs.tools)
        code,actual,stderr = n.completed(collector,n.PrefixReader(readers[p],d+'-'+lane),req,cmd)
        need(code >= 0, 'N01 signal termination is not a semantic success')
        good = n.compare_output(code,actual,stderr,want,candidate=lane=='candidate',original=baselines.get((p,d)))
        need(record['status'] == ('PASS' if good else 'FAILED') and record['exit'] == code
             and record['actual_sha256'] == sha(actual) and record['stderr_sha256'] == sha(stderr)
             and record['input_sha256'] == sha(data) and record['expected_sha256'] == sha(want)
             and record['output_bytes'] == len(actual), 'exact N01 status and full output reconstruction')
        row.update(status=record['status'],attempts=1,exit=code,actual_sha256=sha(actual),stderr_sha256=sha(stderr),
                   output_bytes=len(actual),closure_complete=True)
        if lane == 'original' and good: baselines[p,d] = actual
        inputs.retain_command(command_dir)
    need(summary['counts'] == {s:sum(r['status']==s for r in native) for s in ('PASS','FAILED','UNRUN')}
         and summary['native_correctness_complete'] == closed['native_correctness_complete'] == all(r['status']=='PASS' for r in native),
         'exact saved aggregate; no failure relabel')
    inputs.stable(); return baselines


def outputs(inputs, args, result, destination):
    checked_production(inputs,args.production_sha256)
    result['structural_complete'] = True
    baselines = joined_n01(inputs,args.n01_closed,args.n01_closed_sha256,result['cases'])
    n, collector, f = (inputs.m[x] for x in ('n01','collector','prepare'))
    runnable = {}; readers = {}
    for p in f.PROGRAMS:
        folder = destination/p; folder.mkdir(mode=0o700)
        readers[p] = collector.OutputReader(folder); inputs.readers.append(readers[p])
        for lane in f.E9:
            path = folder/('run-'+lane); write(path,inputs.read(inputs.directory/p/lane/'candidate.elf'),0o700)
            inputs.store.pin(path,16*MIB); runnable[p,lane] = path
    for row in result['cases']:
        p,d,lane = row['program'],row['dataset'],row['lane']
        if lane not in f.E9: continue  # Those forty rows were reconstructed above, never redispatched.
        inputs.stable()
        need(not signal.pthread_sigmask(signal.SIG_BLOCK,[]), 'unchanged empty child signal mask')
        restored = {getattr(signal,name) for name in ('SIGPIPE','SIGXFZ','SIGXFSZ') if hasattr(signal,name)}
        need(all(signal.getsignal(sig) != signal.SIG_IGN for sig in signal.valid_signals() if sig not in restored), 'no ignored inherited signal')
        folder = destination/p/(d+'-'+lane); folder.mkdir(mode=0o700); importer = folder/'importer'; importer.mkdir(mode=0o700)
        row.update(status='FAILED',attempts=1,reason='invocation or checks incomplete')
        req,cmd = invoke(inputs,importer,[str(runnable[p,lane]),str(inputs.directory/'datasets'/d)],{},cwd=folder)
        code,actual,stderr = n.completed(collector,n.PrefixReader(readers[p],d+'-'+lane),req,cmd)
        row.update(exit=code,actual_sha256=sha(actual),stderr_sha256=sha(stderr),output_bytes=len(actual),closure_complete=True)
        need(code >= 0, 'signal termination stops fixed output campaign')
        want = inputs.read(inputs.directory/p/'expected'/d,196616)
        good = n.compare_output(code,actual,stderr,want,candidate=True,original=baselines.get((p,d)))
        inputs.retain_command(importer); inputs.stable()
        row.update(status='PASS' if good else 'FAILED',exit=code,actual_sha256=sha(actual),stderr_sha256=sha(stderr),
            output_bytes=len(actual),closure_complete=True,reason=None if good else 'exact expected/empty stderr/exit0/successful original equality failed')
    result['application_outputs_checked'] = all(r['status']=='PASS' for r in result['cases'])


def main(argv=None):
    args = arguments(argv); need(not sys.flags.optimize, 'assertions required')
    inputs = Inputs(args)
    result = dict(plan=inputs.reference, phase=args.phase, source_revision=args.source_revision,
        provenance=dict(source_revision=args.source_revision, executor_sha256=args.executor_sha256, sources={p:h for p,h in SOURCES.values()}),
        cases=copy.deepcopy(inputs.plan['cases']), retained_history=inputs.plan['retained_history'],
        structural_complete=False, application_outputs_checked=False, qualification_complete=False,
        architectural_full_state=False, performance_eligible=False, error=None)
    destination = inputs.directory if args.phase == 'produce' else inputs.directory/'outputs'
    summary = destination/('production.json' if args.phase=='produce' else 'summary.json')
    owned = False
    try:
        if args.phase == 'produce':
            need(not os.path.lexists(summary) and not os.path.lexists(destination/'production-started.json'), 'one whole production attempt')
            production_ready(inputs)
            # Atomic owned claim: a refused pre-existing tree receives no writes.
            write(destination/'production-started.json',result['provenance'])
            owned = True; produce(inputs,result)
        else:
            need(not os.path.lexists(destination), 'one whole output attempt')
            destination.mkdir(mode=0o700); owned = True
            result['production_sha256'] = args.production_sha256
            result['n01'] = dict(path=str(args.n01_closed),sha256=args.n01_closed_sha256)
            outputs(inputs,args,result,destination)
        inputs.stable()
    except BaseException as error:
        result['error'] = type(error).__name__+': '+str(error)
    finally:
        try: inputs.stable()
        except BaseException as error: result['error'] = (result['error'] or '')+'; final stability: '+str(error)
        try: inputs.close()
        except BaseException as error: result['error'] = (result['error'] or '')+'; close: '+str(error)
        if result['error'] is not None:
            result['structural_complete'] = result['application_outputs_checked'] = False
        if owned:
            result['new_e9_invocations'] = sum(r['attempts'] for r in result['cases'] if r['lane'] in inputs.m['prepare'].E9)
            result['joined_n01_invocations'] = sum(r['attempts'] for r in result['cases'] if r['lane'] not in inputs.m['prepare'].E9)
            result['counts'] = {s:sum(r['status']==s for r in result['cases']) for s in ('PASS','FAILED','UNRUN')}
            write(summary,result)
    good = result['structural_complete'] if args.phase=='produce' else result['application_outputs_checked']
    return 0 if good and result['error'] is None else 1


if __name__ == '__main__':
    raise SystemExit(main())
