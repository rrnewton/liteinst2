#!/usr/bin/env python3
"""Offline PF reader regression only; never rerun or reclassify failed attempt 2.

Run under an externally reserved singleton CPU with --cpu N --output FRESH_DIRECTORY.
The retained subject CPU remains 3. This process may use another reserved CPU.
Only the authenticated pure native-policy classifier is loaded as native code.
No builder, evaluator main, reader_support, subprocess, or guest is invoked.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import struct
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BASE = ROOT / 'target/evaluation/inprocess/bounded-fused-owner-attempt-2'
TESTS = ROOT / 'tools/page-entry/selected/tests'
RECEIPT = dict(bytes=1796341, sha256='a8c62be68aee68ee52ffb21052316dcdb779ab5f22f30cd24558b634ed92db07')
INPUTS = {'bytes': 18620, 'sha256': '806ae653e3c38ba1b2645a6c63443bdeb4ebbbb2fe18d03a47845f2abf6a75f9'}
REVISION = '641b3af039ede26bfe343f8196583a73bb9935e9'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def normalized(value):
    return json.loads(json.dumps(value, sort_keys=True))


def population(value, count, original=None):
    names = value['refusals']
    need(type(names) is list and all(type(n) is str and n for n in names) and
         len(names) == len(set(names)) == count and
         type(value['native_operations']) is int and value['native_operations'] == 0,
         'exact unchanged supplied-control population')
    if original is not None:
        need(value['original_sha256'] == fact(original)['sha256'], 'whole original control input')
    return value


def historical_reader(relative, data):
    if relative == 'persistent_direct_frontier_owner/read.py':
        need(fact(data) == {'bytes': 156684, 'sha256': '16a3da5dd3f4da80af06add55205526dc4b04326a810b2a0412a318d7a041f83'}, 'whole current same-pair focal reader')
        lines = data.decode('utf-8').splitlines(keepends=True)
        result = []; at = 0
        for first, end, previous in [[639, 641, "            self.eq(peer,'li2_pgx_source',started=1)\n            members=self.r.items(view,'li2_pgd_view','member','li2_pgd_member')\n            for i,m in enumerate(members):\n"], [643, 658, "                payload=self.f(matches[0],'pdo_certificate','payload');cp=self.f(payload,'pe_payload','plan')\n                need(self.r.items(peer,'li2_pgx_source','table','li2_mg_table')[i]==self.f(cp,'li2_pg_compact','table'),'whole peer lease table equals actual immutable certificate table')\n                if i==1:self.key_identity(self.f(peer,'li2_pgx_source','key'),self.f(payload,'pe_payload','source'))\n"]]:
            need(at <= first <= end <= len(lines) and ''.join(lines[first:end]) != previous,
                 'ordered exact focal-reader inverse span')
            result.extend(lines[at:first]); result.append(previous); at = end
        data = ''.join(result + lines[at:]).encode('utf-8')
        need(fact(data) == {'bytes': 155896, 'sha256': 'b7826a043aaee74c530f2dcdd70152c05937810b12b127a15b395889c68e39ff'}, 'whole unchanged retained focal reader')
    if relative == 'persistent_direct_frontier_app/read.py':
        # This actual current reader was authenticated by take(). Reconstruct
        # only its unchanged retained endpoint before the existing whole join.
        need(fact(data) == {'bytes': 36830, 'sha256': 'ba86eca297742d95498b8f535276daccc278e67336f84fcb5906e06cc9bb6581'}, 'whole current direct reader')
        lines = data.decode('utf-8').splitlines(keepends=True)
        result = []; at = 0
        for first, end, previous in [
            [13, 22, ''],
            [161, 162, 'def reference_frame(data, prefix, layout, kind, steps, attempt):\n'],
            [177, 178, '    g = q(uc, 40, 23); pc = frame_pc(prefix,kind)\n'],
            [183, 184, '    expected = frame_state(prefix,kind)\n'],
            [185, 186, '    expected_flags=trace_model(prefix)[steps][2] | (RF if kind==0 else TF)\n'],
            [210, 211, 'def fixture(mode,image):\n'],
            [214, 216, '    seed[8]=2;seed[9]=1;seed[10]=1\n'],
            [227, 228, 'def trace_model(prefix):\n'],
            [233, 234, '    for _ in range(41):\n'],
            [261, 265, "def frame_pc(prefix,kind):\n    need(type(kind)is int and 0<=kind<len(STEPS),'one of12 explicitly retained native boundaries')\n    return trace_model(prefix)[STEPS[kind]][0]\n"],
            [266, 267, 'def frame_state(prefix,kind):return trace_model(prefix)[STEPS[kind]][1]\n'],
            [268, 269, 'def state(seed,data,mode):\n'],
            [270, 271, '    out=list(seed);out[0]+=9;out[1]=0;out[8]=1;out[10]=U64-1;return tuple(out)\n'],
            [276, 277, 'def _prefix(data,mode,native,image,pid,cpu,seed_reference):\n'],
            [279, 280, ''],
            [285, 286, "    need(h[:9]==(MAGIC,10,PREFIX,SUFFIX,mode,int(native),pid,pid,cpu)and h[9]<=0xffffffff and h[10:14]==(head,image['page'],DATA,STACK),'exact source/process/entry')\n"],
            [287, 288, "    need(h[30:]==(1,224,DATA+8192 if mode==1 else 0,8 if mode==1 else 0,frontier,predecessor,TRACES[mode],OBS,12,40,image['page']+0x2400,image['page']+PAGE,16384,RSEQ,0x53053053,image['page']+0x215,image['page']+0x3ffa,image['page']+0x241b),'exact cyclic fixture and reserved header')\n"],
            [296, 297, '    expected,want_data,want_stack=fixture(mode,image)\n'],
            [302, 303, 'def read(data,mode,native,exit_status,image,pid,cpu,seed_reference):\n'],
            [306, 308, '    r=_prefix(data[:PREFIX],mode,native,image,pid,cpu,seed_reference)\n'],
            [310, 311, "    need(end==(MAGIC^1,10,mode,int(native),0,1,1,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),2,1,0,0,0,0),'complete cleanup and collection-before-registration chronology')\n"],
            [319, 320, "    need(h==(1,0,12 if native else 0,TRACES[mode]if native else 0,int(mode==1),int(native),0,0,image['symbols']['region_app_capture_high'],0,0,0,0,0,0,0),'whole invocation header')\n"],
            [321, 322, "    need(after[0]==state(r['seed'][0],r['data'],mode)and after[1]==0x246,'all defined loop GPR and flag results')\n"],
            [329, 331, '            steps=STEPS[i]\n            frames.append(reference_frame(frame,r,image,kind,steps,0))\n'],
            [340, 341, 'def controls(data,mode,native,exit_status,image,pid,cpu,seed_reference):\n'],
            [343, 344, '    read(data,mode,native,exit_status,image,pid,cpu,seed_reference)\n'],
            [373, 374, '        try:read(bytes(mutant),mode,native,exit_status,image,pid,cpu,seed_reference)\n'],
            [377, 387, ''],
            [393, 394, "    need(native['header'][8:19]==gated['header'][8:19]and native['hardware']==gated['hardware']and all(native[k]==gated[k]for k in('seed','source','stack','data','rsp','predecessor')),'whole same-source/CPU/seed pair inputs')\n    need(len(native['observations'])==len(gated['observations'])==1,'actual complete application observations')\n"],
            [426, 427, "    actual=gated['observations'][0]\n    need(all(reference[k]==actual[k]for k in('before','after','live','data','stack'))and gated['effects']==native['effects']and gated['suffix']is not None,'whole actual application state and later registration lifecycle')\n"],
        ]:
            need(at <= first <= end <= len(lines) and ''.join(lines[first:end]) != previous,
                 'ordered exact direct-reader inverse span')
            result.extend(lines[at:first]); result.append(previous); at = end
        data = ''.join(result + lines[at:]).encode('utf-8')
        need(fact(data) == {'bytes': 35492, 'sha256': '273cd7c05858c889bef229d2f32439ee794e8f3107bf04d8e5d21457f2f12b71'}, 'whole unchanged retained direct reader')
    replacements = {
        'persistent_fused_app/read.py': [
            (b"==(1,1,1,0,0,0,1),'actual unsupported-store miss", b"==(1,5,1,0,0,0,1),'actual unsupported-store miss")],
        'persistent_fused_owner/read.py': [
            (b"        # 66 89 07 is outside both scalar and guarded-store Code domains:\n"
             b"        # its exact refusal is UNSUPPORTED (1), not the PB fixture's OPERANDS (5).\n", b''),
            (b"self.eq(miss,'li2_pg_miss',version=11,status=1,reason=1,site=1,pc=pc,detail=1)",
             b"self.eq(miss,'li2_pg_miss',version=11,status=1,reason=1,site=1,pc=pc,detail=5)"),
            (b"next=nxt,reason=1,detail=1,source_released=1", b"next=nxt,reason=1,detail=5,source_released=1")],
    }
    for before, after in replacements.get(relative, []):
        need(data.count(before) == 1, 'one exact inverse span: '+relative)
        data = data.replace(before, after)
    return data


def exact_rejection(call, expected):
    try:
        call()
    except ValueError as error:
        need(str(error) == expected, 'exact historical rejection, not an earlier/later failure')
        return dict(status='reproduced_rejection', error='ValueError: '+str(error))
    raise ValueError('historical reader unexpectedly accepted retained actual bytes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'one externally reserved regression CPU')
    directory = args.output.absolute()
    need(not sys.flags.optimize and directory.parent == ROOT/'target/evaluation/inprocess' and
         not directory.exists() and not directory.is_symlink(),
         'assertions enabled and fresh separate direct-child output; historical cohort immutable')
    directory.mkdir()
    output = directory/'receipt.json'
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (900, 900))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('regression wall limit')))
    signal.alarm(1200)
    start = time.monotonic_ns()
    checked, modules = {}, []
    result = dict(schema=1, scope='reader_regression_only', status='failed',
                  historical_receipt=RECEIPT, historical_status='failed', cpu=args.cpu, faults_replayed=False, historical_rejections={},
                  retained_subject_cpu=3, bounds=dict(cpu_seconds=900, wall_seconds=1200,
                  address_space_bytes=512 << 20, file_bytes=16 << 20, cpu_count=1),
                  new_subjects=0, child_commands=0, qualification_credit=False,
                  performance_credit=False, terminal_reports_replayed=False, lanes={}, errors=[])

    def take(path, expected):
        path = Path(path).resolve()
        data = path.read_bytes()
        want = {k: expected[k] for k in ('bytes', 'sha256')}
        need(fact(data) == want, 'whole input identity: ' + str(path))
        if 'mode' in expected:
            need(path.stat().st_mode & 0o7777 == expected['mode'], 'input mode: ' + str(path))
        row = dict(want, mode=path.stat().st_mode & 0o7777)
        need(str(path) not in checked or checked[str(path)] == row, 'consistent input identity')
        checked[str(path)] = row
        return data

    def load(name, path):
        need(str(path.resolve()) in checked, 'reader source authenticated before import')
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
        return module

    def source_closure():
        pending, seen, paths = list(modules), set(), set()
        while pending:
            module = pending.pop()
            if id(module) in seen:
                continue
            seen.add(id(module))
            path = getattr(module, '__file__', None)
            if path is None or not Path(path).resolve().is_relative_to(ROOT):
                continue
            path = str(Path(path).resolve())
            need(path in checked, 'every imported repository module authenticated: ' + path)
            paths.add(path)
            pending.extend(v for v in vars(module).values() if isinstance(v, types.ModuleType))
        result['imported_sources'] = sorted(paths)

    try:
        take(__file__, fact(Path(__file__).read_bytes()))
        contract = json.loads(take(PACKET/'INPUTS.json', INPUTS))
        take(ROOT/'evaluation/inprocess/bounded_fused_owner_helpers.py', contract['helper'])
        r = json.loads(take(BASE / 'receipt.json', RECEIPT))
        need(r['status'] == 'failed' and r['profile'] == 'bounded-fused-owner-v1' and
             r['revision'] == REVISION and r['cpu'] == 3 and
             r['source_unchanged'] is True and r['inputs_unchanged'] is True and
             r['cleanup_complete'] is True and r['final_errors'] == [], 'exact closed failed attempt 2')
        result['historical_revision'] = r['revision']
        result['historical_error'] = r['error']
        result['historical_hardware'] = r['hardware']
        result['historical_cases'] = [{k: c[k] for k in ('label','status','exit','whole_process_ns') } for c in r['cases']]
        result['historical_fault_cases'] = r['fault_cases']
        catalog = dict(r['inputs'])
        for path, value in r['artifacts'].items():
            if path in catalog:
                need(all(catalog[path][k] == value[k] for k in ('bytes','sha256')),
                     'consistent retained whole input/artifact identity')
                if 'mode' in catalog[path] and 'mode' in value:
                    need(catalog[path]['mode'] == value['mode'], 'consistent retained mode')
            catalog[path] = dict(catalog.get(path, {}), **value)
        need(all(x['exit'] == x['expected_exit'] == 0 and x['error'] is None and
                 x['reaped'] is True and x['timed_out'] is False and x['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in x['descriptors']) and x['bounds'] == r['bounds'][x['profile']]
                 for x in r['commands']), 'all101 original bounded children exited0/reaped/closed')
        need([(x['name'],x['profile']) for x in r['commands']] ==
             [tuple(x) for x in contract['base_command_schedule']], 'exact closed positive101-command prefix')
        need(len(r['cases']) == 3 and [x['lane'] for x in r['cases']] == ['native','maintained','differential'] and
             all(x['mode'] == x['control'] == 0 and x['exit'] == 0 and x['launched'] is True for x in r['cases']) and
             r['cases'][0]['status'] == 'observed_native_bounded_fused' and
             all(x['status'] == 'failed' and x['error'] == 'ValueError: exact li2_pg_miss.detail' for x in r['cases'][1:]) and
             len(r['fault_cases']) == 4 and all(x['status'] == 'unexecuted' and x['launched'] is False for x in r['fault_cases']),
             'literal failed positive prefix and unexecuted faults remain unchanged')

        def retained(path, extra=None):
            path = Path(path).resolve()
            need(str(path) in catalog, 'retained input/artifact in exact historical receipt')
            data = take(path, catalog[str(path)])
            if extra is not None:
                need(fact(data) == {k: extra[k] for k in ('bytes', 'sha256')}, 'retained role identity')
            return data

        # Copy only small Python sources, never raw captures or generated images.
        # Historical source is the exact recorded whole, reconstructed by the
        # original PF literal inverses and the exact direct-reader whole inverse.
        historical_tests = directory/'historical-tests'
        for relative, expected in contract['readers'].items():
            path = TESTS/relative
            need(str(path) in r['inputs'] and r['inputs'][str(path)] == contract['historical_readers'][relative],
                 'all reader dependencies belong to the original receipt')
            current = take(path, expected)
            old = historical_reader(relative, current)
            need(fact(old) == {k: r['inputs'][str(path)][k] for k in ('bytes','sha256')},
                 'whole original reader restored; no other source change')
            staged = historical_tests/relative
            staged.parent.mkdir(parents=True,exist_ok=True)
            with staged.open('xb') as stream:
                stream.write(old)
            staged.chmod(expected['mode'])
            take(staged, contract['historical_readers'][relative])
        app = load('regression_pf_app', TESTS/'persistent_fused_app/read.py')
        owner = load('regression_pf_owner', TESTS/'persistent_fused_owner/read.py')
        historical_app = load('historical_pf_app', historical_tests/'persistent_fused_app/read.py')
        historical_owner = load('historical_pf_owner', historical_tests/'persistent_fused_owner/read.py')
        seed = load('regression_seed', TESTS/'provider_app/seed_probe/read.py')
        xstate = load('regression_xstate', TESTS/'b2_reference/xstate.py')
        source_closure()
        result['readers'] = {k: contract['readers'][k] for k in
                            ('persistent_fused_owner/read.py','persistent_fused_app/read.py')}
        need(owner.CONTROL_COUNTS == historical_owner.CONTROL_COUNTS == {0:204} and
             app.APP_CONTROL_COUNTS == historical_app.APP_CONTROL_COUNTS == {0:40} and
             app.PAIR_CONTROL_COUNTS == historical_app.PAIR_CONTROL_COUNTS == {0:36} and
             owner.PF_REFUSAL_CONTROL_COUNT == historical_owner.PF_REFUSAL_CONTROL_COUNT == 28,
             'original complete40/204/36 plus separate PF28 control populations')
        for path, expected in r['reader_support']['headers'].items():
            retained(path, expected)
        policy = BASE / 'native-policy.so'
        retained(policy, r['reader_support']['native_policy'])
        lib = ctypes.CDLL(str(policy))
        lib.li2_native_policy.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
        lib.li2_native_policy.restype = ctypes.c_uint
        native_policy = lambda data: lib.li2_native_policy(data, len(data))

        def command(name):
            rows = [x for x in r['commands'] if x['name'] == name]
            need(len(rows) == 1, 'one retained original command')
            row = rows[0]
            need(row['exit'] == row['expected_exit'] == 0 and row['timed_out'] is False and
                 row['reaped'] is True and row['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in row['descriptors']), 'actual successful closed child')
            return row

        def captures(row):
            return {kind: retained(BASE / value['file'], value) for kind, value in row['captures'].items()}

        sr = command('seed-prerequisite'); sc = captures(sr)
        need(sr['bounds'] == [5, 512 << 20, 16 << 20, 15] and sc['stderr'] == b'' and
             r['seed_prerequisite']['status'] == 'passed', 'unchanged actual same-CPU seed prerequisite')
        raw = sc['stdout']; h = struct.unpack_from('<16Q', raw, 128)
        cp = [struct.unpack_from('<6I', raw, 256 + 24*i) for i in range(67)]
        facts = xstate.profile(cp, h[8], h[10], h[12], h[5], h[6])
        profile = seed.read(raw, retained(BASE / 'seed-probe', r['seed_prerequisite']['elf']),
                            facts, xstate, cpu=r['cpu'], pid=sr['pid'])
        need(seed.require(profile, facts, cpu=r['cpu']) == bytes(16) and
             normalized(profile) == r['seed_prerequisite']['profile'] and
             normalized(facts) == r['seed_prerequisite']['format'], 'whole original seed derivation')
        reference = (seed, xstate, profile, facts)
        original_path = BASE / 'application/persistent-fused-app'
        original = retained(original_path, r['application_build']['artifact'])
        interp_path = Path(r['application_build']['interpreter']['path'])
        interp = retained(interp_path, r['application_build']['interpreter'])
        app_layout = app.elf(original, native_policy)
        projected = {k: v for k, v in app_layout.items() if k not in ('source', 'sources')}
        projected['source_pairs'] = [fact(v) for v in app_layout['source_pairs']]
        need(normalized(projected) == r['application_layout'], 'same whole application ELF model')

        native = None
        for lane in ('native', 'maintained', 'differential'):
            observed = result['lanes'][lane] = dict(status='failed')
            try:
                label = 'subject-' + lane + '-0-0'; row = command(label); capture = captures(row)
                need(row['bounds'] == [30, 512 << 20, 16 << 20, 60] and
                     set(capture) == ({'stdout','stderr'} if lane == 'native' else {'stdout','stderr','record'}),
                     'original subject bounds and complete actual capture streams unchanged')
                observed['captures'] = {kind: fact(data) for kind,data in capture.items()}
                observed['retained_exit'] = row['exit']
                observed['retained_duration_ns'] = row['duration_ns']
                prep = json.loads(retained(BASE / label / 'preparation.json'))
                need(prep['pid'] == row['pid'] and prep['cpu'] == [r['cpu']] and
                     prep['mode'] == prep['control'] == 0 and
                     prep['role'] == ('native' if lane == 'native' else 'gated'), 'actual retained preparation')
                args_app = (capture['stdout'], 0, lane == 'native', row['exit'], app_layout,
                            row['pid'], r['cpu'], reference)
                parsed = app.read(*args_app)
                need(historical_app.read(*args_app) == parsed, 'unchanged complete application read across literal pair repair')
                if lane == 'native':
                    need(capture['stderr'] == b'', 'actual native empty stderr')
                    observed['application_controls'] = population(app.controls(*args_app), 40, capture['stdout'])
                    need(observed['application_controls'] == r['cases'][0]['application_controls'],
                         'unchanged literal native refusal names')
                    native = parsed
                else:
                    holder = r['lanes'][lane]; subject = holder['subject_artifacts']
                    build = BASE / (lane + '-build')
                    suffix = 'persistent-fused-' + ('capture' if lane == 'maintained' else 'differential')
                    bridge = retained(build / suffix / ('bridge-' + suffix + '.so'), subject['bridge'])
                    carrier = retained(build / 'carrier', subject['carrier'])
                    layout = json.loads(retained(build / 'owner-dwarf-layout.json', holder['owner_layout']['artifact']))
                    for path, expected in holder['release_build']['headers'].items():
                        retained(path, expected)
                    need(holder['owner_layout']['bridge'] == subject['bridge'], 'actual DWARF belongs to bridge')
                    ns = BASE / label / 'namespace'
                    manifest = json.loads(retained(ns / 'namespace.json'))
                    launch = json.loads(retained(ns / 'launch.json'))
                    need(manifest['objects'] == [] and manifest['original'] == str(original_path) and
                         manifest['interpreter'] == str(interp_path) and
                         manifest['original_sha256'] == fact(original)['sha256'] and
                         manifest['interpreter_sha256'] == fact(interp)['sha256'] and
                         launch['dependency_fds'] == [] and launch['argv'] == [str(original_path), '0', 'gated'] and
                         launch['carrier_sha256'] == fact(carrier)['sha256'] and
                         launch['carrier_size'] == len(carrier), 'exact empty-dependency image inventory')
                    need(subject['original'] == fact(original) and subject['interpreter'] == fact(interp),
                         'same original and interpreter across lanes')
                    image = dict(objects={0: dict(data=original, carrier_bytes=len(carrier), kind=1),
                                          1: dict(data=interp, carrier_bytes=len(interp), kind=2)},
                                 main_object=0, interpreter_object=1, uid=os.getuid(), bridge=bridge,
                                 persistent_binding=holder['release_build']['persistent_binding'],
                                 headers=holder['release_build']['headers'], app_symbols=app_layout['symbols'])
                    args_owner = (capture['record'], layout, image, parsed, row['pid'], r['cpu'], row['exit'])
                    observed['historical_owner'] = exact_rejection(
                        lambda: historical_owner.read(*args_owner), 'exact li2_pg_miss.detail')
                    result['historical_rejections'][lane] = observed['historical_owner']
                    actual = owner.read(*args_owner)
                    need(actual['cancellation']['detail'] == 1, 'actual unsupported16-bit MOV detail, never rewritten')
                    need(native is not None, 'complete same-capture native reference')
                    observed['historical_pair'] = exact_rejection(
                        lambda: historical_app.pair(native, parsed, actual),
                        'actual unsupported-store miss cancels without publication or completion authority')
                    observed['owner_controls'] = population(owner.controls(*args_owner), 204, capture['record'])
                    observed['pair'] = app.pair(native, parsed, actual)
                    observed['pair_controls'] = population(app.pair_controls(native, parsed, actual), 36)
                    need(observed['pair_controls']['refusals'] == contract['pair_control_names'], 'exact36 named pair controls')
                    observed['pf_refusal_owner_controls'] = population(owner.pf_refusal_controls(*args_owner), 28, capture['record'])
                    observed['pf_refusals'] = actual['pf_refusals']
                    observed['pf_refusal_stages'] = actual['pf_refusal_stages']
                    need(observed['pair'] == contract['pair_expected'], 'exact source-owned finite PF pair result')
                    names = [name+'_'+key for name in
                             [f'epoch{i}_{stage}' for i in range(3) for stage in ('prior','entered','terminal')]+
                             ['cancel_held','cancel_resumed','final']
                             for key in ('pf_backward_refused','pf_backward_cancelled')]
                    names += ['layout_'+name for name in ('previous_last','refused_offset','cancelled_width','owner_extent')]
                    need(observed['pf_refusal_owner_controls']['refusals'] == names, 'exact named28 PF snapshot/layout controls')
                observed['status'] = 'passed'
            except Exception as error:
                observed['error'] = type(error).__name__ + ': ' + str(error)
                result['errors'].append(lane + ': ' + observed['error'])
                if isinstance(error, TimeoutError):
                    raise
        need(list(result['lanes']) == ['native', 'maintained', 'differential'] and
             all(x['status'] == 'passed' for x in result['lanes'].values()), 'all fixed regression lanes')
        need(len(result['historical_rejections']) == 2, 'both literal historical owner failures reproduced')
        need(sum(len(x.get('application_controls', {}).get('refusals', [])) for x in result['lanes'].values()) == 40 and
             sum(len(x.get('owner_controls', {}).get('refusals', [])) for x in result['lanes'].values()) == 408 and
             sum(len(x.get('pair_controls', {}).get('refusals', [])) for x in result['lanes'].values()) == 72 and
             sum(len(x.get('pf_refusal_owner_controls', {}).get('refusals', [])) for x in result['lanes'].values()) == 56,
             'all separate exact supplied control populations; no skipped lane')
        result['status'] = 'passed'
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        signal.alarm(0)
        try:
            source_closure()
            for path, expected in list(checked.items()):
                take(path, expected)
            need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'unchanged singleton regression CPU')
            result['inputs_unchanged'] = True
        except Exception as error:
            result['status'] = 'failed'; result['inputs_unchanged'] = False
            result['errors'].append('closure: ' + type(error).__name__ + ': ' + str(error))
        result['inputs'] = checked
        result['duration_ns'] = time.monotonic_ns() - start
        with output.open('x') as stream:
            json.dump(result, stream, sort_keys=True, indent=2); stream.write('\n')
    print(json.dumps(dict(scope=result['scope'], status=result['status'], errors=result['errors'],
                          output=str(output), **fact(output.read_bytes())), sort_keys=True))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
