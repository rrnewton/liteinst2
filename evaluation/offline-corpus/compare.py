#!/usr/bin/env python3
"""Finite two-program expansion: complete branch witnesses + whole-output equality.

Root supplies a freshly admitted release build/tool catalog. No automatic build,
download, profile substitution, skipped dataset, or renewed historical owner.
"""
import argparse
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
from corpus import PROGRAMS, BASE, LINKER, assembly, datasets, expected, sha
from adapter import prepare, core_witness, core_refusal, e9_witness, read

if sys.flags.optimize:
    raise SystemExit('assertions required')
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
ADAPTER_SHA = '5904a13ec1fcb8b6801dcff12ac1fe5a1154b884555bbd9fbc24521f9bc6949f'
REFERENCE = dict(reference_commit='0d5d36e4c4edcac37ca2499694d64302a391136f',
    reference_tree='b833c9dedd0aaaf8ed60ad1c041bd1535c55ccce',
    archive_sha256='b9d82420ee00a7240f574645c229d91fb993d1f24305258e3cdc294e6df44f0f',
    capstone_revision='e3f106739a6ae78d47772dff31062d644ea21078',
    abi_delta_patch_sha256='66bfd1bbef8fd9f33656a8956d21fbe5cba6c27b6ff034be0084db76bafd9e0d')
LANES = ('native', 'liteinst', 'stock-algorithm', 'bootstrap-patched-reference')
E9 = {
 'stock-algorithm': ('stock_frontend', 'stock_backend', 'stock_loader'),
 'bootstrap-patched-reference': ('transport_frontend', 'abi_backend', 'abi_loader')}
E9_HASHES = {
 'stock_frontend':'36b05e9a47c9193041d71ed4e14dda87e835e0e2b47e4a82a7d30a7c0d4eeb5e',
 'stock_backend':'890f76cb5741b6c7cfba3414ae72a64fd7deddc7d2dd33b17d53e8b906529fdb',
 'stock_loader':'4d39f324ab8a3a9420d2436129ba941e17fd78aa2c4e35eff3d27311e0683477',
 'transport_frontend':'0fea3c8bc0701dffeb16b524e7159e458be9add11bcf3df5f47b9714c1005acc',
 'abi_backend':'3750339187ffc4a084d075de77d1c653c255abd96e396870ea691b495f0c5453',
 'abi_loader':'126b6143c5668e4d390e0b9626824f5007b54d56e47a07bb72b415757b51773c'}
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
PROFILE = dict(opt_level='3', debuginfo=0, debug_assertions=True, overflow_checks=True, test=False)

def encode(value):
    return json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'

def write(path, value):
    with Path(path).open('xb') as f:
        f.write(value if isinstance(value, bytes) else encode(value))

def owner(path):
    p = Path(path)
    assert p.is_absolute() and p.resolve(strict=True) == p and not p.is_symlink()
    with p.open('rb') as f:
        a = os.fstat(f.fileno()); assert stat.S_ISREG(a.st_mode)
        h = hashlib.sha256()
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk: break
            h.update(chunk)
        b = os.fstat(f.fileno())
    six = lambda s: [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    assert six(a) == six(b) == six(p.stat())
    return dict(path=str(p), bytes=a.st_size, sha256=h.hexdigest(), stat=six(a))

def descriptor(path):
    data = read(path)
    return dict(path=str(path), bytes=len(data), sha256=sha(data))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--inputs', type=Path, required=True)
    p.add_argument('--inputs-sha256', required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args(); repo = a.repo.resolve(strict=True); out = a.out
    assert out.is_absolute() and out.parent.resolve(strict=True) == out.parent
    assert out.is_relative_to(repo/'ignored') and not out.exists()
    raw = read(a.inputs); assert sha(raw) == a.inputs_sha256
    x = json.loads(raw)
    assert set(x) == {'schema','revision','hardware','tools','files','release_build','target','retained_heap_evidence'}
    assert x['schema'] == 1 and x['hardware'] == 'AMD EPYC Zen 5 dev host'
    assert x['retained_heap_evidence'], 'existing heap-sort campaign remains separately mandatory'
    watched = {str(a.inputs): owner(a.inputs)}
    for path, row in x['files'].items():
        got = owner(path)
        assert got == row, 'fresh explicit exact owner catalog; no refresh'
        watched[path] = got
    tool = x['tools']
    assert set(tool) == {'python','timeout','as','ld','core','target_driver'} | set(E9_HASHES)
    for role,value in tool.items():
        assert value in watched
        # Loader blobs are authenticated data, never command executables.
        if role not in ('stock_loader','abi_loader'):
            assert watched[value]['stat'][2] & 0o111
    for role, digest in E9_HASHES.items():
        assert watched[tool[role]]['sha256'] == digest
    helper = repo/'tools/unwind-oracle/bounded_command.py'
    e9_adapter = repo/'tools/elf-rewrite/e9-sites.py'
    renderer = repo/'evaluation/elf-exec/render_selection.py'
    for path, digest in ((helper, HELPER_SHA), (e9_adapter, ADAPTER_SHA)):
        assert str(path) in watched and watched[str(path)]['sha256'] == digest
    assert str(renderer) in watched
    for name in ('compare.py','adapter.py','corpus.py','checksum.S','rle-roundtrip.S','layout.ld'):
        assert str(Path(__file__).resolve().with_name(name)) in watched
    assert read(Path(__file__).resolve().with_name('layout.ld'))==LINKER.encode()
    for name in PROGRAMS:
        assert read(Path(__file__).resolve().with_name(name+'.S'))==assembly(name)
    def bound_json(path):
        assert path in watched
        return json.loads(read(path))
    # Explicit release build identity, not an either-debug-profile acceptance.
    # The root-selected admission must bind the actual closed build and product.
    build = bound_json(x['release_build'])
    assert build['status'] == 'PASS' and build['revision'] == x['revision']
    assert build['profile'] == PROFILE and build['product'] == watched[tool['core']]
    assert build['argv'] == ['cargo','build','--release','--locked','--offline','--package','liteinst-rewrite','--bin','liteinst-rewrite','--message-format=json']
    required_env = {'CARGO_INCREMENTAL':'0','CARGO_PROFILE_RELEASE_DEBUG':'0',
                    'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS':'true','CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS':'true'}
    assert all(build['env'].get(k) == v for k,v in required_env.items())
    assert not any(k in build['env'] for k in ('RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS'))
    for field in ('command','receipt','parent_closed','cargo_messages'):
        assert build[field] in watched
    build_request = bound_json(build['command'])
    assert build_request['argv'] == build['argv'] and build_request['env'] == build['env']
    assert build_request['cwd'] == str(repo) and build_request['stdout'] == build['cargo_messages']
    build_receipt = bound_json(build['receipt']); parent = bound_json(build['parent_closed'])
    assert build_receipt['request_sha256'] == sha(read(build['command'])) and build_receipt['helper_sha256'] == HELPER_SHA
    assert build_receipt['stdout_sha256'] == sha(read(build['cargo_messages']))
    assert build_receipt['exit'] == 0 and build_receipt['absence_proof'] == 'ECHILD'
    assert build_receipt['cleanup_events'] == build_receipt['unexpected_descendants'] == []
    assert build_receipt['cleanup_error'] is build_receipt['aborted'] is None
    assert build_receipt['wall_timeout'] is False and build_receipt['inputs_unchanged'] is True
    assert parent['exit'] == 0 and parent['wait_returned'] is True
    messages = [json.loads(line) for line in read(build['cargo_messages']).splitlines()]
    products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'liteinst-rewrite' and m.get('executable')]
    assert len(products) == 1 and products[0]['profile'] == PROFILE
    assert products[0]['target']['kind'] == ['bin'] and products[0]['executable'] == tool['core']
    # Saved original heap results are carried by exact descriptor, not reclassified.
    retained = {path: bound_json(path) for path in x['retained_heap_evidence']}
    revision = subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=repo,env=ENV,timeout=15).decode().strip()
    assert revision == x['revision']
    assert subprocess.check_output(['/usr/bin/git','diff','--binary','HEAD','--'],cwd=repo,env=ENV,timeout=15) == b''
    out.mkdir(); write(out/'inputs.json', raw)
    commands = []; results = []
    planned = {(program,key,lane):dict(program=program,dataset=key,lane=lane,input_bytes=len(data),
        selected_sites=None,status='UNRUN',attempted=False,exit=None,expected_sha256=sha(expected(program,data)),
        actual_sha256=None,seconds=None,reason='not attempted')
        for program in PROGRAMS for key,data in datasets().items() for lane in LANES}
    assert len(planned) == 80
    write(out/'planned.json',list(planned.values()))
    def freeze(path):
        key=str(path); row=owner(path)
        assert key not in watched or watched[key] == row
        watched[key]=row
    def stable():
        assert all(owner(path) == row for path,row in watched.items()), 'owner/source/tool drift'
    def execute(name, argv, cwd, compiler=False, case_row=None):
        stable(); d = out/name; d.mkdir()
        request = dict(argv=list(map(str,argv)),cwd=str(cwd),env=dict(ENV,TMPDIR=str(cwd)),
            stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),
            cpu_seconds=60 if compiler else 20,wall_seconds=90 if compiler else 30,
            file_bytes=(128 if compiler else 16)*1024*1024)
        write(d/'request.json',request)
        wrapper = [tool['timeout'],'--signal=TERM','--kill-after=10s','100s' if compiler else '40s',
                   tool['python'],'-B',str(helper),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')]
        write(d/'command.json',dict(argv=wrapper,env=ENV,cwd=str(repo),request=request))
        command_row = dict(name=name,request=request,status='FAILED',attempted=False,exit=None,
            seconds=None,receipt=None,parent=None,parent_exit=None)
        commands.append(command_row)
        begin = time.monotonic(); child = None
        closed = dict(exit=None,wait_returned=False,timeout=False,error=None)
        try:
            with (d/'helper.stdout').open('xb') as stdout,(d/'helper.stderr').open('xb') as stderr:
                child = subprocess.Popen(wrapper,cwd=repo,env=ENV,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
                closed['pid'] = child.pid
                command_row['attempted'] = True
                if case_row is not None:case_row['attempted'] = True
                try:
                    write(d/'started.json',dict(pid=child.pid,monotonic=begin))
                    closed['exit'] = child.wait(timeout=115 if compiler else 55); closed['wait_returned'] = True
                except BaseException as failure:
                    closed['error'] = type(failure).__name__
                    closed['timeout'] = isinstance(failure,subprocess.TimeoutExpired)
                    if child.poll() is None:
                        try: os.killpg(child.pid,signal.SIGKILL)
                        except ProcessLookupError: pass
                    try: closed['exit'] = child.wait(timeout=10); closed['wait_returned'] = True
                    except subprocess.TimeoutExpired:
                        closed['error'] += ':CLEANUP_WAIT_EXPIRED'
                        raise
                    raise
        finally:
            if child is not None:
                closed['exit'] = child.returncode
                closed['seconds'] = time.monotonic()-begin
                write(d/'closed.json',closed)
                command_row['parent'] = descriptor(d/'closed.json')
                command_row['parent_exit'] = closed['exit']
        assert closed['wait_returned'] and not closed['timeout']
        receipt = json.loads(read(d/'receipt.json'))
        assert receipt['request_sha256'] == sha(read(d/'request.json')) and receipt['helper_sha256'] == HELPER_SHA
        assert receipt['absence_proof'] == 'ECHILD' and receipt['inputs_unchanged'] is True
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None and receipt['wall_timeout'] is False
        assert type(receipt['exit']) is int and closed['exit'] == (0 if receipt['exit'] == 0 else 1)
        assert math.isfinite(receipt['elapsed_seconds']) and 0 <= receipt['elapsed_seconds'] <= request['wall_seconds']
        for stream in ('stdout','stderr'):
            assert sha(read(d/(stream+'.txt'))) == receipt[stream+'_sha256']
        terminal = dict(exit=receipt['exit'],wall_timeout=False,absence_proof='ECHILD',descendants=0,success=receipt['exit']==0)
        assert read(d/'helper.stdout') == (json.dumps(terminal)+'\n').encode() and read(d/'helper.stderr') == b''
        stable(); command_row.update(status='PASS' if receipt['exit']==0 else 'FAILED',exit=receipt['exit'],seconds=receipt['elapsed_seconds'],
            receipt=descriptor(d/'receipt.json'),parent=descriptor(d/'closed.json'))
        return d,receipt['exit']
    fatal = None
    try:
        # Reuse unchanged complete target grammar; no fixture()/main() call.
        spec = importlib.util.spec_from_file_location('authored_target_grammar',renderer)
        grammar = importlib.util.module_from_spec(spec); spec.loader.exec_module(grammar)
        target = bound_json(x['target'])
        assert target['driver'] == watched[tool['target_driver']] and target['record'] in watched
        assert target['receipt'] in watched and target['request'] in watched
        target_request = bound_json(target['request']); tr = bound_json(target['receipt'])
        assert target_request['argv'] == [tool['target_driver'],'target']
        assert tr['exit'] == 0 and tr['absence_proof'] == 'ECHILD' and tr['inputs_unchanged'] is True
        assert tr['unexpected_descendants'] == tr['cleanup_events'] == [] and tr['aborted'] is tr['cleanup_error'] is None and tr['wall_timeout'] is False
        assert tr['request_sha256'] == sha(read(target['request'])) and tr['helper_sha256'] == HELPER_SHA
        target_line = grammar.target_record(read(target['record']))
        extents = [576] + [int(v.split(':')[1]) + int(v.split(':')[2]) for v in target_line.split()[3:]]
        assert max(extents) <= 16384, 'finite target-state extent fits the authored 64 KiB stack with save/call margin'
        assert tr['stdout_sha256'] == sha(read(target['record']))
        now,rc=execute('target-current',[tool['target_driver'],'target'],out)
        assert rc==0 and read(now/'stdout.txt')==read(target['record']) and not read(now/'stderr.txt')
        data_dir=out/'datasets';data_dir.mkdir()
        for key,data in datasets().items():
            write(data_dir/key,data);freeze(data_dir/key)
        write(out/'layout.ld',LINKER.encode());freeze(out/'layout.ld')
        for program in PROGRAMS:
            d=out/program;d.mkdir(); src=d/'subject.S'; obj=d/'subject.o'; original=d/'original'
            write(src,assembly(program));freeze(src)
            c,rc=execute(program+'-assemble',[tool['as'],'--64',src,'-o',obj],d,True)
            assert rc == 0 and not read(c/'stderr.txt')
            c,rc=execute(program+'-link',[tool['ld'],'-static','-nostdlib','--build-id=none','-z','noexecstack','-T',out/'layout.ld',obj,'-o',original],d,True)
            assert rc == 0 and not read(c/'stderr.txt')
            freeze(obj);freeze(original);original_bytes=read(original)
            selection,heads,selected=prepare(program,original_bytes,target_line,sha(assembly(program)))
            write(d/'selection.txt',selection);freeze(d/'selection.txt')
            write(d/'heads.json',[dict(**{k:v for k,v in h.items() if k!='code'},code=h['code'].hex()) for h in heads])
            policy=dict(schema=1,original_sha256=sha(original_bytes),selection_sha256=sha(selection),
                        e9_revision=REFERENCE['reference_commit'],instrumentation='null',selection_style='jump-site')
            write(d/'policy.json',policy);freeze(d/'policy.json')
            available={'native':original}; failures={}
            c,rc=execute(program+'-liteinst-produce',[tool['core'],'prepare',original,d/'selection.txt',d/'core'],d)
            if rc == 0:
                try:
                    assert read(c/'stderr.txt')==b''
                    assert read(c/'stdout.txt')==f'candidate_complete=true qualification_complete=false sites={len(selected)}\n'.encode()
                    witness=core_witness(original_bytes,selection,d/'core',selected)
                    write(d/'core-witness.json',witness); available['liteinst']=d/'core/candidate.elf'
                except (AssertionError,KeyError,ValueError) as error:
                    failures['liteinst']=('FAILED','byte/complete-selection witness: '+repr(error))
            else:
                # Exit2 is the producer's explicit complete selected-site refusal;
                # errors/signals remain FAILED, never availability success.
                status='FAILED'
                if rc==2:
                    core_refusal(original_bytes,selection,d/'core',selected)
                    assert read(c/'stdout.txt')==f'candidate_complete=false qualification_complete=false sites={len(selected)}\n'.encode()
                    assert read(c/'stderr.txt')==b''
                    status='UNSUPPORTED'
                failures['liteinst']=(status,f'producer exit {rc}')
            for lane,roles in E9.items():
                ld=d/lane;ld.mkdir(); candidate=ld/'candidate.elf'
                common=['--action=asm=j.*:passthru','--executable','--compression=9',
                        '--start='+hex(BASE),'--end='+hex(BASE+sum(len(h['code']) for h in heads))]
                transport,tc=execute(program+'-'+lane+'-transport',[tool['transport_frontend'],*common,'--format=json','--output=-',original],ld)
                producer,pc=execute(program+'-'+lane+'-produce',[tool[roles[0]],*common,'--format=binary','--output='+str(candidate),'--backend='+tool[roles[1]],'--option=--debug',original],ld)
                if tc or pc:
                    failures[lane]=('FAILED',f'transport exit {tc}; producer exit {pc}');continue
                paths=dict(original=original,selection=d/'selection.txt',policy=d/'policy.json',candidate=candidate,
                    frontend=Path(tool[roles[0]]),backend=Path(tool[roles[1]]),loader=Path(tool[roles[2]]),
                    transport_frontend=Path(tool['transport_frontend']),helper=helper)
                for phase,where in (('transport',transport),('producer',producer)):
                    for role in ('request','receipt','stdout','stderr'):
                        paths[phase+'_'+role]=where/(role+('.json' if role in ('request','receipt') else '.txt'))
                envelope=dict(schema=1,lane=lane,common_argv=common,hook=None,files={k:descriptor(v) for k,v in paths.items()},**REFERENCE)
                write(ld/'envelope.json',envelope)
                c,rc=execute(program+'-'+lane+'-adapter',[tool['python'],'-B',e9_adapter,ld/'envelope.json',ld/'inventory','--envelope-sha256',sha(read(ld/'envelope.json'))],ld)
                if rc:
                    failures[lane]=('FAILED','unchanged structural adapter refused');continue
                binding=json.loads(read(ld/'inventory/producer-binding.json'))
                if any(r['tactic'] is None for r in binding['outcomes']):
                    failures[lane]=('UNSUPPORTED','selected sites refused; complete inventory retained');continue
                try:
                    witness=e9_witness(original_bytes,read(candidate),binding,selected)
                    write(ld/'branch-witness.json',witness);available[lane]=candidate
                except (AssertionError,KeyError,ValueError) as error:
                    failures[lane]=('FAILED','relocated-branch witness: '+repr(error))
            # New executable copies only; the authenticated structural originals
            # and candidate bundles retain their original modes and whole bytes.
            runnable={}
            for lane,path in available.items():
                freeze(path)
                run=d/('run-'+lane);write(run,read(path));run.chmod(0o700)
                assert read(run)==read(path);freeze(run);runnable[lane]=run
            for key,data in datasets().items():
                want=expected(program,data); baseline=None
                for lane in LANES:
                    row=planned[(program,key,lane)]
                    row['selected_sites']=len(selected)
                    if lane not in runnable:
                        row.update(status=failures[lane][0],reason=failures[lane][1]);results.append(row);continue
                    row.update(status='FAILED',reason='command or its saved checks did not complete')
                    results.append(row)
                    c,rc=execute(program+'-'+key+'-'+lane,[runnable[lane],data_dir/key],d,case_row=row)
                    actual=read(c/'stdout.txt');err=read(c/'stderr.txt')
                    okay=rc==0 and actual==want and err==b''
                    if lane=='native': baseline=actual if okay else None
                    elif baseline is None or actual!=baseline: okay=False
                    row.update(status='PASS' if okay else 'FAILED',exit=rc,actual_sha256=sha(actual),
                               seconds=commands[-1]['seconds'],output_bytes=len(actual),stderr_sha256=sha(err))
                    row.pop('reason',None)
            assert len(results)==len(datasets())*len(LANES)*(list(PROGRAMS).index(program)+1)
        stable()
        assert subprocess.check_output(['/usr/bin/git','rev-parse','HEAD'],cwd=repo,env=ENV,timeout=15).decode().strip()==revision
        assert subprocess.check_output(['/usr/bin/git','diff','--binary','HEAD','--'],cwd=repo,env=ENV,timeout=15)==b''
    except BaseException as error:
        fatal=type(error).__name__+': '+str(error)
    existing={(r['program'],r['dataset'],r['lane']) for r in results}
    for program in PROGRAMS:
        for key,data in datasets().items():
            for lane in LANES:
                if (program,key,lane) not in existing:
                    row=planned[(program,key,lane)]
                    row['reason']='campaign stopped'
                    results.append(row)
    assert len(results)==80 and len({(r['program'],r['dataset'],r['lane']) for r in results})==80
    summary=dict(schema=1,revision=revision,hardware=x['hardware'],profile=PROFILE,programs=list(PROGRAMS),
        cases=len(results),counts={s:sum(r['status']==s for r in results) for s in ('PASS','FAILED','UNSUPPORTED','UNRUN')},
        fatal=fatal,architectural_full_state=False,normal_loader_generalization=False,full_a3=False,
        performance_scope='end-to-end bounded process wall time, including helper/exec/I/O; no isolated kernel or steady-state claim',
        retained_heap_evidence={p:watched[p] for p in retained},qualification_complete=False)
    write(out/'summary.json',summary);write(out/'cases.json',results);write(out/'commands.json',commands)
    with (out/'cases.csv').open('x',newline='') as f:
        keys=['program','dataset','lane','status','attempted','exit','input_bytes','output_bytes','selected_sites','seconds','expected_sha256','actual_sha256','stderr_sha256','reason']
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(results)
    print(json.dumps(summary,sort_keys=True))
    return 0 if fatal is None and summary['counts']['PASS']==len(results) else 1

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except FileNotFoundError as error:
        print(json.dumps(dict(status='UNAVAILABLE',reason='required pinned input absent',path=error.filename,
                              qualification_complete=False)),file=sys.stderr)
        raise SystemExit(2)
