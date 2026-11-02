#!/usr/bin/env python3
"""Release unit-cost diagnostic using an explicit closed effects-native archive; no qualification or retry."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import statistics
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[3]
PACKET=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
RUST_SOURCES=('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs',
              'admission_oneshot.rs','region.rs','mov_guard.rs','scalar_read.rs','loop_scalar.rs','byte_mov_guard.rs')
BOUNDS=[30,512<<20,16<<20,60]
NAMES=('empty_loop','raw_getpid','rx_ret_call','mprotect_same_rx','mprotect_r_rx_ret_pair',
       'nx_signal_ucontext_ret','nx_fault_grant_ret_cycle','maps_open_close','devnull_read',
       'maps_fresh_open_read_close','minor_first_write','decoder_scan_ls','decoder_scan_true',
       'decoder_scan_helper','native_policy_ls','native_policy_true','native_policy_helper',
       'source_lease_policy_ls','source_lease_policy_true','source_lease_policy_helper',
       'membarrier_sync_core','mincore_absent_predecessor')

def need(ok,message):
    if not ok:raise ValueError(message)
def fact(path):
    raw=Path(path).read_bytes()
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def git(*args):
    return subprocess.check_output(['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false',*args],cwd=ROOT)
def clean(revision):
    need(git('rev-parse','HEAD').decode().strip()==revision and not git('status','--porcelain','--untracked-files=no'),'exact clean revision')
    return dict(revision=revision,tree=git('rev-parse','HEAD^{tree}').decode().strip(),tracked_clean=True)
def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def portable(value):
    if isinstance(value,str):
        return value.replace(str(ROOT)+'/', '').replace(str(Path(sys.executable).resolve()),'{PYTHON3_12}')
    if isinstance(value,list):return [portable(x) for x in value]
    if isinstance(value,dict):return {portable(k):portable(v) for k,v in value.items()}
    return value

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--native-receipt',type=Path,required=True);ap.add_argument('--native-sha256',required=True)
    args=ap.parse_args();os.chdir(ROOT)
    native_path=args.native_receipt.resolve(strict=True)
    need(native_path.name=='receipt.json' and native_path.parent.parent==ROOT/'target/evaluation/inprocess' and
         re.fullmatch('[0-9a-f]{64}',args.native_sha256),'explicit local closed native receipt and whole digest')
    need(sys.version_info[:2]==(3,12) and not sys.flags.optimize,'Python3.12 with assertions')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision),'full revision')
    affinity=os.sched_getaffinity(0);need(len(affinity)==1,'one externally reserved singleton')
    cpu=next(iter(affinity));out=args.output.absolute()
    need(out.parent==ROOT/'target/evaluation/inprocess' and out.name.startswith('admission-unit-cost-') and not out.exists(),'fresh diagnostic output')
    source=clean(args.expect_revision);out.mkdir()
    r=dict(schema=1,profile='admission-unit-cost-diagnostic-v1',status='failed',source=source,cpu=cpu,
           bounds=BOUNDS,commands=[],inputs={},artifacts={},source_unchanged=False,inputs_unchanged=False,
           artifacts_unchanged=False,cleanup_complete=False,error=None,final_errors=[],qualification_credit=False,performance_target_credit=False)
    def pin(path):
        path=Path(path).absolute();value=fact(path);key=str(path)
        need(key not in r['inputs'] or r['inputs'][key]==value,'stable complete input');r['inputs'][key]=value;return value
    def artifact(path):
        value=fact(path);r['artifacts'][str(path)]=value;return value
    def close_inputs():
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all used input bytes unchanged')
    try:
        pin(__file__);pin(PACKET/'bench.c');pin(PACKET/'policy_lease.c')
        need(pin(native_path)['sha256']==args.native_sha256,'exact supplied closed native receipt')
        native=json.loads(native_path.read_bytes())
        need(native['profile']=='persistent-loop-effects-native-v1' and native['status']=='observed_native_references' and native['source_unchanged'] is True and
             native['inputs_unchanged'] is True and native['cleanup_complete'] is True and
             native['error'] is None and native['final_errors']==[],'closed native archive producer')
        need(native['source']['revision']==native['revision'] and native['source']['tracked_clean'] is True and
             len(native['commands'])==82 and len(native['cases'])==28 and
             {(x['mode'],x['placement']) for x in native['cases']}=={(c,p) for c in range(7) for p in range(4)} and
             all(x['status']=='observed_native_reference' for x in native['cases']) and
             all(x['exit']==x['expected_exit']==0 and x['timed_out'] is False and x['reaped'] is True and
                 x['error'] is None and x['cleanup_errors']==[] and type(x['descriptors']) is list and
                 all(d['closed'] is True for d in x['descriptors']) for x in native['commands']),
             'closed original82/28 producer metadata; archive provenance only, not reference replay')
        build=native['build'];deps=build['dep_info']
        need(build['status']=='passed' and build['started'] is True and build['command_completed'] is True and
             build['configuration_unchanged'] is True and build['final_errors']==[] and
             build['registry_before']==build['registry_after'] and
             set(deps)=={'tools/page-entry/selected/decoder/src/'+name for name in RUST_SOURCES} and
             build['decoder_features']==['scalar-region','scalar-span','linked-epoch','mov-guard','scalar-read','loop-effects'],
             'exact release decoder feature/source closure')
        for path,value in deps.items():need(pin(ROOT/path)==value,'current Rust source equals actual compiled source')
        for name in ('Cargo.toml','Cargo.lock'):
            p=SELECTED/'decoder'/name;need(pin(p)==native['inputs'][str(p)],'decoder build configuration unchanged')
        ar=build['artifacts']['decoder.a'];archive=Path(ar['path'])
        need(archive==native_path.parent/'artifacts/decoder.a' and pin(archive)=={k:ar[k] for k in ('bytes','sha256')} and
             archive.stat().st_mode&0o7777==ar['mode'] and
             native['artifacts'][str(archive)]=={k:ar[k] for k in ('bytes','sha256','mode')},'actual retained release archive')
        r['archive_provenance']=dict(receipt=dict(path=str(native_path),**fact(native_path)),archive=dict(path=str(archive),**fact(archive)),
            compiled_revision=native['revision'],current_13_rust_sources_equal=True,same_revision_native_credit=False,
            scope='Reuse exact supplied archive and source facts; no native reference replay or qualification credit')
        # The original bounded process owner is reused unchanged.
        sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
        from page_selected_process import invoke
        from run import hardware
        for module in list(sys.modules.values()):
            f=getattr(module,'__file__',None)
            if f and Path(f).resolve().is_relative_to(ROOT):
                p=Path(f).resolve();pin(p)
                if not p.is_relative_to(PACKET):need(git('show',args.expect_revision+':'+str(p.relative_to(ROOT)))==p.read_bytes(),'loaded helper equals current committed source')
        r['hardware']=hardware(cpu)
        gcc=Path(build['tools']['cc']['path']).resolve(strict=True);pin(gcc);pin(Path(sys.executable).resolve());pin('/usr/bin/git')
        need(fact(gcc)=={k:build['tools']['cc'][k] for k in ('bytes','sha256')},'same GCC as retained archive linkage')
        for key in ('as','ld','cc1','collect2'):
            tool=build['tools'][key];need(pin(tool['path'])=={k:tool[k] for k in ('bytes','sha256')},'same compiler tool bytes')
        sources=[PACKET/'bench.c',PACKET/'policy_lease.c',SELECTED/'native_policy.c']
        for p in sources:pin(p)
        flags=['-std=gnu11','-O2','-g','-fno-builtin','-fno-stack-protector',
               '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only',
               '-fno-omit-frame-pointer','-Wall','-Wextra','-Werror','-I'+str(SELECTED)]
        def command(name,argv):
            row=dict(name=name,profile='micro_build' if name!='measure' else 'micro_measure',argv=list(map(str,argv)),
                     bounds=BOUNDS,capture_limit=16<<20,expected_exit=0);r['commands'].append(row);save(out/'receipt.json',r)
            stdout,stderr=invoke(row,out,cpu)
            need(row['exit']==row['expected_exit']==0 and row['timed_out'] is False and row['error'] is None and
                 row['reaped'] is True and row['cleanup_errors']==[] and type(row['descriptors']) is list and
                 all(x['closed'] is True for x in row['descriptors']),'bounded command success and cleanup')
            return stdout,stderr
        headers,err=command('headers',[gcc,*flags,'-M','-MT','unit_cost_deps',*sources]);need(not err,'header extraction stderr empty')
        text=headers.decode().replace('\\\n',' ').replace('unit_cost_deps:',' ')
        for word in shlex.split(text):pin(Path(word) if Path(word).is_absolute() else out/word)
        binary=out/'unit-cost'
        _,err=command('build',[gcc,*flags,*sources,archive,'-Wl,-z,now,-z,relro,--no-undefined',
                              '-ldl','-lpthread','-lm','-o',binary]);need(not err,'release build stderr empty');artifact(binary)
        fixture=native_path.parent/'application/tunables-loop-paired';app=native['application_build']
        need(app['status']=='passed' and app['translation_units']==6 and
             pin(fixture)==app['artifact']=={k:native['artifacts'][str(fixture)][k] for k in ('bytes','sha256')} and
             fixture.stat().st_mode&0o777==native['artifacts'][str(fixture)]['mode'],'exact closed fixture ELF')
        for path,value in app['headers'].items():
            need(pin(path)==value==native['inputs'][path],'fixture actual compiler-M source/header inputs unchanged')
        for path,key in ((SELECTED/'tests/tunables_loop_paired_app/build.sh','recipe'),
                         (SELECTED/'tests/persistent_direct_frontier_app/app.ld','linker')):
            need(pin(path)==app[key]==native['inputs'][str(path)],'current exact fixture recipe and linker')
        r['fixture_provenance']=dict(artifact=dict(path=str(fixture),**fact(fixture)),
            headers=len(app['headers']),current_inputs_equal=True,executed_by_micro=False)
        windows=[];r['scan_inputs']=[]
        for name,path,page in (('ls',Path('/usr/bin/ls'),0x5000),('true',Path('/usr/bin/true'),0x2000),('helper',fixture,0x200021000)):
            pin(path);raw=path.read_bytes();eh=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
            need(eh[0][:7]==b'\x7fELF\x02\x01\x01' and eh[2]==62 and eh[9]==56,'actual ELF64 x86-64 page source')
            matches=[]
            for i in range(eh[10]):
                ph=struct.unpack_from('<IIQQQQQQ',raw,eh[5]+i*eh[9])
                if ph[0]==1 and ph[1]==5 and ph[3]<=page-14 and page+4096+14<=ph[3]+ph[5]:matches.append(ph)
            need(len(matches)==1,'one whole RX file-backed page and real executable halos')
            ph=matches[0];offset=ph[2]+page-14-ph[3];data=raw[offset:offset+4124];need(len(data)==4124,'whole page window')
            dest=out/(name+'.window');dest.write_bytes(data);artifact(dest);windows.append(dest)
            r['scan_inputs'].append(dict(name=name,elf=dict(path=str(path),**fact(path)),page=page,file_offset=offset,
                requested_page_bytes=4096,halo_before=14,halo_after=14,window=dict(path=str(dest),**fact(dest))))
        close_inputs();raw,stderr=command('measure',[binary,*windows])
        lines=stderr.decode().splitlines();need(len(lines)==4,'three page diagnostics plus one initialization record')
        for i,(line,window) in enumerate(zip(lines[:3],windows)):
            match=re.fullmatch(r'WINDOW (\d+) (\d+) ([0-9a-f]{16}) starts=(\d+) candidates=(\d+) invalid=(\d+) truncated=(\d+)',line)
            need(match is not None,'exact page diagnostic grammar')
            index,length,digest,starts,candidates,invalid,truncated=match.groups();h=1469598103934665603
            for byte in window.read_bytes():h=((h^byte)*1099511628211)&((1<<64)-1)
            need(int(index)==i and int(length)==4124 and digest==f'{h:016x}' and int(starts)==4110,'actual input window and complete start count')
            r['scan_inputs'][i]['result']=dict(starts=int(starts),candidates=int(candidates),invalid=int(invalid),truncated=int(truncated))
        init=re.fullmatch(r'INIT abi=(\d+) phase=(\d+) arena=(\d+) retained=(\d+) allocations=(\d+) deallocations=(\d+) sync_query=(\d+) sync_register=(\d+)',lines[3])
        need(init is not None,'typed actual initialization and sync registration')
        r['initialization']=dict(zip(('abi','phase','arena','retained','allocations','deallocations','sync_query','sync_register'),map(int,init.groups())))
        need(r['initialization']['abi']==1 and r['initialization']['phase']==2 and r['initialization']['sync_register']==0,'sealed decoder and registered sync')
        (out/'raw.csv').write_bytes(raw);artifact(out/'raw.csv')
        reader=csv.DictReader(io.StringIO(raw.decode()))
        need(reader.fieldnames=='name,sample,iterations,elapsed_ns,mprotect_calls,signals,opens,reads,closes,read_bytes,scan_starts,scan_candidates,policy_mask,minor_pages,checksum,minor_faults,major_faults,sync_core_calls,mincore_calls'.split(','),'exact raw columns')
        values=list(reader)
        expected=[('decoder_initialize',-1,1),('first_nx_fault_grant_ret_cycle',-1,1),('first_nx_ucontext_ret_control',-1,1)]
        def iterations(t):return 2000 if t in (5,6,14,15,16) else 500 if t in (7,9) else 256 if t==10 else 64 if 11<=t<=13 else 20000
        for sample in range(11):
            order=range(21,-1,-1) if sample%2 else range(22)
            expected.extend((NAMES[t],sample,iterations(t)) for t in order)
        need(len(values)==len(expected)==245,'all initialization/first/warmup/ten measured batches')
        for row,wanted in zip(values,expected):
            for key in row:
                if key!='name':row[key]=int(row[key])
            need((row['name'],row['sample'],row['iterations'])==wanted and row['elapsed_ns']>=0,'fixed ordered raw row')
            n=row['iterations'];name=row['name']
            need(row['signals']==(n if 'nx_' in name else 0),'exact actual signal count')
            need(row['mprotect_calls']==(2*n if name in ('mprotect_r_rx_ret_pair','nx_fault_grant_ret_cycle','first_nx_fault_grant_ret_cycle') else n if name=='mprotect_same_rx' else 0),'exact timed permission call count')
            need(row['scan_starts']==(4110*n if name.startswith('decoder_scan_') else 0),'complete shared all-byte-start scans')
            if name.startswith('decoder_scan_'):
                d=('ls','true','helper').index(name.removeprefix('decoder_scan_'))
                need(row['scan_candidates']==r['scan_inputs'][d]['result']['candidates']*n and row['checksum']==row['scan_candidates'],'exact shared scan results every iteration')
            else:need(row['scan_candidates']==0,'non-scan rows have no decoder result')
            need(row['sync_core_calls']==(n if name=='membarrier_sync_core' else 0) and
                 row['mincore_calls']==(n if name=='mincore_absent_predecessor' else 0),'exact successful sync and expected-ENOMEM probe counts')
            if name.startswith('source_lease_policy_'):need(row['policy_mask']==2 and row['checksum']==2*n,'actual source-lease blanket refusal counted separately')
            if name.startswith('native_policy_'):need(row['checksum']==row['policy_mask']*n,'same complete byte-policy result every iteration')
            if name in ('maps_open_close','maps_fresh_open_read_close'):need(row['opens']==row['closes']==n,'all fresh maps descriptors closed')
            if name=='maps_fresh_open_read_close':need(row['reads']>=2*n and row['read_bytes']>0,'full read including EOF')
            if name=='devnull_read':need(row['reads']==n and row['read_bytes']==0,'syscall-only EOF control')
            if name=='minor_first_write':need(row['minor_pages']==n,'one write to each newly mapped4KiB page')
        r['samples']=values;r['status']='observed_component_unit_costs'
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:need(clean(args.expect_revision)==source,'source closure');r['source_unchanged']=True
        except BaseException as error:r['final_errors'].append('source: '+str(error))
        try:close_inputs();r['inputs_unchanged']=True
        except BaseException as error:r['final_errors'].append('inputs: '+str(error))
        try:
            need(all(fact(p)==value for p,value in r['artifacts'].items()),'complete output bytes unchanged')
            for row in r['commands']:
                need(set(row['captures'])=={'stdout','stderr'},'two exact command captures')
                for stream,value in row['captures'].items():
                    need(value['file']==row['name']+'.'+stream and fact(out/value['file'])=={k:value[k] for k in ('bytes','sha256')},'whole final capture join')
            r['artifacts_unchanged']=True
        except BaseException as error:r['final_errors'].append('artifacts: '+str(error))
        r['cleanup_complete']=all(x.get('reaped') is True and x.get('cleanup_errors')==[] and all(d['closed'] is True for d in x.get('descriptors',[])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']:r['status']='failed'
        save(out/'receipt.json',r)
    if r['status']!='failed':
        stats=[]
        for name in NAMES:
            rows=[x for x in r['samples'] if x['name']==name and x['sample']>0]
            need(len(rows)==10,'all ten raw batches retained')
            times=[x['elapsed_ns']/x['iterations'] for x in rows]
            quartiles=statistics.quantiles(times,n=4,method='inclusive')
            stats.append(dict(name=name,batches=10,iterations_per_batch=rows[0]['iterations'],
                              median_ns_per_iteration=statistics.median(times),q1_ns_per_iteration=quartiles[0],q3_ns_per_iteration=quartiles[2],
                              min_ns_per_iteration=min(times),max_ns_per_iteration=max(times)))
        hardware={k:v for k,v in r['hardware'].items() if not k.startswith('runner_') and k!='isa_flags'}
        hardware['isa_flags_sha256']=hashlib.sha256(json.dumps(r['hardware']['isa_flags'],separators=(',',':')).encode()).hexdigest()
        public=portable(dict(schema=1,status=r['status'],scope='isolated component costs, not complete admission or guest timing',
            source=source,cpu=cpu,hardware=hardware,bounds=BOUNDS,receipt=dict(path=str(out/'receipt.json'),**fact(out/'receipt.json')),
            driver=dict(path=str(Path(__file__)),**fact(__file__)),reproduce_argv=[sys.executable,'-B',str(Path(__file__)),
            '--expect-revision',args.expect_revision,'--native-receipt','{CLOSED_NATIVE_RECEIPT}',
            '--native-sha256',args.native_sha256,'--output','{FRESH_OUTPUT}'],archive_provenance=r['archive_provenance'],
            fixture_provenance=r['fixture_provenance'],
            scan_inputs=r['scan_inputs'],commands=[{k:x[k] for k in ('name','argv','exit','duration_ns','timed_out','reaped')} for x in r['commands']],
            raw_csv=dict(path=str(out/'raw.csv'),**fact(out/'raw.csv')),statistics=stats,first_samples=r['samples'][:3],initialization=r['initialization'],
            warmup_batches=1,measured_batches=10,quartiles='inclusive linear interpolation',no_outlier_removal=True,no_overhead_subtraction=True,
            overlap='NX complete cycle includes revoke, signal delivery, checked handler grant, sigreturn and RET. Permission-pair/call and ucontext-skip rows are controls, not disjoint summands.',
            scan_scope='Initialized, warmed shared decoder scans4110 starts for a4096B page plus authenticated14B halos; each call includes whole88B summary equality. Actual native-policy byte scanner and constant source-lease refusal are separate rows. Initialization is one process cost, not a per-page charge.',
            clock='CLOCK_MONOTONIC_RAW batch endpoints; two clock calls per row, not subtracted',
            first_touch='Code, altstack and scan data pre-touched; first signal retained separately. minor_first_write uses fresh anonymous pages with THP disabled; mmap/madvise/munmap excluded.',
            maps_scope='Fresh openat/read-through-EOF/close syscall sequence only; no parser, maintained view, or loader validation.',
            sync_scope='QUERY and REGISTER once before timing; each sync row calls PRIVATE_EXPEDITED_SYNC_CORE. Source has one sync after each native admission and one per nonempty close, not one per closed page. Neither is included in the NX cycle.',
            mincore_scope='One absent predecessor page adjacent to a retained mapping; every mincore returns exact -ENOMEM. This models the maintained-view probe syscall, not the entire hit path.',
            qualification_credit=False,whole_admission_cost=False,performance_target_credit=False))
        try:
            encoded=json.dumps(public,sort_keys=True,indent=2)+'\n'
            need(len(encoded.encode())<=24000 and str(ROOT) not in encoded and '/home/' not in encoded and platform.node() not in encoded,'bounded portable summary')
            (out/'public.json').write_text(encoded)
        except BaseException as error:
            r['status']='failed';r['error']='public: '+type(error).__name__+': '+str(error);save(out/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],receipt=str((out/'receipt.json').relative_to(ROOT))),sort_keys=True))
    return int(r['status']=='failed')
if __name__=='__main__':raise SystemExit(main())
