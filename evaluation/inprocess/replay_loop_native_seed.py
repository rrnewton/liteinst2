#!/usr/bin/env python3
"""Replay four retained seed rows and six corruptions; no build or subject.

Run from the clean repository root with --expect-revision REV40,
--native-receipt PATH --native-receipt-sha256 SHA --comparator-sha256 SHA and
--output FRESH_DIRECTORY on one reserved CPU. Two read-only Git calls precede
the guard that forbids every later process launch.
The original seed helper and source/ELF/raw admission stay unchanged. Only the
current, explicitly pinned require_seed_record helper supplies the new join.
Also pass --lifecycle-comparator-sha256 SHA to exercise its exact canonical seed
assertion with the same replayed seed and six mutations, not full admission.
This diagnostic cannot qualify an owner or replace any failed historical run.
"""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import sys
from types import SimpleNamespace

ROOT=Path.cwd().resolve()
NAMES=('seed-headers','seed-link','seed-libraries','seed-prerequisite')
ERROR='whole original independently qualified seed'
LIFECYCLE_ERROR='complete separately qualified seed capture'
BOUNDS={'cpu_seconds':30,'wall_seconds':60,'address_space_bytes':512<<20,'file_bytes':16<<20}


def need(ok,message):
    if not ok:raise ValueError(message)


def fact(path):
    p=Path(path);need(p.is_file()and not p.is_symlink(),'whole regular evidence')
    b=p.read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())


def decode(raw):
    def unique(items):
        d=dict(items);need(len(d)==len(items),'unique evidence keys');return d
    return json.loads(raw,object_pairs_hook=unique)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--native-receipt',type=Path,required=True)
    ap.add_argument('--native-receipt-sha256',required=True)
    ap.add_argument('--comparator-sha256',required=True)
    ap.add_argument('--lifecycle-comparator-sha256',required=True)
    ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    need(not sys.flags.optimize and sys.version_info[:2]==(3,12)and len(os.sched_getaffinity(0))==1,
         'assertions, Python3.12 and one externally reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision)and
         all(re.fullmatch('[0-9a-f]{64}',v)for v in(args.native_receipt_sha256,args.comparator_sha256)),
         'explicit current revision and whole receipt/comparator identities')
    need(re.fullmatch('[0-9a-f]{64}',args.lifecycle_comparator_sha256),'explicit whole lifecycle comparator identity')
    need(not args.output.exists(),'fresh diagnostic output')
    resource.setrlimit(resource.RLIMIT_CPU,(30,30));resource.setrlimit(resource.RLIMIT_AS,(512<<20,512<<20))
    resource.setrlimit(resource.RLIMIT_FSIZE,(16<<20,16<<20))
    def timeout(*unused):raise TimeoutError('bounded retained seed replay')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(60);sys.dont_write_bytecode=True
    args.output.mkdir(parents=True)
    result=dict(schema=1,profile='loop-seed-record-regression-v1',status='failed',phase='inputs',
        review_cpu=next(iter(os.sched_getaffinity(0))),bounds=BOUNDS,error_type=None,
        native_execution=0,builds=0,qualification_credit=False,performance_credit=False,
        historical_failure_reclassified=False,controls=[],source_unchanged=False,
        scope='Retained seed serialization regression only; original owner failure remains failed.')
    pins={};used=[]
    try:
        git=['/usr/bin/git','-c','index.threads=1','-c','core.preloadIndex=false']
        revision,tree=subprocess.check_output([*git,'rev-parse','HEAD','HEAD^{tree}'],cwd=ROOT).decode().splitlines()
        need(revision==args.expect_revision and not subprocess.check_output(
            [*git,'status','--porcelain','--untracked-files=no'],cwd=ROOT),'exact clean validator revision')
        result.update(validator_revision=revision,validator_tree=tree,validator_tracked_clean=True,git=fact(Path('/usr/bin/git').resolve()))
        path=args.native_receipt.resolve(strict=True);receipt_fact=fact(path)
        need(receipt_fact['sha256']==args.native_receipt_sha256,'explicit retained native receipt')
        a=decode(path.read_bytes());directory=path.parent
        need(a['schema']==1 and a['profile']=='persistent-loop-native-v2'and a['status']=='observed_native_references'and
             a['error']is None and a['final_errors']==[]and all(a[k]is True for k in
             ('source_unchanged','inputs_unchanged','cleanup_complete')),'closed complete native reference')
        hardware={k:a['hardware'][k]for k in('architecture','vendor_id','model name','cpu family','model','stepping',
            'microcode','kernel_version','kernel_release_sha256','probe_cpu','affinity_cpu_count')}
        flags=json.dumps(a['hardware']['isa_flags'],sort_keys=True,separators=(',',':')).encode()
        hardware.update(isa_flags_count=len(a['hardware']['isa_flags']),isa_flags_sha256=hashlib.sha256(flags).hexdigest())
        result.update(native_receipt=receipt_fact,original_source=a['source'],original_cpu=a['cpu'],original_hardware=hardware,
                      original_seed_status=a['seed_prerequisite']['status'],driver=fact(Path(__file__).resolve()),
                      reproduce=['python3','-B','evaluation/inprocess/replay_loop_native_seed.py',
                        '--expect-revision',revision,'--native-receipt','<RETAINED_NATIVE_RECEIPT>',
                        '--native-receipt-sha256',args.native_receipt_sha256,'--comparator-sha256',args.comparator_sha256,
                        '--lifecycle-comparator-sha256',args.lifecycle_comparator_sha256,
                        '--output','target/evaluation/inprocess/<FRESH_ATTEMPT>'])
        def pin(name):
            p=Path(name).resolve(strict=True);v=fact(p)
            need(v==a['inputs'][str(p)],'whole original seed input')
            need(str(p)not in pins or pins[str(p)]==v,'stable replay input');pins[str(p)]=v;return p
        def binary(name):
            p=Path(name).resolve(strict=True);v=fact(p)
            need(dict(v,mode=p.stat().st_mode&0o777)==a['artifacts'][str(p)],'whole actual seed artifact')
            need(str(p)not in pins or pins[str(p)]==v,'stable seed artifact');pins[str(p)]=v;return p
        comparator=ROOT/'evaluation/inprocess/persistent_loop_native_prerequisite.py'
        comparator_fact=fact(comparator)
        need(comparator_fact['sha256']==args.comparator_sha256,'exact current seed comparator')
        lifecycle=ROOT/'evaluation/inprocess/persistent_loop_lifecycle_prerequisite.py'
        lifecycle_fact=fact(lifecycle)
        need(lifecycle_fact['sha256']==args.lifecycle_comparator_sha256,'exact current lifecycle seed comparator')
        pin(ROOT/'evaluation/inprocess/unrolled_hash_owner.py')
        pin(ROOT/'evaluation/inprocess/persistent_dynamic.py')
        def forbidden(*unused,**kwargs):raise RuntimeError('process launch forbidden during retained replay')
        for name in('Popen','run','check_output','check_call','call'):setattr(subprocess,name,forbidden)
        os.system=forbidden
        sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
        import unrolled_hash_owner as original
        from persistent_dynamic import digest
        from persistent_loop_native_prerequisite import require_seed_record
        # Exercise the actual one named lifecycle join, without importing or
        # invoking that full prerequisite on a native-only receipt.
        lifecycle_tree=ast.parse(lifecycle.read_bytes())
        joins=[n for n in ast.walk(lifecycle_tree)if isinstance(n,ast.Call)and
               isinstance(n.func,ast.Name)and n.func.id=='need'and len(n.args)==2 and
               isinstance(n.args[1],ast.Constant)and n.args[1].value==LIFECYCLE_ERROR]
        expected_join=ast.parse("need(digest(native_holder['seed_prerequisite'])==digest(a['seed_prerequisite']),"
                                "'complete separately qualified seed capture')",mode='eval').body
        need(len(joins)==1 and ast.dump(joins[0])==ast.dump(expected_join),'one exact whole canonical lifecycle seed assertion')
        lifecycle_code=compile(ast.Expression(body=joins[0]),str(lifecycle),'eval')
        def lifecycle_seed(recorded):
            return eval(lifecycle_code,dict(__builtins__={},need=original.need,digest=digest,
                native_holder={'seed_prerequisite':replayed},a={'seed_prerequisite':recorded}))
        # Every imported repository dependency, except the explicit comparator
        # successor and this new script, is a whole original native input.
        def imports():
            for module in tuple(sys.modules.values()):
                name=getattr(module,'__file__',None)
                if not name:continue
                p=Path(name).resolve()
                if p==Path(__file__).resolve()or p==comparator:continue
                if p.is_relative_to(ROOT)and not p.is_relative_to(ROOT/'target'):pin(p)
        imports();rows={c['name']:c for c in a['commands']}
        need(len(rows)==len(a['commands'])and all(n in rows for n in NAMES),'unique complete retained command roster')
        def recorded(name,argv,profile='metadata',expected=0,env=None,record=False):
            need(len(used)<4 and name==NAMES[len(used)]and record is False,'only the four original seed invocations')
            row=rows[name]
            need(row['argv']==list(map(str,argv))and row['environment']==dict(original.ENV if env is None else env)and
                 row['profile']==profile and row['bounds']==original.BOUNDS[profile]and
                 type(row['exit'])is int and row['exit']==row['expected_exit']==expected==0 and
                 row['capture_limit']==16<<20 and row['reaped']is True and row['timed_out']is False and
                 row['error']is None and row['cleanup_errors']==[]and type(row['descriptors'])is list and
                 all(d['closed']is True for d in row['descriptors']),'whole actual bounded seed command and cleanup')
            need(decode(binary(directory/(name+'.json')).read_bytes())==row,'whole retained seed command row')
            out={}
            for stream,value in row['captures'].items():
                need(Path(value['file']).name==value['file'],'local retained seed capture')
                p=binary(directory/value['file']);need(fact(p)=={k:value[k]for k in('bytes','sha256')},'whole seed capture')
                out[stream]=p.read_bytes()
            need(set(out)=={'stdout','stderr'},'both complete seed streams');used.append(name)
            return row,out['stdout'],out['stderr']
        builder=SimpleNamespace(tools={k:Path(v['path'])for k,v in a['build']['tools'].items()},environment=a['build']['environment'])
        holder=dict(cpu=a['cpu'],commands=a['commands'][:next(i for i,c in enumerate(a['commands'])if c['name']=='seed-prerequisite')+1],
            seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=original.BOUNDS['seed'],
                completed_applications=0,owner_subjects=0,performance_credit=False))
        result['phase']='original_seed_replay'
        original.seed_prerequisite(builder,directory,pin,binary,recorded,holder)
        replayed=holder['seed_prerequisite'];saved=a['seed_prerequisite'];differences=[]
        def compare(x,y,path):
            if type(x)!=type(y):
                need(type(x)is tuple and type(y)is list and(path=='format.components'or path.startswith('format.components[')or
                     path=='format.cpuid'or path.startswith('format.cpuid[')),'only declared JSON array transport differs')
                differences.append(path)
            if isinstance(x,dict)and isinstance(y,dict):
                need(set(x)==set(y),'whole seed key equality')
                for k in x:compare(x[k],y[k],path+'.'+k if path else k)
            elif isinstance(x,(tuple,list))and isinstance(y,(tuple,list)):
                need(len(x)==len(y),'whole seed sequence length')
                for i,(u,v)in enumerate(zip(x,y)):compare(u,v,path+'['+str(i)+']')
            else:need(type(x)is type(y)and x==y,'every seed scalar value and type preserved')
        compare(replayed,saved,'')
        need(used==list(NAMES)and replayed!=saved and differences,'actual original JSON representation regression')
        require_seed_record(replayed,saved)
        lifecycle_seed(saved)
        result['lifecycle_join']=dict(comparator=lifecycle_fact,canonical_equal=True,controls=[],
            scope='Exact lifecycle seed assertion only; no lifecycle prerequisite or owner credit.')
        result['phase']='tamper_controls'
        for label in('cpuid_word','component_extent','fxsave_hash','missing_field','extra_field','bool_int'):
            changed=copy.deepcopy(saved)
            if label=='cpuid_word':changed['format']['cpuid'][0][2]^=1
            elif label=='component_extent':changed['format']['components'][0][1]^=1
            elif label=='fxsave_hash':
                h=changed['profile']['full_fxsave_sha256'];changed['profile']['full_fxsave_sha256']=('1'if h[0]=='0'else'0')+h[1:]
            elif label=='missing_field':del changed['profile']['fip']
            elif label=='extra_field':changed['unexpected_seed_field']=0
            else:changed['profile']['accepted']=1
            need(digest(changed)!=digest(saved),'nonidentity whole serialized seed mutation')
            try:require_seed_record(replayed,changed)
            except ValueError as error:need(str(error)==ERROR,'exact intended whole-seed rejection')
            else:raise ValueError('accepted seed corruption '+label)
            result['controls'].append(label)
            try:lifecycle_seed(changed)
            except ValueError as error:need(str(error)==LIFECYCLE_ERROR,'exact intended lifecycle whole-seed rejection')
            else:raise ValueError('accepted lifecycle seed corruption '+label)
            result['lifecycle_join']['controls'].append(label)
        result['phase']='closure';imports()
        need(all(fact(Path(p))==v for p,v in pins.items())and fact(path)==receipt_fact and
             fact(comparator)==comparator_fact and fact(Path(__file__).resolve())==result['driver'],'whole replay source/evidence unchanged')
        need(fact(lifecycle)==lifecycle_fact and result['lifecycle_join']['controls']==result['controls'],
             'whole lifecycle comparator unchanged and all six original corruptions rejected')
        result.update(status='passed',phase='complete',source_unchanged=True,comparator=comparator_fact,
            seed_raw=fact(directory/'seed-prerequisite.stdout'),seed_elf=fact(directory/'seed-probe'),
            canonical_seed_sha256=digest(replayed),python_equal=False,canonical_equal=True,
            tuple_list_nodes=len(differences),difference_paths_sha256=digest(differences),
            component_nodes=sum(p.startswith('format.components')for p in differences),
            cpuid_nodes=sum(p.startswith('format.cpuid')for p in differences),
            original_seed_profile=saved['profile'],pinned_inputs=dict(count=len(pins),sha256=digest(pins)),
            commands=[dict(name=n,profile=rows[n]['profile'],bounds=rows[n]['bounds'],exit=rows[n]['exit'],
                expected_exit=rows[n]['expected_exit'],validation_duration_ns=rows[n]['duration_ns'],
                captures={k:{q:v[q]for q in('bytes','sha256')}for k,v in rows[n]['captures'].items()})for n in NAMES])
    except Exception as error:
        result['error_type']=type(error).__name__
        print(type(error).__name__+': '+str(error),file=sys.stderr)
    finally:signal.alarm(0)
    payload=json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n'
    need(all(t not in payload for t in(str(ROOT),str(Path.home()),'/home/','/tmp/')),'compact public output excludes private paths')
    with(args.output/'result.json').open('x')as stream:stream.write(payload)
    print(json.dumps(dict(status=result['status'],result=fact(args.output/'result.json')),sort_keys=True))
    return int(result['status']!='passed')


if __name__=='__main__':raise SystemExit(main())
