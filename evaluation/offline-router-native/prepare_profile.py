#!/usr/bin/env python3
"""Prepare an observer build plan or an unapproved final V2 profile; no dispatch.

Run only after source review, with an actual committed native revision. All
imported project bytes are authenticated first. Final profile output is a draft
for root review; execution still requires the separate explicit unsafe caller.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import types

MIB = 1048576
NATIVE = 'evaluation/offline-router-native/'
CRATE = 'evaluation/adjacent-b2/artifact-verifier/'
PROCESS_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
GIT_ENV = {'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8',
           'GIT_CONFIG_NOSYSTEM':'1', 'GIT_CONFIG_GLOBAL':'/dev/null', 'GIT_OPTIONAL_LOCKS':'0'}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact SHA256')
    return value


def decode(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            need(key not in value, 'duplicate JSON key');value[key]=item
        return value
    def constant(_): raise ValueError('nonfinite JSON')
    need(len(raw)<=MIB, 'bounded input JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def stamp(s): return [s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(path, cap=2*MIB):
    path=Path(path)
    need(path.is_absolute() and str(path)==os.path.normpath(str(path)), 'canonical absolute input')
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for name in path.parts[1:-1]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            before=os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=cap,'bounded regular input')
            chunks=[];left=before.st_size
            while left:
                part=os.read(fd,min(left,65536));need(part,'short input');chunks.append(part);left-=len(part)
            need(not os.read(fd,1) and stamp(before)==stamp(os.fstat(fd))==
                 stamp(os.stat(path.name,dir_fd=parent,follow_symlinks=False)),'stable input identity')
            raw=b''.join(chunks)
            return raw,dict(path=str(path),bytes=len(raw),sha256=sha(raw),stat=stamp(before))
        finally: os.close(fd)
    finally: os.close(parent)


def git(root,*args):
    return subprocess.check_output(['/usr/bin/git','--no-optional-locks','-C',str(root),*args],
                                   env=GIT_ENV,timeout=15)


class Sources:
    def __init__(self,root,revision):
        self.root=Path(root);self.revision=revision;self.held={}
        need(self.root.is_absolute() and self.root.resolve(strict=True)==self.root,'canonical root')
        need(type(revision) is str and re.fullmatch('[0-9a-f]{40}',revision),'actual native commit')
        need(git(self.root,'cat-file','-t',revision)==b'commit\n','native revision is a commit')
        self.pins={}
        rows=git(self.root,'ls-tree','-r','-z',revision,'--',NATIVE).split(b'\0')
        need(1<=sum(bool(row) for row in rows)<=128,'unchanged native source-count bound')
        for row in rows:
            if not row: continue
            metadata,path=row.split(b'\t',1);mode,kind,_=metadata.split()
            relative=path.decode('utf-8')
            need(mode in (b'100644',b'100755') and kind==b'blob' and relative.startswith(NATIVE),
                 'complete ordinary native source inventory')
            size=int(git(self.root,'cat-file','-s',revision+':'+relative))
            need(0<=size<=2*MIB,'bounded committed native source')
            raw=git(self.root,'show',revision+':'+relative)
            need(len(raw)==size,'whole committed native blob')
            current,pin=read(self.root/relative)
            need(current==raw,'working native source equals committed source')
            self.pins[relative]=sha(raw);self.held[str(self.root/relative)]=(raw,pin)
        need(1<=len(self.pins)<=128,'unchanged native source-count bound')
        need(Path(__file__).resolve(strict=True)==self.root/NATIVE/'prepare_profile.py' and
             NATIVE+'prepare_profile.py' in self.pins,'run the actual committed tracked reproducer')
        self.stable()

    def stable(self):
        current=git(self.root,'ls-files','-z','--',NATIVE).split(b'\0')
        need({p.decode() for p in current if p}==set(self.pins),'whole current tracked native inventory')
        for path,(raw,pin) in self.held.items():
            found,actual=read(path,max(MIB,len(raw)))
            need(found==raw and actual==pin,'source/input identity drift')

    def reference(self,reference,cap=MIB):
        need(type(reference) is dict and set(reference)=={'path','sha256'},'exact file reference')
        raw,pin=read(reference['path'],cap)
        need(sha(raw)==digest(reference['sha256']),'frozen input reference')
        previous=self.held.get(reference['path'])
        need(previous is None or previous==(raw,pin),'repeated input keeps original identity')
        self.held[reference['path']]=(raw,pin)
        return raw

    def load(self,relative):
        need(relative in self.pins,'required committed native source')
        raw,_=self.held[str(self.root/relative)]
        module=types.ModuleType('_profile_builder_'+Path(relative).stem)
        module.__file__=str(self.root/relative)
        exec(compile(raw,module.__file__,'exec'),module.__dict__)
        return module


def file_ref(path,d): return dict(path=str(path),sha256=digest(d))


def directory_ref(path,d): return dict(directory=str(path),sha256=digest(d))


def private(root,path):
    path=Path(path)
    need(path.is_absolute() and path.is_relative_to(root/'ignored') and
         path.parent.resolve(strict=True)==path.parent,'canonical private pathname')
    return path


def observer_plan(args):
    sources=Sources(args.root,args.native_revision);root=sources.root
    launch=sources.load(NATIVE+'native_launch.py')
    profile=file_ref(args.source_profile,args.source_profile_sha256)
    sources.reference(profile)
    capture=directory_ref(private(root,args.capture),args.capture_sha256)
    plan=dict(schema='LI2NATIVE-OBSERVER-BUILD-PLAN-1',root=str(root),native_sources=sources.pins,
        artifact_source_profile=profile,capture=capture,output=str(private(root,args.build_output)),
        destination=str(private(root,args.binary_output)))
    need(not os.path.lexists(plan['output']) and not os.path.lexists(plan['destination']),
         'fresh observer build and retained copy destinations')
    output=private(root,args.output)
    need(not os.path.lexists(output),'new observer plan file')
    modules=launch.artifact_modules(root,profile)
    store=modules.custody.Store(2*1024*MIB)
    try:
        _,_,_,stable=launch.build_inputs(root,plan,modules,store)
        stable();sources.stable()
    finally: store.close()
    sources.stable()
    pin=launch.write(output,plan,0o400)
    print(json.dumps(dict(status='PROSPECTIVE_OBSERVER_PLAN',plan=pin,native_revision=args.native_revision,
                          build_dispatches=0,native_dispatches=0),sort_keys=True))


def probe_measurement(sources,reference,captured,context):
    need(set(reference)=={'owner_source','owner_receipt','log','raw'},'exact measured probe input roster')
    # The external frozen inputs identify the separately reviewed owner source;
    # the instance wrapper may differ across hosts. This is not self-approval.
    need(sources.reference(reference['owner_source']), 'nonempty externally pinned reviewed owner source')
    receipt=decode(sources.reference(reference['owner_receipt']))
    logfile=sources.reference(reference['log'],8*MIB)
    raw=sources.reference(reference['raw'],16384)
    closed=receipt['closed']
    need(receipt['source_unchanged'] is True and type(receipt['attempts']) is int and receipt['attempts']==1 and
         type(closed['exit_code']) is int and closed['exit_code']==0 and closed['cleanup_complete'] is True and
         type(closed['reaped_descendants']) is int and closed['reaped_descendants']==0 and closed['termination'] is None,
         'actual successful unchanged-source owner cleanup, not a failed prior probe')
    need(type(receipt['wall_limit_seconds']) is int and receipt['wall_limit_seconds']==1200 and
         type(receipt['output_limit_bytes']) is int and receipt['output_limit_bytes']==8*MIB and
         receipt['hardware']=='AMD EPYC Zen 5 dev host','exact reviewed owner bounds/hardware')
    need(closed['private_log_sha256']==sha(logfile),'owner binds exact child stdout log')
    need(logfile.endswith(b'\n') and len(logfile.splitlines())==1,'exact single child JSON report')
    report=decode(logfile)
    probe=NATIVE+'probe_xstate.py'
    expected=[captured['tools']['python']['path'],'-B',probe,'--raw-output',reference['raw']['path']]
    need(receipt['command']==expected and receipt['env']['CARGO_TARGET_DIR']==str(sources.root/'target'),
         'exact owned probe command/root, not wrapper stdout or a candidate')
    need(context.B.identity(expected[0])==captured['tools']['python'],'same pinned probe Python tool')
    base=receipt['base'];delta=receipt['working_source_sha256']
    need(type(base) is str and re.fullmatch('[0-9a-f]{40}',base) and type(delta) is dict,'actual probe source snapshot')
    def effective(relative):
        return delta[relative] if relative in delta else sha(git(sources.root,'show',base+':'+relative))
    need(effective(probe)==sources.pins[probe]==report['probe_sha256'] and
         effective('evaluation/admission/processes.py')==PROCESS_SHA,'exact observed probe and owner-helper sources')
    expected_keys={'schema','hardware','probe_sha256','platform','request_bytes','xstate_bytes','xstate_sha256',
        'initial_status','terminal_status','child_started','child_reaped','kill_sent','absence_proof','raw_saved',
        'observation_complete','command_seconds','cleanup_seconds','errors','exec_dispatches','candidate_dispatches',
        'native_dispatches','qualification_complete','performance_eligible','elapsed_seconds'}
    need(set(report)==expected_keys and report['schema']=='LI2HOST-XSTATE-1' and
         report['hardware']=='AMD EPYC Zen 5 dev host' and report['platform']=='linux-x86_64','exact measured probe report')
    need(all(report[k] is True for k in ('child_started','child_reaped','kill_sent','raw_saved','observation_complete')) and
         report['errors']==[] and report['absence_proof']=='ECHILD' and
         type(report['initial_status']) is int and report['initial_status']==((signal.SIGSTOP<<8)|0x7f) and
         type(report['terminal_status']) is int and report['terminal_status']==signal.SIGKILL,
         'successful exact stopped/killed/reaped measurement child')
    need(all(type(report[k]) is int and report[k]==v for k,v in
         (('request_bytes',16384),('command_seconds',15),('cleanup_seconds',5),('exec_dispatches',0),
          ('candidate_dispatches',0),('native_dispatches',0))) and report['qualification_complete'] is False and
         report['performance_eligible'] is False,'unchanged probe bounds and no execution/qualification promotion')
    need(type(report['xstate_bytes']) is int and 576<=report['xstate_bytes']<=16384 and
         len(raw)==report['xstate_bytes'] and sha(raw)==report['xstate_sha256'],'actual full raw xstate length/hash')
    need(stat.S_IMODE(sources.held[reference['raw']['path']][1]['stat'][2])==0o400,'immutable raw measurement bytes')
    return report


def final_profile(args):
    raw,_=read(args.inputs,MIB);need(sha(raw)==digest(args.inputs_sha256),'frozen final builder inputs')
    inputs=decode(raw)
    need(set(inputs)=={'schema','root','native_revision','observer_plan','arguments','bootstrap','contract',
                      'observer_build','xstate'} and inputs['schema']=='LI2NATIVE-FINAL-PROFILE-INPUTS-1',
         'exact final builder input roster')
    sources=Sources(inputs['root'],inputs['native_revision']);root=sources.root
    sources.reference(file_ref(args.inputs,args.inputs_sha256))
    launch=sources.load(NATIVE+'native_launch.py');admission=sources.load(NATIVE+'final_admission.py')
    platform=sources.load(NATIVE+'final_platform.py');reader=sources.load(NATIVE+'final_bootstrap.py')
    resolver=sources.load(NATIVE+'dependency_constructors.py')
    required=admission.REQUIRED_NATIVE|{NATIVE+n for n in ('dependency_constructors.py','dependency_constructor_controls.py','probe_xstate.py')}
    need(required<=set(sources.pins) and sources.pins[NATIVE+'package.py']==admission.PACKAGE_SHA,'whole reviewed V2 source roster')
    package=sources.load(NATIVE+'package.py')
    plan=decode(sources.reference(inputs['observer_plan']))
    need(plan['native_sources']==sources.pins and plan['root']==str(root),'same committed native observer plan')
    common=plan['artifact_source_profile'];old=decode(sources.reference(common))
    modules=launch.artifact_modules(root,common)
    def artifact(name):return launch.source(root,CRATE+name+'.py',old['sources'][CRATE+name+'.py'])
    startup=artifact('startup_saved');completed=artifact('startup_completed')
    bootstrap=artifact('startup_bootstrap');dso=artifact('startup_dso')
    values=inputs['arguments']
    need(type(values) is dict and set(values)==set(admission.ARGUMENTS),'complete saved-main argument roster')
    parsed=types.SimpleNamespace(source_profile=Path(common['path']),source_profile_sha256=common['sha256'])
    for name,value in values.items():setattr(parsed,name,digest(value) if name.endswith('_sha256') else private(root,value))
    need(plan['capture']==directory_ref(parsed.capture,parsed.capture_sha256),'same independently captured originals')
    store=modules.custody.Store(2*1024*MIB);held=package.Custody();observer_store=None
    output=private(root,args.output);need(not os.path.lexists(output),'new owned draft output directory')
    output.mkdir(mode=0o700)
    try:
        saved=reader.authenticate(modules.ctx,modules.a,modules.legacy,modules.custody,modules.pins,
            modules.originals,startup,completed,modules.driver,bootstrap,dso,parsed,store,inputs['bootstrap'])
        contract_raw=sources.reference(inputs['contract'])
        contract,deps=platform.contract(contract_raw,inputs['contract']['sha256'],package,held)
        facts={};reviewed=dict(dependencies={},bootstraps={})
        for program in platform.PROGRAMS:
            item=saved['programs'][program]
            platform.main_facts(item,contract,inputs['contract']['sha256'],package,dso,dependency=resolver)
            namespace=resolver.Namespace(dict(main=item['main']['product']['candidate.elf'],bootstrap=item['bootstrap'],**deps),package,dso)
            facts[program]=dict(bootstrap=item['linked'],dependencies={})
            reviewed['bootstraps'][program]=sha(platform.canonical(item['linked']))
            reviewed['dependencies'][program]={}
            for role in platform.ROLES:
                value=platform.library_facts_v2(deps[role],role,package,dso,namespace)
                facts[program]['dependencies'][role]=value
                reviewed['dependencies'][program][role]=sha(platform.canonical(value))
        probe=probe_measurement(sources,inputs['xstate'],saved['completed']['captured'],modules.ctx)
        reviewed['xstate_bytes']=probe['xstate_bytes']
        build=inputs['observer_build'];need(set(build)=={'directory','sha256'},'exact observer build reference')
        build_raw=store.read(private(root,build['directory'])/'closed.json',MIB)
        need(sha(build_raw)==digest(build['sha256']),'actual frozen observer build closure')
        build_value=decode(build_raw);binary=build_value['copy']['destination']
        need(build_value['plan']['path']==inputs['observer_plan']['path'] and
             build_value['plan']['sha256']==inputs['observer_plan']['sha256'] and
             plan['output']==build['directory'] and plan['destination']==binary['path'],
             'same frozen observer plan, actual build directory and retained copy')
        profile=dict(schema='LI2STARTUP-FINAL-PROFILE-2',native_revision=inputs['native_revision'],native_sources=sources.pins,
            artifact_source_profile=common,arguments=values,bootstrap=inputs['bootstrap'],contract=inputs['contract'],
            reviewed=reviewed,observer=dict(binary=binary,build=build))
        def stable():
            saved['stable']();sources.stable();store.verify();held.verify()
            platform.contract(contract_raw,inputs['contract']['sha256'],package,held)
        # Read-only adapter for the existing raw build reader, never an admitted
        # Session or an execution capability. This reader does not dispatch.
        view=types.SimpleNamespace(profile=profile,stable=stable)
        _,observer_store,target,observer_stable=launch.observer_build(view,root)
        need(target==binary,'independently reconstructed exact observer copy')
        observer_stable();stable()
        files={}
        for program in platform.PROGRAMS:
            files[program]=launch.write(output/(program+'-facts.json'),facts[program],0o400)
        files['probe']=launch.write(output/'xstate-measurement.json',probe,0o400)
        observer_stable();stable()
    finally:
        try:
            if observer_store is not None:observer_store.close()
        finally:
            try:held.close()
            finally:store.close()
    sources.stable()
    # All custody close paths have finished before the draft profile is exposed.
    pin=launch.write(output/'proposed-profile.json',profile,0o400)
    print(json.dumps(dict(status='DRAFT_PROFILE_REQUIRES_ROOT_REVIEW',profile=pin,facts=files,
        input_sha256=args.inputs_sha256,execution_authorized=False,native_dispatches=0,
        qualification_complete=False,performance_eligible=False),sort_keys=True))


def main():
    need(not sys.flags.optimize,'assertions required')
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode',required=True)
    plan=sub.add_parser('observer-plan')
    for name in ('root','source-profile','capture','build-output','binary-output','output'):
        plan.add_argument('--'+name,type=Path,required=True)
    for name in ('native-revision','source-profile-sha256','capture-sha256'):
        plan.add_argument('--'+name,required=True)
    final=sub.add_parser('final-profile')
    final.add_argument('--inputs',type=Path,required=True);final.add_argument('--inputs-sha256',required=True)
    final.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.mode=='observer-plan':observer_plan(args)
    else:final_profile(args)


if __name__=='__main__':main()
