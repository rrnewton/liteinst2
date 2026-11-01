"""Fresh finite three-resident build/native/gated observation; offline audit is mandatory."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,json,os,re,struct
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV,save,need,interpreter
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from direct_frontier_loop_helpers import prepare_inputs
from unrolled_hash_owner import seed_prerequisite
from call_owner.custody import check_archive
from resident_three import build,native_prerequisites,terminal_reports

MASK=0xffffffffbffbfae7
BUILD=[30,512<<20,16<<20,60]
NATIVE=[5,512<<20,16<<20,15]
INSPECT=[10,256<<20,4<<20,20]


def fact(path):
    p=Path(path);data=p.read_bytes()
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=format(p.stat().st_mode&0o777,'04o'))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','flags-native','helper-native'):
        p.add_argument('--'+name+'-receipt',type=Path,required=True)
        p.add_argument('--'+name+'-receipt-sha256',required=True)
    p.add_argument('--cpu',type=int,required=True);p.add_argument('--expect-revision',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();private=a.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess' and not private.exists(),'fresh direct output child')
    need(not sys.flags.optimize and a.cpu>=0 and sorted(os.sched_getaffinity(0))==[a.cpu],
         'assertions enabled and exact externally reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_revision) and all(re.fullmatch('[0-9a-f]{64}',v) for v in
         (a.archive_receipt_sha256,a.flags_native_receipt_sha256,a.helper_native_receipt_sha256)),
         'explicit source and complete prerequisite hashes')
    private.mkdir();receipt=private/'receipt.json'
    r=dict(schema=1,profile='resident-three-observation-v1',status='failed',cpu=a.cpu,
        source=source(),hardware=hardware(a.cpu),commands=[],inputs={},aliases={},artifacts={},
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,
        qualification_credit=False,performance_credit=False,equivalence_credit=False,
        native_subjects=0,gated_subjects=0,error=None,final_errors=[],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,bounds=NATIVE,
            completed_applications=0,owner_subjects=0,performance_credit=False))

    def pin(path):
        alias=Path(path).absolute();q=alias.resolve(strict=True);v=fact(q)
        need(str(q)not in r['inputs']or r['inputs'][str(q)]==v,'stable whole input')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(q),'stable whole alias')
        r['inputs'][str(q)]=v;r['aliases'][str(alias)]=str(q);return q

    def binary(path):
        q=Path(path).resolve(strict=True);need(q.is_relative_to(private),'owned output artifact')
        v=fact(q);need(str(q)not in r['artifacts']or r['artifacts'][str(q)]==v,'immutable actual artifact')
        r['artifacts'][str(q)]=v;return q

    def closure():
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'all literal input aliases unchanged')
        need(all(fact(p)==v for p,v in r['artifacts'].items()),'all completed artifacts unchanged')
        need(sorted(os.sched_getaffinity(0))==[a.cpu],'same actual reserved CPU')

    def run(name,argv,profile='metadata',env=None,record=False):
        closure();need(not any(v['name']==name for v in r['commands']),'unique fixed command; no retry')
        bounds=NATIVE if profile in ('finite','seed') else INSPECT if profile=='inspect' or name=='seed-headers' else BUILD
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=list(bounds),
            environment=dict(ENV if env is None else env),capture_limit=16<<20,expected_exit=0)
        r['commands'].append(row);save(receipt,r)
        try:out,err=program_invoke(row,private,a.cpu,record=True) if record else invoke(row,private,a.cpu)
        finally:
            for c in row.get('captures',{}).values():binary(private/c['file'])
            save(receipt,r)
        need(row['exit']==0 and row['reaped']is True and row['timed_out']is False and row['error']is None and
             not row['cleanup_errors'] and all(v['closed']is True for v in row['descriptors']),
             'bounded successful '+name)
        return row,out,err

    try:
        r['revision']=r['source']['revision']
        need(r['source']['revision']==a.expect_revision,'exact clean current revision')
        pin(__file__);contract=json.loads(pin(HERE/'CONTRACT.json').read_bytes())
        for relative in contract['reader_paths']:pin(ROOT/relative)
        for name in ('build.py','native_prerequisites.py','terminal_reports.py','native_launch.py','launch.py','audit.py','audit_semantics.py'):
            pin(HERE/name)
        archive_receipt=pin(a.archive_receipt)
        archive,archive_build,_,_,old=check_archive(archive_receipt,a.archive_receipt_sha256,r,pin)
        r['archive_prerequisite']=dict(path=str(archive_receipt),**fact(archive_receipt))
        r['archive']=dict(receipt=fact(archive_receipt),revision=old['revision'],archive=fact(archive))
        tools={name:pin(archive_build['tools'][name]['path'])for name in ('cc','cc1','collect2','as','ld','nm','git')}
        tools['python']=pin(sys.executable)
        need(fact(tools['python'])==fact(pin(archive_build['tools']['python']['path'])),
             'same archive/native/build Python identity')
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():pin(path)
        app,interp,bridge,builder=build.build(private,archive,tools,r,pin,binary,r['aliases'],run,fact)
        need(pin(interpreter(app))==interp,'exact newly built application PT_INTERP')
        r['flags_native_prerequisite']=native_prerequisites.flags(a.flags_native_receipt,a.flags_native_receipt_sha256,r,r,pin,fact)
        r['helper_native_prerequisite']=native_prerequisites.helper(a.helper_native_receipt,a.helper_native_receipt_sha256,r,r,pin,fact)
        seed_prerequisite(builder,private,pin,binary,run,r)
        need(r['seed_prerequisite']['status']=='passed','independent complete seed before both subjects')
        native_prep=private/'native-preparation.json';native_launch=pin(HERE/'native_launch.py')
        try:
            row,data,err=run('native-fixture',[tools['python'],'-I','-S','-B',native_launch,'--root',ROOT,
                '--original',app,'--preparation',native_prep],profile='finite')
        finally:
            if native_prep.is_file():binary(native_prep)
        need(err==b'','native application stderr is empty')
        prep=json.loads(native_prep.read_bytes())
        expected_env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',
                          GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH='/usr/lib64')
        need(prep['schema_version']==1 and prep['status']=='prepared_not_executed' and prep['role']=='native' and
             prep['pid']==row['pid'] and prep['cpu']==[a.cpu] and prep['reset_mask']==0 and prep['launch_mask']==MASK and
             prep['observer']is None and prep['argv']==[str(app),'native'] and prep['default_rseq']is False and
             prep['environment']==expected_env and [v['signal']for v in prep['dispositions']]==
             [n for n in range(1,65)if n not in (9,19)] and all(v['after']==0 for v in prep['dispositions']),
             'actual full native preparation and exact selected signal mask')
        need(len(data)==341960,'entire raw native application record including all five full frames')
        h=struct.unpack_from('<48Q',data);tail=struct.unpack_from('<16Q',data,2728)
        need(h[:6]==(0x334450414132494c,1,2728,339232,4,1) and h[6]==h[7]==row['pid'] and
             h[8]==a.cpu and h[30]==1 and h[31]==520 and h[36:39]==(30,339232,5) and
             tail[:9]==(h[0]^1,1,4,1,0,1,1,5,30),'actual complete four-cycle native header/cleanup/frame population')
        for i in range(5):
            frame=struct.unpack_from('<12Q',data,8040+i*66784)
            need(frame[0]==1 and frame[1]==i and frame[7]==968 and 580<=frame[9]<=65536,
                 'all five complete retained actual native frame extents')
        r['native_subjects']=1
        application=dict(interpreter=dict(path=str(interp),**{k:fact(interp)[k]for k in ('bytes','sha256')}))
        _,roots,_,_,_,_,carrier=prepare_inputs(app,bridge,builder,private,pin,binary,run,r,application)
        preparation=private/'preparation.json';launcher=pin(HERE/'launch.py')
        argv=[tools['python'],'-B',launcher,'--root',ROOT,'--role','gated','--mode','0','--control','0',
              '--original',app,'--preparation',preparation]
        for directory in roots:argv+=['--library-root',directory]
        argv+=['--carrier',carrier,'--namespace',private/'namespace','--record-fd','{record_fd}']
        try:row,out,err=run('gated-fixture',argv,profile='program',record=True)
        finally:
            for p in (preparation,private/'namespace/namespace.json',private/'namespace/launch.json'):
                if p.is_file():binary(p)
        need(len(out)==341960,'complete successful fixture output')
        r['terminal_reports']=terminal_reports.check(err)
        r['terminal_controls']=terminal_reports.controls(err)
        need(row['captures']['record']['bytes']==2063104,'complete owner raw record and footer')
        need([row['name']for row in r['commands']]==contract['commands'],'all22 fixed fresh commands')
        r['gated_subjects']=1;r['status']='bounded_subjects_completed'
        r['result']=dict(independent_semantic_audit_pending=True,native_subjects=1,gated_subjects=1,
            app_bytes=341960,owner_bytes=2063104,qualification_credit=False,performance_credit=False,equivalence_credit=False)
    except Exception as e:r['error']=repr(e)
    finally:
        try:
            for module in tuple(sys.modules.values()):
                path=getattr(module,'__file__',None)
                if path and Path(path).is_file():pin(path)
            closure();r['inputs_unchanged']=True
        except Exception as e:r['final_errors'].append(repr(e));r['status']='failed'
        r['source_unchanged']=source()==r['source']
        r['cleanup_complete']=all(v.get('reaped')is True and not v.get('cleanup_errors')and
            all(d['closed']is True for d in v.get('descriptors',[]))for v in r['commands'])
        if not r['source_unchanged']or not r['cleanup_complete']:r['status']='failed'
        save(receipt,r)
    print(json.dumps({k:r.get(k)for k in ('status','error','source_unchanged','inputs_unchanged','cleanup_complete')}))
    return 0 if r['status']=='bounded_subjects_completed'else 1

if __name__=='__main__':raise SystemExit(main())
