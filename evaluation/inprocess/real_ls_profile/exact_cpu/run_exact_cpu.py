#!/usr/bin/env python3
"""Reserve an explicit origin CPU through the unchanged hard allocator; profile one exact failed input."""
import argparse,hashlib,json,os,re,shutil,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PROFILE=HERE.parent
ROOT=Path.cwd().resolve()



def need(ok,why):
    if not ok:raise ValueError(why)


def fact(path):
    p=Path(path);b=p.read_bytes()
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=p.stat().st_mode&0o7777)


def save(path,value):
    path.write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')


def main():
    ap=argparse.ArgumentParser(description=__doc__,allow_abbrev=False)
    ap.add_argument('--tool-root',type=Path,required=True)
    ap.add_argument('--cpu',type=int,required=True)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--expect-origin-revision',required=True)
    ap.add_argument('--origin-receipt',type=Path,required=True)
    ap.add_argument('--expect-origin-sha256',required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    TOOLS=a.tool_root.resolve(strict=True);CPU=a.cpu;TAG='li2-real-ls-profile-cpu'+str(CPU)
    need(CPU>=0 and re.fullmatch('[0-9a-f]{40}',a.expect_origin_revision)and
         re.fullmatch('[0-9a-f]{64}',a.expect_origin_sha256),'explicit CPU and whole origin identity')
    need(not sys.flags.optimize and os.environ.get('PYTHONDONTWRITEBYTECODE')=='1','assertions and bytecode writes disabled')
    need(re.fullmatch('[0-9a-f]{40}',a.expect_revision),'exact expected revision')
    out=a.output.resolve();out.relative_to(ROOT/'target/evaluation/inprocess');out.mkdir(mode=0o700)
    r=dict(schema=1,status='failed',cpu=CPU,parent_pid=os.getpid(),command=None,command_returncode=None,
           reservation=None,released=False,source_unchanged=False,parent_affinity_unchanged=False,
           sources={},aliases={},captures={},error=None,final_errors=[],qualification=False,performance_credit=False)
    sources=r['sources'];aliases=r['aliases'];holder=None;child=None
    allowed=set(os.sched_getaffinity(0));r['parent_affinity_before']=sorted(allowed)
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);v=fact(p)
        need(p.is_file() and (want is None or v==want),'complete pinned source/tool bytes and mode '+str(alias))
        need(str(p)not in sources or sources[str(p)]==v,'same source/tool throughout wrapper')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'same lexical source/tool alias')
        sources[str(p)]=v;aliases[str(alias)]=str(p);return p
    def stable():
        need(all(fact(p)==v for p,v in sources.items()),'all wrapper/tool/profiler facts unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'all wrapper/tool/profiler aliases unchanged')
        need(set(os.sched_getaffinity(0))==allowed,'parent affinity never narrowed for exact selection')
    try:
        need(CPU in allowed and len(allowed)>1,'requested CPU allowed and a separate core remains for the real escape probe')
        source=pin(HERE/'SOURCE.json');m=json.loads(source.read_bytes())
        pin(HERE/'run_exact_cpu.py',m['wrapper']);pin(HERE/'README.md',m['readme'])
        for name,want in m['profile'].items():pin(PROFILE/name,want)
        for name,want in m['tool_sources'].items():pin(TOOLS/name,want)
        for name,item in m['executables'].items():
            actual=sys.executable if name=='python' else shutil.which(name)
            need(actual is not None and item['resolver']==('sys.executable'if name=='python'else'PATH'),
                 'explicit executable resolver '+name)
            pin(actual,item['fact'])
        origin=pin(a.origin_receipt)
        need(fact(origin)['sha256']==a.expect_origin_sha256,'exact explicit original program receipt')
        original=json.loads(origin.read_bytes())
        need(original['revision']==a.expect_origin_revision and original['cpu']==CPU,
             'requested CPU and origin revision are the actual whole origin identity')
        # Select through the real shared ledger, with no process-affinity mutation.
        # No copy, stub, monkeypatch, alternate ledger, fallback or retry of either API.
        sys.path.insert(0,str(TOOLS/'py'))
        from dagrun import reservation,cpuset_allocator
        need(Path(reservation.__file__).resolve()==(TOOLS/'py/dagrun/reservation.py').resolve() and
             Path(cpuset_allocator.__file__).resolve()==(TOOLS/'py/dagrun/cpuset_allocator.py').resolve(),
             'actual source-bound allocator and reservation modules')
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():
                p=Path(path).resolve()
                if p.is_relative_to((TOOLS/'py').resolve()):
                    name=str(p.relative_to(TOOLS.resolve()))
                    need(name in m['tool_sources'],'every actual imported allocator source is frozen')
                pin(path)
        argv=[str(Path(sys.executable).resolve()),'-B',str(PROFILE/'run.py'),
              '--expect-revision',a.expect_revision,'--expect-origin-revision',a.expect_origin_revision,
              '--origin-receipt',str(origin),
              '--expect-origin-sha256',a.expect_origin_sha256,'--output',str(out/'profile')]
        r['command']=argv;r['cwd']=str(ROOT);r['wrapper_source']=fact(source)
        r['allocator_environment']={k:os.environ.get(k)for k in ('DAGRUN_CORE_LEDGER','XDG_RUNTIME_DIR','TMPDIR','PATH')}
        r['selection']=dict(count=1,exclude=sorted(allowed-{CPU}),sample_s=0.3,max_irq_rate=None)
        allocation=reservation.reserve_cores(1,exclude=allowed-{CPU},tag=TAG,sample_s=0.3,max_irq_rate=None)
        stable();r['start_ns']=time.monotonic_ns();save(out/'receipt.json',r)
        with allocation as cores:
            holder=allocation._reservation
            need(cores==[CPU] and holder is not None and holder.pid==os.getpid() and not holder._released,
                 'one actual exact-CPU shared-ledger reservation')
            r['reservation']=dict(cores=list(cores),count=len(cores),pid=holder.pid,starttime=holder.starttime,
                                  ledger=str(holder.ledger),tag=holder.tag)
            stable();save(out/'receipt.json',r)
            with (out/'command.stdout').open('xb')as stdout,(out/'command.stderr').open('xb')as stderr:
                sys.stdout.flush();sys.stderr.flush();saved=(os.dup(1),os.dup(2))
                try:
                    os.dup2(stdout.fileno(),1);os.dup2(stderr.fileno(),2)
                    r['command_start_ns']=time.monotonic_ns()
                    r['command_returncode']=cpuset_allocator._run_reserved_hard(cores,argv,tag=TAG,prog='li2-ls-exact-cpu')
                    r['command_end_ns']=time.monotonic_ns()
                finally:
                    sys.stdout.flush();sys.stderr.flush()
                    for fd,old in zip((1,2),saved):os.dup2(old,fd);os.close(old)
        r['released']=holder._released
        need(r['released'] and r['command_returncode']==0,'actual hard allocator/observer success and released reservation')
        notice=('li2-ls-exact-cpu: reserved '+json.dumps(dict(cores=[CPU],count=1),separators=(',',':'))+
                '; running whole tree pinned via AllowedCPUs='+str(CPU)+'\n').encode()
        need((out/'command.stderr').read_bytes().splitlines(keepends=True).count(notice)==1,
             'actual allocator notice emitted only after its unchanged HARD escape probe')
        r['hard_scope_notice']=True
        p=out/'profile/receipt.json';child=json.loads(p.read_bytes());r['profile_receipt']=fact(p)
        r['profile_summary']=fact(out/'profile/summary.json')
        need(child['cpu']==CPU and child['status']=='observed_unqualified' and child['qualification']is False and
             child['performance_credit']is False and child['source_unchanged']is child['cleanup_complete']is child['namespace_complete']is True and
             not child['error'] and child['final_errors']==[] and child['observer_packet']==
             {k:m['profile']['SOURCE.json'][k]for k in('bytes','sha256')},'whole closed exact profile result, without target success credit')
        r['status']='observed_wrapper_complete'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        if holder is not None:r['released']=holder._released
        r['end_ns']=time.monotonic_ns()
        try:stable();r['source_unchanged']=True;r['parent_affinity_unchanged']=True
        except BaseException as exc:r['final_errors'].append('source/affinity closure: '+repr(exc))
        for name in ('command.stdout','command.stderr'):
            p=out/name
            if p.exists():
                try:need(p.stat().st_size<=16<<20,'bounded wrapper command capture');r['captures'][name]=fact(p)
                except BaseException as exc:r['final_errors'].append('capture: '+repr(exc))
        if r['error']or r['final_errors']or not r['released']:r['status']='failed'
        save(out/'receipt.json',r)
        # Correct operational recipe is separate; the original profile's whole summary stays untouched.
        summary=dict(schema=1,status=r['status'],cpu=CPU,command_returncode=r['command_returncode'],
            released=r['released'],source_unchanged=r['source_unchanged'],parent_affinity_unchanged=r['parent_affinity_unchanged'],
            wrapper_source=r.get('wrapper_source'),wrapper_receipt=fact(out/'receipt.json'),
            profile_receipt=r.get('profile_receipt'),profile_summary=r.get('profile_summary'),
            target_exit=(child or{}).get('target',{}).get('exit'),target_outcome=(child or{}).get('target_outcome'),
            qualification=False,performance_credit=False,
            reproduce=['env','PYTHONDONTWRITEBYTECODE=1','python3','-B',str((HERE/'run_exact_cpu.py').relative_to(ROOT)),
                '--tool-root','${AGENT_UTILS_ROOT}','--cpu',str(CPU),'--expect-revision',a.expect_revision,
                '--expect-origin-revision',a.expect_origin_revision,'--origin-receipt',str(a.origin_receipt.resolve().relative_to(ROOT)),
                '--expect-origin-sha256',a.expect_origin_sha256,'--output','${FRESH_PRIVATE_WRAPPER_OUTPUT}'],
            recipe_scope='Explicit same-origin-CPU profile through the actual shared allocator. Do not taskset the parent. '
                'The unmodified allocator must prove HARD on another allowed core before its sole observed command. '
                'Source-bound wrapper completion never implies target completion, qualification or speedup.')
        save(out/'summary.json',summary)
        print(json.dumps(dict(status=r['status'],command_returncode=r['command_returncode'],output=str(out))))
    return 0 if r['status']=='observed_wrapper_complete'else 1


if __name__=='__main__':raise SystemExit(main())
