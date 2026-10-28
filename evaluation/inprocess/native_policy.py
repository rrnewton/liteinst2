#!/usr/bin/env python3
"""Finite raw-policy component oracle; no mode, mapping or admission qualification."""
import argparse, datetime, hashlib, json, os, platform, resource, shlex, shutil, signal, subprocess, sys, time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
SOURCE='tools/page-entry/selected/tests/native_pages/policy_probe.c'
POLICY='tools/page-entry/selected/native_policy.c'
HEADER='tools/page-entry/selected/native_policy.h'
RUNNER='evaluation/inprocess/native_policy.py'
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC'}

def fact(path):
    data=Path(path).read_bytes()
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def need(value,message):
    if not value:raise ValueError(message)

def expected():
    cores=[2,2,3,2,2,2,2,2,2,2,2,2,2,3,3,2,2]
    lengths=[[c+p for c in cores for p in (0,1,1,1,1,9)],
             [4]*4+[3]*6+[4,7]+list(range(4,16))*4,
             [1,3,4,4,3,2,5,1,1,1,1,3,2,5,3,4,2,2]]
    return dict(version=1,window_bytes=4124,patterns=[len(x) for x in lengths],
        checks=[sum(4125-n for n in x) for x in lengths]+[3*256*12,32+sum(cores)],
        pattern_straddles=[sum(2*(n-1) for n in x) for x in lengths])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.chdir(ROOT)
    need(not args.output.is_absolute() and '..' not in args.output.parts,'relative public destination')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    private=Path('target/native-policy')/stamp;private.mkdir(parents=True)
    receipt=dict(schema=1,profile='native_policy_byte_component',status='failed',
        revision=args.expect_revision,commands=[],sources={},tools={},dependencies={},result=None)
    aliases={};artifacts={};env=dict(ENV)
    def pin(name,value):
        need(value is not None,'actual tool '+name)
        aliases[name]=Path(value);actual=aliases[name].resolve(strict=True)
        receipt['tools'][name]=dict(path=str(actual),**fact(actual));return actual
    def run(name,argv,cpu=3,memory=256<<20,cap=1<<20,wall=10):
        row=dict(name=name,argv=argv,limits=dict(cpu_seconds=cpu,memory_bytes=memory,
                 file_bytes=cap,wall_seconds=wall,core_bytes=0));receipt['commands'].append(row)
        def limits():
            for key,n in ((resource.RLIMIT_CPU,cpu),(resource.RLIMIT_AS,memory),
                          (resource.RLIMIT_FSIZE,cap),(resource.RLIMIT_CORE,0)):resource.setrlimit(key,(n,n))
        start=time.monotonic_ns()
        with (private/(name+'.stdout')).open('wb') as out,(private/(name+'.stderr')).open('wb') as err:
            child=subprocess.Popen(argv,env=env,stdout=out,stderr=err,start_new_session=True,preexec_fn=limits)
            row['pid']=child.pid
            while True:
                if os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None:break
                if time.monotonic_ns()-start>=wall*1_000_000_000:row['timeout']=True;break
                time.sleep(.02)
            # Retain the leader until group cleanup, so its PGID cannot recycle.
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            row['exit']=child.wait(timeout=5);row['owned_group_closed']=True
        row['elapsed_ns']=time.monotonic_ns()-start
        for suffix in ('stdout','stderr'):row[suffix]=fact(private/(name+'.'+suffix))
        need(row['exit']==0 and not row.get('timeout') and row['stderr']['bytes']==0,name+' actual outcome')
        return (private/(name+'.stdout')).read_bytes()
    try:
        affinity=sorted(os.sched_getaffinity(0));need(len(affinity)==1,'one externally reserved CPU')
        revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
        need(revision==args.expect_revision,'exact source revision')
        for p in (SOURCE,POLICY,HEADER,RUNNER):
            subprocess.run(['git','ls-files','--error-unmatch',p],check=True,stdout=subprocess.DEVNULL)
            receipt['sources'][p]=fact(p)
        subprocess.run(['git','diff','--exit-code','HEAD','--',SOURCE,POLICY,HEADER,RUNNER],check=True,
                       stdout=subprocess.DEVNULL)
        rows=[dict((k.strip(),v.strip()) for k,v in (x.split(':',1) for x in r.splitlines() if ':' in x))
              for r in Path('/proc/cpuinfo').read_text().split('\n\n')]
        cpu=next(r for r in rows if r.get('processor')==str(affinity[0]))
        receipt['hardware']=dict(machine=platform.machine(),kernel=platform.release(),reserved_cpu=affinity[0],
            reserved_cpu_count=1,cpu={k:cpu[k] for k in ('vendor_id','cpu family','model','model name','stepping','microcode','flags')})
        pin('cc',shutil.which('cc',path=env['PATH']));pin('python',sys.executable)
        pin('nm',shutil.which('nm',path=env['PATH']))
        for name in ('cc1','collect2','as','ld'):
            value=run('resolve-'+name,['cc','-print-prog-name='+name]).decode().strip()
            pin(name,value if Path(value).is_absolute() else shutil.which(value,path=env['PATH']))
        flags=['-O2','-g','-std=gnu11','-Wall','-Wextra','-Werror','-Itools/page-entry/selected']
        for i,source in enumerate((SOURCE,POLICY)):
            raw=run('dependencies-'+str(i),['cc',*flags,'-M',source])
            names=shlex.split(raw.decode().replace('\\\n',' ').split(':',1)[1])
            for name in names:receipt['dependencies'][name]=fact(name)
        binary=private/'policy-probe'
        run('compile',['cc',*flags,SOURCE,POLICY,'-o',str(binary)],cpu=5,memory=512<<20,cap=16<<20,wall=15)
        artifacts[str(binary)]=fact(binary);receipt['binary']=artifacts[str(binary)]
        symbols=run('symbols',['nm','-S','--defined-only',str(binary)]).decode().splitlines()
        for symbol in ('main','li2_native_policy'):
            found=[x.split() for x in symbols if x.split()[-1:]==[symbol]]
            need(len(found)==1 and found[0][2]=='T' and int(found[0][1],16)>0,'actual linked '+symbol)
        raw=run('oracle',[str(binary)],cpu=30,wall=45)
        want=expected();need(raw==json.dumps(want,separators=(',',':')).encode()+b'\n','exact finite result')
        receipt['result']=want;receipt['status']='passed'
    except BaseException as error:receipt['error']=type(error).__name__+': '+str(error)
    errors=receipt['final_errors']=[]
    for category,rows in (('source',receipt['sources']),('dependency',receipt['dependencies']),('artifact',artifacts)):
        for path,before in rows.items():
            try:need(fact(path)==before,category+' changed')
            except BaseException as error:errors.append(category+': '+type(error).__name__)
    for name,row in receipt['tools'].items():
        try:need(str(aliases[name].resolve())==row['path'] and fact(row['path'])=={k:row[k] for k in ('bytes','sha256')},'tool changed')
        except BaseException as error:errors.append('tool '+name+': '+type(error).__name__)
    try:need(subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==args.expect_revision,'revision changed')
    except BaseException as error:errors.append('revision: '+type(error).__name__)
    if errors:receipt['status']='failed'
    (private/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    public={k:v for k,v in receipt.items() if k not in ('dependencies','tools','error')}
    public['error']=receipt.get('error','').split(':',1)[0] or None
    public['tools']={k:{n:v[n] for n in ('bytes','sha256')} for k,v in receipt['tools'].items()}
    public['dependency_manifest_sha256']=hashlib.sha256(json.dumps(receipt['dependencies'],sort_keys=True).encode()).hexdigest()
    public['dependency_count']=len(receipt['dependencies']);public['private_receipt_sha256']=fact(private/'receipt.json')['sha256']
    public['scope']='Finite byte-pattern and buffer-boundary component only; no mode, map, rseq or production admission qualification.'
    public['check_groups']=['all-offset prefixed cores','all-offset HLE','all-offset barrier-free patterns','ModRM seam matrix','actual inaccessible buffer neighbors']
    public['reproduce']=['python3',RUNNER,'--expect-revision',args.expect_revision,'--output',str(args.output)]
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(public,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(status=receipt['status'],private=str(private),receipt_sha256=public['private_receipt_sha256'],error=public['error'])))
    return 0 if receipt['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
