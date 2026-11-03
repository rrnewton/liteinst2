"""Private fresh invocation of the unchanged maps_view.finite callback only."""
import argparse,json,os,re,sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from page_selected import ENV,fact,need,save
from page_selected_process import invoke
from run import hardware
import maps_view as original

def observed(p):return dict(fact(p),mode=Path(p).stat().st_mode&0o777)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision','attempt','provider','provider-sha256'):ap.add_argument('--'+name,required=True)
    a=ap.parse_args();need(re.fullmatch('[0-9a-f]{40}',a.expect_revision)and re.fullmatch('[0-9a-f]{64}',a.provider_sha256)and re.fullmatch('[a-z0-9][a-z0-9-]{0,80}',a.attempt)and len(os.sched_getaffinity(0))==1 and not sys.flags.optimize,'explicit clean source, provider and singleton')
    os.chdir(ROOT);cpu,=os.sched_getaffinity(0);before=source();need(before['revision']==a.expect_revision,'requested source')
    out=ROOT/'target/evaluation/inprocess'/a.attempt;out.mkdir(parents=True,exist_ok=False)
    names=['finite-headers-0','finite-link','finite-native-libraries']+['finite-'+str(i)for i in range(6)]
    bounds=dict(original.BUILD_PROFILES,**original.BOUNDS,finite=[5,512<<20,16<<20,15])
    need(bounds['metadata']==[30,512<<20,64<<20,60],'unchanged original metadata bounds')
    r=dict(schema=1,profile='original-maps-view-finite-v1',status='failed',source=before,cpu=cpu,hardware=hardware(cpu),driver=fact(__file__),argv=[sys.executable,'-B',*sys.argv],commands=[],inputs={},aliases={},artifacts={},bounds={k:bounds[k]for k in('metadata','finite')},error=None,final_errors=[],source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,qualification_credit=False,performance_credit=False,scope='Fresh original six-mode component only; no maps42/full19, guest-program or performance credit.',finite_cases=[dict(mode=i,expected_exit=code,status='not_run',qualified_case=0,supplied_return_control=i==4,performance_credit=False)for i,code in enumerate((0,125,125,125,125,0))])
    def pin(p):
        alias=str(Path(p).absolute());p=Path(alias).resolve(strict=True);v=observed(p)
        need(alias not in r['aliases']or r['aliases'][alias]==str(p),'input alias');r['aliases'][alias]=str(p)
        need(str(p)not in r['inputs']or r['inputs'][str(p)]==v,'whole input');r['inputs'][str(p)]=v;return p
    def binary(p):
        p=Path(p).resolve(strict=True);v=observed(p);need(str(p)not in r['artifacts']or r['artifacts'][str(p)]==v,'whole artifact');r['artifacts'][str(p)]=v;return p
    def modules():
        for m in tuple(sys.modules.values()):
            p=getattr(m,'__file__',None)
            if p and Path(p).is_file():pin(p)
    def closure():
        need(source()==before and os.sched_getaffinity(0)=={cpu},'same source and CPU')
        need(all(str(Path(a).resolve(strict=True))==p for a,p in r['aliases'].items()),'all aliases')
        need(all(observed(p)==v for p,v in r['inputs'].items())and all(observed(p)==v for p,v in r['artifacts'].items()),'whole inputs/artifacts')
    def closed(row,directory,expected_bounds):
        need(row['bounds']==expected_bounds and row['capture_limit']==16<<20 and row['reaped']is True and row['cleanup_errors']==[]and row['descriptors']==[],'actual original bounds/process closure')
        need(json.loads((directory/(row['name']+'.json')).read_bytes())==row,'whole saved command')
        need(set(row['captures'])=={'stdout','stderr'},'both captures')
        for stream,v in row['captures'].items():need(v['file']==row['name']+'.'+stream and 0<=v['bytes']<=16<<20 and fact(directory/v['file'])=={k:v[k]for k in('bytes','sha256')},'whole capture')
    def run(name,argv,profile='metadata',expected=0,env=None):
        closure();need(name==names[len(r['commands'])]and profile in('metadata','finite'),'fixed original nine-command order')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,environment=dict(ENV if env is None else env),expected_exit=expected);r['commands'].append(row)
        stdout,stderr=invoke(row,out,cpu);need(type(row['exit'])is int and row['exit']==expected,'literal required exit');return row,stdout,stderr
    try:
        pin(__file__);pin(sys.executable);modules();provider=pin(a.provider)
        need(fact(provider)['sha256']==a.provider_sha256,'explicit whole fresh provider')
        prior=json.loads(provider.read_bytes());need(prior['profile']=='maps-anonymous-reset-component-v1'and prior['status']=='passed'and prior['source']==before and all(prior[x]is True for x in('source_unchanged','inputs_unchanged','cleanup_complete'))and prior['error']is None and prior['final_errors']==[],'same-source completed current tools/input producer, no reused qualification')
        need([x['name']for x in prior['commands']]==['maintained-build','maintained-run','differential-build','differential-run']and prior['results']==[dict(version=1,differential=i,positives=5,fallback_controls=20,row_refusals=6,guest_executions=0)for i in(0,1)],'whole exact current producer schedule/results')
        for row in prior['commands']:
            closed(row,provider.parent,[5,512<<20,16<<20,15]);need(row['exit']==row['expected_exit']==0 and row['timed_out']is False and row['error']is None,'actual producer command success')
        for alias,p in prior['aliases'].items():need(str(pin(alias))==p,'provider alias')
        for p,v in prior['inputs'].items():need(observed(pin(p))==v,'whole current provider input')
        for p,v in prior['artifacts'].items():need(observed(binary(p))==v,'whole current provider artifact')
        build_path=provider.parent/'differential/build.json';state=json.loads(build_path.read_bytes())
        need(state==prior['builds']['differential']and state['status']=='passed'and state['profile']=='differential'and state['error']is None,'whole actual successful current build')
        cc=pin(state['compiler']['path']);need(fact(cc)=={k:state['compiler'][k]for k in('bytes','sha256')}and str(cc)==state['compiler_argv'][0],'actual current compiler')
        r['provider']=dict(path=str(provider),**fact(provider),scope='Current tool/input closure only; all six original modes execute freshly.')
        for p,v in state['configuration_presence'].items():need(os.path.lexists(p)==v,'actual loader configuration')
        builder=SimpleNamespace(tools={'cc':str(cc)},environment=dict(ENV))
        original.finite(builder,out,pin,binary,r['aliases'],run,r)
        need([x['name']for x in r['commands']]==names and len(r['finite_cases'])==6 and all(x['qualified_case']==1 for x in r['finite_cases'])and r['error']is None,'all original cases and unchanged reader accepted');r['status']='passed'
    except BaseException as exc:
        if r['error'] is None:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:
            p=out/'finite/maps-view'
            if p.exists():binary(p)
            modules();closure();r['source_unchanged']=r['inputs_unchanged']=True
            for row in r['commands']:closed(row,out,bounds[row['profile']])
            if 'state'in locals():need(all(os.path.lexists(p)==v for p,v in state['configuration_presence'].items()),'final loader configuration')
            r['cleanup_complete']=True
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        if r['error']or r['final_errors']or not r['cleanup_complete']:r['status']='failed'
        save(out/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],commands=len(r['commands']),cases=[{k:x.get(k)for k in('mode','expected_exit','exit','qualified_case','status')}for x in r['finite_cases']],error=r['error'],receipt=str((out/'receipt.json').relative_to(ROOT)))),flush=True)
    return int(r['status']!='passed')
if __name__=='__main__':raise SystemExit(main())
