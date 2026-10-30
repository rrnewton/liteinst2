#!/usr/bin/env python3
"""Current-custody component and compiled storage only; genuine TF stays separate."""
import argparse,csv,hashlib,importlib.util,io,json,os,platform,re,shutil,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from maps_view import (ENV,fact,need,save,source,hardware,Build,BUILD_PROFILES,BOUNDS,
    SELECTED,PROGRAM_ENV,invoke,program_invoke,finalize,before_default,digest)
import maps_current_build as bridge_build
import maps_current_component as component
import maps_current_fallback as fallback
NAMES=()  # The unchanged command owner always selects direct invoke here.
REQUIRED=('evaluation/inprocess/maps_current_qualification.py',
    'evaluation/inprocess/maps_current_build.py','evaluation/inprocess/maps_current_component.py',
    'evaluation/inprocess/maps_current_extents.py','tools/page-entry/selected/tests/current_custody/extents.py',
    'evaluation/inprocess/maps_current_fallback.py',
    *('tools/page-entry/selected/tests/maps_current_fallback/'+n for n in ('oracle.c','build.sh','check.py')),
    *('tools/page-entry/selected/tests/maps_current_custody/'+n for n in ('oracle.c','build.sh','check.py')),
    *('tools/page-entry/selected/'+n for n in bridge_build.CURRENT_HEADERS))


def publish(path,r,private):
    cases=[]
    for c in r['component_cases']:
        row={k:c.get(k)for k in('profile','mode','expected_exit','status','exit','launched','duration_ns','timed_out','captures')}
        v=c.get('result');row['reader_refusals']=c.get('controls',{}).get('refusals',0)
        row['result_sha256']=digest(v)if v is not None else None
        row['io']=v['io']if v is not None else None
        row['cleanup']=v['cleanup']if v is not None else None
        row['event_count']=len(v['events'])if v is not None else 0
        row['error_type']=(c.get('error')or'').split(':',1)[0]or None
        cases.append(row)
    totals=dict(required_cases=28,launched=sum(c.get('launched')is True for c in cases),
        qualified=sum(c['status']in('qualified_component','qualified_required_refusal')for c in cases),
        complete_component=sum(c['status']=='qualified_component'for c in cases),
        required_api_refusals=sum(c['status']=='qualified_required_refusal'for c in cases),
        supplied_record_refusals=sum(c['reader_refusals']for c in cases),
        compiled_storage_profiles=sum(v.get('status')=='passed'for k,v in r.get('current_bridge_builds',{}).items()if k!='physical'),
        storage_refusals=sum(len(v.get('storage_controls',{}).get('refusals',[]))for v in r.get('current_bridge_builds',{}).values()))
    hardware=dict(r['hardware']);flags=hardware.pop('isa_flags',[])
    hardware.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    pub={k:r.get(k)for k in('schema','profile','scope','status','expected_revision','started_utc','source','source_after','source_unchanged','cpu','bounds','reproduce','cleanup_complete')}
    pub.update(totals=totals,cases=cases,fallback_component=fallback.project(r),hardware=hardware,command_count=len(r['commands']),
        commands_sha256=digest(r['commands']),private_receipt=fact(private/'receipt.json'),
        inputs_sha256=digest(r['inputs_before']),artifacts_sha256=digest(r['artifacts_before']),
        final_error_count=len(r['final_errors']),failure_type=(r['error']or'').split(':',1)[0]or None,
        runtime_registration_observed=False,genuine_tf_qualified=False,full_frame_qualified=False,
        application_qualified=False,performance_credit=False,
        compiled_bridges={k:{'status':v.get('status'),'bridge':v.get('release_build',{}).get('bridge'),
            'storage_sha256':digest(v['storage_proof'])if 'storage_proof'in v else None,
            'symbols':v.get('storage_proof',{}).get('symbols',0)}for k,v in r.get('current_bridge_builds',{}).items()})
    output=io.StringIO(newline='');writer=csv.writer(output,lineterminator='\n')
    writer.writerow(('profile','mode','expected_exit','exit','status','duration_ns','reader_refusals','event_count'))
    for c in cases:writer.writerow(c.get(k,'')for k in('profile','mode','expected_exit','exit','status','duration_ns','reader_refusals','event_count'))
    csv_bytes=output.getvalue().encode();csv_path=path.with_suffix('.csv')
    need(len(csv_bytes)<=8192,'bounded complete twenty-eight-row CSV')
    pub['csv']=dict(file=csv_path.name,bytes=len(csv_bytes),sha256=hashlib.sha256(csv_bytes).hexdigest())
    encoded=json.dumps(pub,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in output.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'bounded private-path-free public projection')
    path.parent.mkdir(exist_ok=True)
    with csv_path.open('xb')as stream:stream.write(csv_bytes)
    with path.open('x')as stream:stream.write(encoded)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expect-revision',required=True);a=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1 and re.fullmatch('[0-9a-f]{40}',a.expect_revision),
         'exact committed revision, assertions and one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-maps-current-component-'+a.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem
    private.mkdir(parents=True,mode=0o700);public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    bounds=dict(BUILD_PROFILES,**BOUNDS,finite=[5,512<<20,16<<20,15],finite_build=[30,512<<20,16<<20,60])
    pins={};aliases={};artifacts={};presence={};commands=[]
    r=dict(schema=1,profile='maps-current-component-storage-v1',
        scope='28 actual lifecycle-TU cases with supplied owner/session boundaries, and nine compiled objects in each of two enabled production bridges. No genuine TF, full-frame, application or performance qualification.',
        status='failed',expected_revision=a.expect_revision,started_utc=stamp,source=None,source_unchanged=False,
        cpu=cpu,hardware=hardware(cpu),bounds=bounds,commands=commands,error=None,final_errors=[],
        component_cases=[dict(profile=p,mode=m,expected_exit=0 if m<3 else 125,status='not_run')for p,m in component.MODES],
        fallback_cases=[dict(profile=p,mode=m,expected_exit=0 if m==0 else 125,status='not_run')for p,m in fallback.MODES],
        reproduce=['python3','evaluation/inprocess/maps_current_qualification.py','--expect-revision',a.expect_revision])
    def pin(path,want=None):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);f=fact(p)
        need(want is None or f=={k:want[k]for k in('bytes','sha256')},'exact requested input bytes')
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'input alias changed')
        need(str(p)not in pins or pins[str(p)]==f,'input bytes changed')
        aliases[str(alias)]=str(p);pins[str(p)]=f;return p
    def binary(path):
        p=Path(path).resolve(strict=True);f=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==f,'retained artifact changed');artifacts[str(p)]=f;return p
    def stable():
        need(all(Path(p).resolve(strict=True)==Path(v)for p,v in aliases.items()),'all lexical input aliases unchanged')
        need(all(fact(p)==v for p,v in pins.items()),'all input bytes unchanged')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'all artifact bytes/modes unchanged')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence unchanged')
        finalize(r)
    def run(name,argv,profile='metadata',expected=0,env=None,record=False,step=False):
        stable();need(not any(x['name']==name for x in commands),'unique command/capture names')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected);commands.append(row)
        try:
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
            need(type(row['exit'])is int and(expected is None or row['exit']==expected),'actual command exit '+name)
            return row,out,err
        finally:
            for stream in('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream)
                try:
                    observed=row.get('captures',{}).get(stream)
                    if path.exists()or path.is_symlink():
                        actual=fact(binary(path))
                        if observed is not None:need(observed['file']==path.name and actual=={k:observed[k]for k in('bytes','sha256')},'actual command capture binding')
                    else:need(observed is None,'retained command capture missing')
                except BaseException as error:r['final_errors'].append('capture '+name+'.'+stream+': '+type(error).__name__+': '+str(error))
            path=private/(name+'.json')
            try:
                if path.exists()or path.is_symlink():binary(path);need(digest(json.loads(path.read_bytes()))==digest(row),'actual retained command row')
            except BaseException as error:r['final_errors'].append('command row '+name+': '+type(error).__name__+': '+str(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder=Build(r,private,pin,binary,build_run)
    try:
        r['source']=source();need(r['source']['revision']==a.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z'])
        need(not err,'source enumeration stderr')
        tracked={os.fsdecode(n)for n in out.split(b'\0')if n}
        need(set(REQUIRED)<=tracked,'every new source/helper/fixture committed at the requested revision')
        for name in sorted(tracked):
            if not name.startswith(('evaluation/inprocess/results/','evaluation/admission/results/')):pin(ROOT/name)
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).resolve().is_relative_to(ROOT)and Path(p).suffix=='.py':pin(p)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload');r['configuration_presence']=presence
        products=builder.prepare();r['archive']=fact(products['archive'])
        need(builder.extra_decoder_sources==()and builder.decoder_features==()and r['build']['decoder_features']==[],
             'original eight-source decoder and no scalar feature')
        try:
            component.fixture(builder,products,private,pin,binary,aliases,run,r)
        except Exception as error:
            if r['error']is None:r['error']=type(error).__name__+': '+str(error)
            last=r['commands'][-1]if r['commands']else{}
            need(all(c.get('launched')is True for c in r['component_cases']) and
                 last.get('name')=='current-verified-13' and last.get('reaped')is True and
                 last.get('cleanup_errors')==[] and isinstance(last.get('descriptors'),list) and
                 all(d.get('closed')is True for d in last['descriptors']),
                 'companion continuation only after all28 attempted and exact final subject completely reaped')
        fallback.fixture(builder,products,private,pin,binary,aliases,run,r)
        bridge_build.bridges(builder,products,private,pin,binary,aliases,run,r)
        need(not r['error']and not r['final_errors'],'all original and additional subjects qualified; no retained command errors')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for m in tuple(sys.modules.values()):
                path=getattr(m,'__file__',None)
                if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        except BaseException as error:r['final_errors'].append('final imported source closure: '+repr(error))
        try:r['final_errors'].extend(builder.finish())
        except BaseException as error:r['final_errors'].append('build finalization: '+type(error).__name__+': '+str(error))
        for p in sorted(private.rglob('*')):
            if p.is_file()and not p.is_symlink():
                try:binary(p)
                except BaseException as error:r['final_errors'].append('retain '+str(p)+': '+type(error).__name__+': '+str(error))
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        for label,fn in(('closure',stable),('namespace',lambda:finalize(r))):
            try:fn()
            except BaseException as error:r['final_errors'].append(label+': '+type(error).__name__+': '+str(error))
        try:r['source_after']=source();need(r['source_after']==r['source'],'exact committed source unchanged')
        except BaseException as error:r['final_errors'].append('source: '+type(error).__name__+': '+str(error))
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged']=r['source']is not None and r.get('source_after')==r['source']and r['inputs_before']==r['inputs_after']and r['aliases_before']==r['aliases_after']
        r['cleanup_complete']=all(type(c.get('exit'))is int and c.get('reaped')is True and
            c.get('timed_out')is False and not c.get('error')and c.get('cleanup_errors')==[] and
            all(d['closed']for d in c.get('descriptors',[]))for c in commands)
        if r['error']or r['final_errors']or not r['source_unchanged']or r['artifacts_before']!=r['artifacts_after']or not r['cleanup_complete']:r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),commands=len(commands),
                             failure_type=r['error'].split(':',1)[0]if r['error']else None)))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
