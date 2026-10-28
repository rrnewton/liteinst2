#!/usr/bin/env python3
"""Portable bounded inactive-rseq applications; full finite records stay private."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from page_selected import ENV,fact,need,save,interpreter
from page_selected_process import invoke
from page_selected_generic_build import Build,PROFILES
from run import hardware
from page_selected_rseq_build import application as link
from page_selected_rseq_prepare import CATALOG
import page_selected_rseq_application_compare as compare
from page_selected_rseq_application_images import NAMES
BOUNDS=dict(PROFILES,native=[5,512<<20,16<<20,15])

def publish(path,r,private):
    def digest(v):
        return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    b=r.get('build',{})
    result={k:r.get(k)for k in ('version','profile','status','expected_revision','started_utc','environment','bounds','cpu',
        'source','source_unchanged','hardware','reproduce','cases')}
    result.update(scope='Two fresh-exec whole applications and15 named pre-effect refusals. No active critical sections, threads or complete B3 claim.',
        required_cases=17,accepted_cases=sum(c.get('accepted',False)for c in r['cases']),
        completed_cases=sum(c.get('outcome')=='completed'for c in r['cases']),
        required_refusals=sum(c.get('outcome')=='required_refusal'for c in r['cases']),
        finite_command_count=sum(c['stage']=='cohort'for c in r['commands']),command_count=len(r['commands']),
        command_rows_sha256=digest(r['commands']),case_rows_sha256=digest(r['cases']),
        private_receipt=fact(private/'receipt.json'),input_manifest_sha256=digest(r['inputs']),
        alias_manifest_sha256=digest(r['input_aliases']),artifact_manifest_sha256=digest(r['artifacts']),
        build_status=b.get('status'),rseq_build_status=r.get('rseq_build',{}).get('status'),
        tool_versions=b.get('numeric_versions'),tool_bindings_sha256=digest(b.get('tools',{})),
        build_evidence_sha256=digest(b),rseq_build_sha256=digest(r.get('rseq_build')),
        final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0]if r['error']else None)
    if r.get('rseq_build',{}).get('fast_memset'):
        body=r['rseq_build'].get('fast_memset_body',{})
        result['fast_memset_body']={k:body[k]for k in ('bytes','sha256')if k in body}
    text=json.dumps(result,sort_keys=True,indent=2,allow_nan=False)+'\n'
    import platform,re
    need(not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node())) and
         not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text),'private publication data')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--fast-memset',action='store_true',help='Use the qualified full-byte REP STOSB reset in the actual bridge')
    args=ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'one external reserved CPU and assertions')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    profile='page-selected-rseq-application'+('-fast-memset' if args.fast_memset else '')
    stem=stamp+'-'+profile+'-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem
    public=HERE/'results'/(stem+'.json')
    need(not public.exists(),'unique public receipt')
    private.mkdir(parents=True,exist_ok=False)
    r=dict(version=1,profile=profile+'-v1',status='failed',expected_revision=args.expect_revision,
           environment=ENV,bounds=BOUNDS,cpu=cpu,started_utc=stamp,commands=[],cases=[],error=None,final_errors=[],source_unchanged=False,
           reproduce=['python3','evaluation/inprocess/page_selected_rseq_application.py','--expect-revision',args.expect_revision])
    if args.fast_memset:r['reproduce'].append('--fast-memset')
    pins={};binaries={};aliases={};stage='build'
    def pin(p):
        lexical=str(Path(os.path.abspath(p)));p=Path(lexical).resolve(strict=True)
        need(lexical not in aliases or aliases[lexical]==str(p),'input alias changed')
        aliases[lexical]=str(p)
        v=fact(p);need(str(p)not in pins or pins[str(p)]==v,'input changed');pins[str(p)]=v;return p
    def binary(p):
        p=Path(p).resolve(strict=True);v=fact(p);need(str(p)not in binaries or binaries[str(p)]==v,'artifact changed');binaries[str(p)]=v;return p
    def run(name,argv,expected=0,profile='native',env=None,record=False):
        need(all(str(Path(a).resolve(strict=True))==p for a,p in aliases.items()),'input alias before command')
        need(all(fact(p)==v for p,v in pins.items())and all(fact(p)==v for p,v in binaries.items()),'source/artifact before command')
        row=dict(name=name,stage=stage,profile=profile,argv=list(map(str,argv)),expected_exit=expected,bounds=BOUNDS[profile],
                 environment=dict(ENV if env is None else env),capture_limit=65536 if profile=='native' else 4<<20)
        r['commands'].append(row);out,err=invoke(row,private,cpu,record=record,step=record)
        need(row['exit']==expected,'exact command exit '+name);return row,out,err
    builder=Build(r,private,pin,binary,run)
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        r['hardware']=hardware(cpu)
        manifest=compare.decode(pin(CATALOG).read_bytes())
        for v in manifest['inputs']:
            need(fact(pin(ROOT/v['path']))=={k:v[k]for k in ('bytes','sha256')},'exact fixed candidate input '+v['path'])
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for p in out.split(b'\0'):
            if p and not os.fsdecode(p).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(p))
        products=builder.prepare();bridge=link(builder,products,private,pin,binary,run,r,fast_memset=args.fast_memset)
        python=builder.tools['python'];schema=compare.decode(pin(HERE/'page_selected_rseq_schema.json').read_bytes())
        stage='cohort';run('generate-images',[python,HERE/'page_selected_rseq_application_images.py',private/'images',cpu],profile='metadata')
        catalog=compare.decode(binary(private/'images/images.json').read_bytes())
        need(len(catalog)==17 and [x['actual']['name']for x in catalog]==NAMES,'exact17-case catalog')
        for item in catalog:
            spec=item['actual'];name=spec['name'];case=dict(name=name,accepted=False);r['cases'].append(case)
            original=binary(spec['original']);ip=binary(spec['interpreter'])
            need(interpreter(original)==ip and fact(original)['sha256']==spec['original_sha256'] and
                 fact(ip)['sha256']==spec['interpreter_sha256'],'actual unchanged literal ELF/initial interpreter')
            binary(Path(spec['library_root'])/'li2-stream.so')
            native_spec=item['native_prefix'] or spec
            native=binary(native_spec['original']);binary(native_spec['interpreter']);binary(Path(native_spec['library_root'])/'li2-stream.so')
            row,out,err=run('native-'+name,[native],record=True)
            need(not err and (private/row['captures']['record']['file']).read_bytes()==b'','native no runtime reports or fabricated observer')
            compare.output(native_spec,out);native_stdout=out
            case['native_kind']='complete_operation' if spec['index']<2 else 'stopped_before_forbidden_operation'
            carrier=private/('carrier-'+name)
            run('make-'+name,[python,ROOT/'tools/page-entry/carrier.py','make',original,bridge,carrier],profile='metadata');binary(carrier)
            ns=private/('namespace-'+name)
            row,out,err=run('gated-'+name,[python,ROOT/'tools/page-entry/carrier.py','exec-loader','--library-root',
                spec['library_root'],'--namespace',ns,carrier,original,'--',original],expected=spec['expected_exit'],record=True)
            record=(private/row['captures']['record']['file']).read_bytes()
            case.update(compare.check(spec,row,out,err,record,native_stdout,schema))
            namespace=compare.decode(binary(ns/'namespace.json').read_bytes());launch=compare.decode(binary(ns/'launch.json').read_bytes())
            need(launch['carrier_sha256']==fact(carrier)['sha256'] and 'GLIBC_TUNABLES'not in launch['environment'],
                 'actual fresh standalone environment, no inherited libc or rseq tunable')
            for obj in namespace['objects']:
                need(obj['seals']==15 and fact(pin(obj['source']))['sha256']==obj['sha256'],'actual sealed dependency identity')
            case['namespace']={n:fact(ns/n)for n in ('namespace.json','launch.json')}
        need(len(r['cases'])==17 and all(c['accepted']for c in r['cases']) and
             sum(c['operation_exit']==0 for c in r['cases'])==2 and sum(c['operation_exit']==125 for c in r['cases'])==15,
             'two actual completed applications and15 required failures, separately counted')
        need(sum(x['stage']=='cohort'for x in r['commands'])==52,'one generator plus17native/17carrier/17gated commands')
        r['status']='passed_finite_inactive_profile'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finish: '+repr(exc))
        r['input_aliases']=dict(aliases)
        for lexical,resolved in aliases.items():
            try:need(str(Path(lexical).resolve(strict=True))==resolved,'input alias closure')
            except BaseException as exc:r['final_errors'].append('input alias '+lexical+': '+type(exc).__name__+': '+str(exc))
        try:
            r['source_after']=source();r['source_unchanged']=r.get('source')==r['source_after']
            need(r['source_unchanged'],'source changed')
            need(all(fact(p)==v for p,v in pins.items()),'input closure');need(all(fact(p)==v for p,v in binaries.items()),'artifact closure')
            for row in r['commands']:
                need(row.get('reaped')and not row.get('timed_out')and not row.get('error')and not row.get('cleanup_errors'),'process cleanup closure')
                for cap in row.get('captures',{}).values():need(fact(private/cap['file'])=={k:cap[k]for k in ('bytes','sha256')},'capture closure')
            need(r.get('build',{}).get('status')=='passed' and r.get('rseq_build',{}).get('status')=='passed','actual complete build closure')
        except BaseException as exc:r['final_errors'].append(type(exc).__name__+': '+str(exc))
        if r['error']or r['final_errors']:r['status']='failed'
        r['inputs']=pins;r['artifacts']=binaries;save(private/'receipt.json',r)
        publish(public,r,private)
        print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)),cases=len(r['cases']),commands=len(r['commands']))))
    return 0 if r['status']=='passed_finite_inactive_profile' else 1
if __name__=='__main__':raise SystemExit(main())
