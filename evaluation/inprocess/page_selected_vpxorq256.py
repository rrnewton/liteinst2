#!/usr/bin/env python3
"""Canonical EVEX256.W1 VPXORQ register/memory full-state qualification."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,platform,re,shutil,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save,elf
from page_selected_generic import digest
from page_selected_generic_build import Build,PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe,expand,headers
from page_selected_register_time_compare import decode
from page_selected_vpxorq256_record import NAMES,GROUP_COUNTS,FAULT_NAMES,OUTCOMES_SHA,REFUSALS,catalogue,record
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/vpxorq128'
PROFILES=dict(BUILD_PROFILES,fixture_link=[5,512<<20,16<<20,15],native=[5,512<<20,16<<20,15])


def publish(path,r,private):
    b=r.get('build',{});hw=dict(r.get('hardware')or{});flags=hw.pop('isa_flags',[])
    hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    public={k:r.get(k)for k in ('schema','profile','status','scope','expected_revision','started_utc',
        'cpu','source','source_unchanged','totals','reproduce','bounds','cleanup_complete','catalogue')}
    public.update(hardware=hw,environment=ENV,private_receipt=fact(private/'receipt.json'),
        command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r['inputs_before']),binaries_sha256=digest(r['binaries_before']),
        aliases_sha256=digest(r['aliases']),build_status=b.get('status'),
        tool_versions=b.get('numeric_versions'),tool_bindings_sha256=digest(b.get('tools',{})),
        fixture_build_sha256=digest(r.get('fixture_build')),cases_sha256=digest(r['cases']),
        cases=[dict(name=c['name'],status=c['status'],exit=c['actual_exit'],record=c.get('record'),
            **{k:c.get('outcome',{}).get(k)for k in('operation','pairs','new_pairs','verified_memory_failures','actual_before_queries','refusals')})for c in r['cases']],
        failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
        command_recipe=dict(product=['sh','tools/page-entry/selected/build.sh'],
          fixture=['sh','tools/page-entry/selected/tests/vpxorq128/build256.sh','<retained decoder.a>',
                   '<unique private output>','tools/page-entry/selected','<group0..11>'],
          native=[['vpxorq256-'+str(g)]for g in range(12)]+[['vpxorq256-0']]*4,
          selectors=[{}]*12+[{'LI2_VPX256_CONTROL':x}for x in FAULT_NAMES]),
        qualification_scope='This193-case family only. Original2459 and all25 changed compatibility processes are separately mandatory; supplied promotions are not native state pairs.',performance_credit=False)
    text=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<16<<10 and not any(x and len(x)>1 and x in text for x in
        (str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public receipt without private paths')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x')as f:f.write(text)


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    args=ap.parse_args()
    cfg=dict(name='vpxorq256',profile='page-selected-vpxorq256-v1',outcomes='OUTCOMES256.json',outcomes_sha=OUTCOMES_SHA,build='build256.sh',cases_json='cases256.json',cases_inc='cases256.inc')
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         len(os.sched_getaffinity(0))==1,'assertions, exact revision and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-'+cfg['name']+'-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique receipt')
    r=dict(schema=1,profile=cfg['profile'],status='failed',
        scope='Canonical unmasked/unbroadcast EVEX256.W1 VPXORQ Code2460,193 literal original-PC native/TF pairs plus12 successful startup pairs. All32 destination/source register roles,96 memory forms including real source-consistent libc bytes,16 bases/15 indices/scales, all42 length/fetch-tail combinations, one successful32-byte cross-page source read and four real ordinary/indexed failed reads. Exact low256 XOR, upper256 destination zeroing, every other initialized kernel/live vector/K/GPR/flags/selectors/FS/GS and complete source/stack/data unchanged. No mask/broadcast/other-width/store authority, address exhaustiveness, application completion or performance credit. Original37 neighbor rows remain36refusals+one mandatory supplied Code2460 typed/NONE row; original Code2785 and10 Code2791 promotions retained. Failed reads earn no instruction completion credit.',
        expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,source=None,source_unchanged=False,
        bounds=PROFILES,reproduce=['python3','evaluation/inprocess/page_selected_vpxorq256.py','--expect-revision',args.expect_revision],
        commands=[],cases=[],error=None,final_errors=[],
        totals=dict(pairs=0,new_pairs=0,startup_pairs=0,verified_memory_failures=0,refusals=0,actual_before_queries=0,ending_pairs=0,crossing_pairs=0,vtn_typed_promotions=0,vtn_supplied_none_queries=0,vpx256_typed_promotions=0,vpx256_supplied_none_queries=0,promoted_encoding_checks=0,promoted_footprint_queries=0))
    pins,binaries,aliases={},{},{}
    def pin(path):
        lexical=str(Path(path).absolute());p=Path(path).resolve(strict=True);value=fact(p)
        need(lexical not in aliases or aliases[lexical]==str(p),'input resolution changed');aliases[lexical]=str(p)
        need(str(p)not in pins or pins[str(p)]==value,'input changed');pins[str(p)]=value;return p
    def artifact(path):return dict(fact(path),mode=Path(path).stat().st_mode&0o777)
    def binary(path):
        p=Path(path).resolve(strict=True);value=artifact(p)
        need(str(p)not in binaries or binaries[str(p)]==value,'artifact changed');binaries[str(p)]=value;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items()) and all(artifact(p)==v for p,v in binaries.items()) and
             all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'actual source/artifact/alias closure')
    def run(label,argv,expected=0,profile='native',env=None):
        closure();native=profile=='native'
        row=dict(name=label,argv=list(map(str,argv)),bounds=PROFILES[profile],profile=profile,
            expected_exit=expected,capture_limit=65536 if native else 4<<20,environment=dict(ENV if env is None else env))
        r['commands'].append(row);out,err=invoke(row,private,cpu,record=native,step=native)
        need(type(row['exit'])is int and row['exit']==expected,'exact process exit '+label);return row,out,err
    builder=Build(r,private,pin,binary,run)
    states={};r['private_fixture_build']=states
    fixture_outputs=[private/cfg['name']/(cfg['name']+'-'+str(group))for group in range(12)]
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        r['hardware']=hardware(cpu)
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,out,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'],profile='metadata')
        need(not err,'source enumeration stderr')
        for raw in out.split(b'\0'):
            if raw and not os.fsdecode(raw).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(raw))
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        need(fact(pin(FIXTURE/cfg['outcomes']))['sha256']==cfg['outcomes_sha'],'exact sixteen-command family/fault protocol')
        protocol=decode((FIXTURE/cfg['outcomes']).read_bytes());commands=protocol['commands']
        need(protocol['bounds']==dict(cpu_seconds=5,address_space_bytes=512<<20,file_size_bytes=16<<20,wall_seconds=15,cpu_affinity_count=1)
          and protocol['record_header_fields']==list(NAMES) and protocol['record_header_format']=='<17Q' and
          len(commands)==16 and [c['exit']for c in commands]==[0]*12+[125]*4 and
          [c['name']for c in commands]==['group'+str(g)for g in range(12)]+['full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault'] and
          [c['argv']for c in commands]==[[cfg['name']+'-'+str(g)]for g in range(12)]+[[cfg['name']+'-0']]*4 and
          [c['environment_delta']for c in commands]==[{}]*12+[{'LI2_VPX256_CONTROL':name}for name in ('full-read-fault','cross-read-fault','indexed-full-read-fault','indexed-cross-read-fault')] and
          [c['group']for c in commands]==list(range(12))+[0]*4 and
          [c['fault_kind']for c in commands]==[0]*12+[1,2,3,4],
          'closed actual processes, selectors, failed exits and unchanged bounds')
        cases=catalogue(FIXTURE);r['catalogue']=dict(source=fact(FIXTURE/cfg['cases_json']),compiled=fact(FIXTURE/cfg['cases_inc']),rows_sha256=digest(cases),new_pairs=193,register_cases=97,memory_cases=96,group_counts=list(GROUP_COUNTS))
        products=builder.prepare();output=private/cfg['name'];output.mkdir()
        recipe_path=pin(FIXTURE/cfg['build']);lines=recipe(recipe_path,'"$cc_bin"');need(len(lines)==1,'one exact bounded link template')
        r['fixture_build']={};samples={}
        for group in range(12):
            name=cfg['name']+'-'+str(group);values={'$cc_bin':builder.tools['cc'],'$source_dir':FIXTURE,'$selected_dir':SELECTED,
                '$parent_dir':SELECTED.parent,'$decoder_archive':products['archive'],'$output_dir':output,'$group':group}
            argv=expand(lines[0],values);path=output/name
            need(argv[-2:]==['-o',str(path)] and [x for x in argv if x.startswith('-D')]==['-DVPX_GROUP='+str(group),'-DVPX_BITS=256'] and all(x in argv for x in ('-O2','-g','-nostdlib','-static','-no-pie','-Werror')),
                 'exact optimized bounded fixture recipe')
            sources=[SELECTED/'step_owner.c',SELECTED/'lifecycle_loader.c',SELECTED/'tests/generic/tf_controls.c',FIXTURE/'fixture.c',FIXTURE/'fixture.S']
            state={};states[name]=state
            headers(name+'-headers',argv,list(map(str,sources)),products['archive'],builder,pin,aliases,run,state)
            run(name+'-link',argv,profile='fixture_link',env=builder.environment);binary(path);state['artifact']=artifact(path)
            state['elf']=plain_executable(path)
            _,out,err=run(name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
            need(out==err==b'','no unresolved fixture imports')
            _,out,err=run(name+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual symbol inspection stderr');roots={'vpx256_promotions','vtn_promotions','samples','negative_sample','result','refused_last','vpb_observations','v64_fault','vpc_queries'}
            symbols={};counts={k:0 for k in roots};_,_,segments=elf(path)
            for line in out.decode().splitlines():
                w=line.split()
                if w and w[-1]in roots:counts[w[-1]]+=1
                if len(w)!=4 or w[-1]not in roots:continue
                at,n,kind,key=w;at,n=int(at,16),int(n,16)
                need(kind in ('b','B','d','D') and key not in symbols and n>0 and
                    sum(s[0]==1 and s[1]==6 and s[3]<=at<at+n<=s[3]+s[6]for s in segments)==1,'whole unique actual writable NX record symbol')
                symbols[key]=dict(address=at,bytes=n)
            need(set(symbols)==roots and all(n==1 for n in counts.values()),'all required record symbols')
            intervals=sorted((v['address'],v['address']+v['bytes'])for v in symbols.values())
            need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'all record objects disjoint')
            state['symbols']=symbols;sample=symbols['negative_sample']['bytes']
            need(symbols['vpx256_promotions']['bytes']==352 and symbols['samples']['bytes']==21*sample and symbols['result']['bytes']==136 and
                symbols['refused_last']['bytes']==40 and symbols['vpb_observations']['bytes']==5000 and symbols['v64_fault']['bytes']==96 and
                symbols['vpc_queries']['bytes']==7680 and symbols['vtn_promotions']['bytes']==3232 and 352+136+22*sample+40+5000+96+7680+3232<16<<20,
                'actual ELF-sized complete sample array/trailers below unchanged cap');samples[name]=sample
            r['fixture_build'][name]=dict(artifact=state['artifact'],elf=state['elf'],symbols_sha256=digest(symbols),
                record_bytes=352+136+22*sample+40+5000+96+7680+3232,headers_sha256=digest(state['headers']))
        for expected in commands:
            item=dict(name=expected['name'],status='failed',environment_delta=expected['environment_delta'],actual_exit=None);r['cases'].append(item)
            row,out,err=run(expected['name'],[output/expected['argv'][0]],expected['exit'],env=dict(ENV,**expected['environment_delta']))
            item['actual_exit']=row['exit'];need(out==expected['stdout'].encode() and err==expected['stderr'].encode(),'exact finite output')
            captured=row['captures']['record'];path=binary(private/captured['file'])
            need(fact(path)=={k:captured[k]for k in ('bytes','sha256')},'complete actual capture binding');item['record']=fact(path)
            value=record(path.read_bytes(),expected,samples[expected['argv'][0]],cases)
            need(value['operation']==('completed'if expected['exit']==0 else 'failed_memory_read'),
                 'no failed operation relabelled completed')
            for key in r['totals']:r['totals'][key]+=value[key]
            item.update(status='accepted_observation',outcome=value)
        need(r['totals']==dict(pairs=205,new_pairs=193,startup_pairs=16,verified_memory_failures=4,refusals=16*REFUSALS,actual_before_queries=394,ending_pairs=77,crossing_pairs=116,vtn_typed_promotions=160,vtn_supplied_none_queries=160,vpx256_typed_promotions=16,vpx256_supplied_none_queries=16,promoted_encoding_checks=16,promoted_footprint_queries=16) and
            len(r['cases'])==16 and all(c['status']=='accepted_observation'for c in r['cases']),
            'all193 selected pairs plus12 completed startup pairs and four true failed-read prefixes')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors']+=builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for path in fixture_outputs:
            try:
                if path.exists()or path.is_symlink():
                    state=states.setdefault(path.name,{})
                    state['artifact_after']=artifact(path);binary(path)
            except BaseException as exc:r['final_errors'].append('fixture artifact closure: '+str(path)+': '+repr(exc))
        for row in r['commands']:
            for capture in row.get('captures',{}).values():
                try:
                    path=private/capture['file'];need(path.parent==private and fact(path)=={k:capture[k]for k in ('bytes','sha256')},'retained capture closure');binary(path)
                except BaseException as exc:r['final_errors'].append('capture closure: '+repr(exc))
        r['inputs_before'],r['binaries_before'],r['aliases']=pins,binaries,aliases
        for name,before,observe in (('inputs_after',pins,fact),('binaries_after',binaries,artifact)):
            after=r[name]={}
            for p,value in before.items():
                try:after[p]=observe(p);need(after[p]==value,'final exact identity')
                except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        try:r['source_unchanged']=source()==r['source'];need(r['source_unchanged'],'source closure')
        except BaseException as exc:r['final_errors'].append('source closure: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and
            not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']or r['build']['status']!='passed':r['status']='failed'
        save(private/'receipt.json',r);publish(public,r,private)
    print(json.dumps(dict(status=r['status'],totals=r['totals'],receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
