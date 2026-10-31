#!/usr/bin/env python3
"""Require both original392 and cross-pair522 finite cohorts; no LS/performance credit.

This read-only gate never launches a target or turns a failed cohort into a pass.
Run both collectors on one reserved CPU at the same committed revision first.
"""
import argparse,csv,hashlib,json,os,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import fact,need,save
from persistent_dynamic import BOUNDS,digest,named
from scalar_reuse_performance import closed
import persistent_joint_startup as joint
import cross_pair_loop_helpers as cross

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--joint-receipt',type=Path,required=True)
    ap.add_argument('--cross-pair-receipt',type=Path,required=True)
    args=ap.parse_args();os.chdir(ROOT)
    args.joint_receipt=args.joint_receipt.resolve(strict=True)
    args.cross_pair_receipt=args.cross_pair_receipt.resolve(strict=True)
    need(all(p.parent==HERE/'results'and p.suffix=='.json'for p in
        (args.joint_receipt,args.cross_pair_receipt)),'portable repository public receipt inputs')
    need(not sys.flags.optimize and len(os.sched_getaffinity(0))==1,'assertions and one reserved CPU')
    cpu=next(iter(os.sched_getaffinity(0)))
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name=stamp+'-cross-pair-qualification-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/name;private.mkdir(mode=0o700)
    public=HERE/'results'/(name+'.json')
    r=dict(schema=1,profile='persistent-cross-pair-qualification-v1',status='failed',
        expected_revision=args.expect_revision,cpu=cpu,hardware=hardware(cpu),source=None,
        whole_profile_qualified=False,whole_ls_eligibility_credit=False,performance_credit=False,
        group_fault_qualification=False,error=None,source_unchanged=False,cleanup_complete=True,
        required=['original392','cross_pair522'],bounds=BOUNDS)
    inputs={};artifacts={}
    def pin(path,want=None):
        p=Path(path).resolve(strict=True);value=fact(p)
        need(str(p)not in inputs or inputs[str(p)]==value,'stable qualification input')
        if want is not None:need(value==want,'whole exact retained qualification input')
        inputs[str(p)]=value;return p
    def binary(path):
        p=pin(path);value=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p)not in artifacts or artifacts[str(p)]==value,'stable qualification artifact')
        artifacts[str(p)]=value;return p
    def path(value):
        p=pin(value);need(p.parent==HERE/'results'and p.suffix=='.json'and
            p.stat().st_size<=32768,'bounded canonical public cohort receipt');return p
    def commands(actual,directory):
        rows=actual['commands'];need(rows and len({x['name']for x in rows})==len(rows),'all actual command identities')
        for row in rows:
            need(type(row.get('exit'))is int and row.get('reaped')is True and row.get('timed_out')is False and
                 not row.get('error')and row.get('cleanup_errors')==[]and type(row.get('descriptors'))is list and
                 all(d.get('closed')is True for d in row['descriptors'])and row['bounds']==BOUNDS[row['profile']]and
                 (row.get('expected_exit')is None or row['exit']==row['expected_exit']),
                 'every command retains exact original bounds, outcome and complete cleanup')
            for capture in row['captures'].values():
                p=pin(directory/capture['file'],{k:capture[k]for k in('bytes','sha256')})
                need(p.is_relative_to(directory),'actual capture remains in its own retained cohort')
        return {x['name']:x for x in rows}
    def cases(actual,rows,pair,expected,app_count,owner_count,pair_count,tls_count,effect):
        need([(c['lane'],c['mode'],c['control'])for c in actual['cases']]==
            [('native',0,0),('maintained',0,0),('differential',0,0)],'all three distinct actual lanes without skipped cases')
        for c in actual['cases']:
            row=rows[c['label']];lane=c['lane']
            need(c['status']==expected[lane,0]and c['launched']is True and
                 c['expected_exit']==c['exit']==row['expected_exit']==row['exit']==0 and
                 row['profile']=='program'and c['timed_out']is False and c['whole_process_ns']==row['duration_ns']and
                 c['captures']=={k:{n:v[n]for n in('bytes','sha256')}for k,v in row['captures'].items()},
                 'each successful complete subject is the actual bounded child')
            if lane=='native':named(c['application_controls'],app_count,row['captures']['stdout']['sha256'])
            else:
                for key,count,stream,hash_key in (
                    ('owner_reader_controls',owner_count,'record','original_sha256'),
                    ('terminal_controls',73,'stderr','original_stderr_sha256'),
                    ('native_probe_controls',22,'stderr','original_stderr_sha256'),
                    ('repeat_tls_controls',tls_count,'stderr','original_stderr_sha256'),
                    ('subentry_controls',19,'stderr','original_stderr_sha256')):
                    named(c[key],count,row['captures'][stream]['sha256'],hash_key=hash_key)
                if effect:named(c['effect_controls'],12,row['captures']['stderr']['sha256'],hash_key='original_stderr_sha256')
                need(c['pair']==pair,'whole exact full-state pair summary with every original obligation')
                controls=c['pair_controls'];refusals=controls['refusals']
                need(type(refusals)is list and len(refusals)==len(set(refusals))==pair_count and
                     all(type(n)is str and n for n in refusals)and controls['native_operations']==0,
                     'all separate exact full-state pair reader controls')
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean current revision')
        jp=path(args.joint_receipt);cp=path(args.cross_pair_receipt)
        jpublic,j=closed(jp,r,pin,binary)
        need(j['profile']==jpublic['profile']=='persistent-joint-subentry-finite-v1'and
             j['status']==jpublic['status']=='passed'and j['bounds']==BOUNDS,
             'original392 must pass; no prior failure or substitute cohort is accepted')
        archive=binary(j['build']['artifacts']['decoder.a']['path'])
        need(fact(archive)=={k:j['build']['artifacts']['decoder.a'][k]for k in('bytes','sha256')},'actual original392 decoder archive')
        # Reuse the five original prerequisite validators, in their original order.
        for key,validator,extra in (
            ('fixed',joint.fixed_prerequisite,()),('dynamic',joint.dynamic_prerequisite,()),
            ('group',joint.group_prerequisite,()),('resident',joint.resident_prerequisite,(joint.resident,)),
            ('retained',joint.retained_prerequisite,(joint.retained,))):
            old=j[key+'_prerequisite'];p=path(HERE/'results'/old['file'])
            r[key+'_prerequisite']=validator(p,r,pin,binary,archive,*extra)
            need(r[key+'_prerequisite']==old==jpublic[key+'_prerequisite'],
                 'same five mandatory original cohorts, source, CPU and archive')
        jdir=ROOT/'target/evaluation/inprocess'/jp.stem
        jrows=commands(j,jdir)
        cases(j,jrows,joint.PAIR_EXPECTED,joint.EXPECTED_STATUS,24,193,12,33,False)
        need(jpublic['cases']==[joint.public_case(c)for c in j['cases']]and
             pin(jp.with_suffix('.csv')).read_bytes()==joint.csv_projection(jpublic['cases']),
             'complete original392 public case and CSV projection')
        need(j['seed_prerequisite']['status']=='passed'and j['namespace_controls']==dict(status='passed',tests=12,existing=5,added=7)and
             j['application_build']['copy_oracle']['status']=='passed'and
             [s['name']for s in j['component_oracles']]==list(joint.COMPONENT_ORDER)and
             all(s['status']=='passed'and s['summaries']==[joint.COMPONENT_SUMMARIES[s['name']]]for s in j['component_oracles'])and
             all(j[k]['status']=='passed'for k in('native_probe_component','maps_parse_component')),
             'original392 seed, namespace, copy and every source component remain required')
        cpublic=json.loads(cp.read_bytes());cdir=ROOT/'target/evaluation/inprocess'/cp.stem
        cpath=pin(cdir/'receipt.json',cpublic['receipt']);c=json.loads(cpath.read_bytes())
        need(c['profile']==cpublic['profile']=='persistent-cross-pair-finite-v1'and
             c['status']==cpublic['status']=='passed'and c['revision']==args.expect_revision and
             c['source']==cpublic['source']==r['source']and c['cpu']==cpublic['cpu']==cpu and
             c['hardware']==cpublic['hardware']==r['hardware']and c['bounds']==cpublic['bounds']==BOUNDS and
             c['source_unchanged']is cpublic['source_unchanged']is True and
             c['cleanup_complete']is cpublic['cleanup_complete']is True and c['error']is None and c['final_errors']==[]and
             c['whole_profile_qualified']is cpublic['whole_profile_qualified']is False,
             'separate successful cross-pair finite proof on identical source CPU hardware and bounds')
        for p,value in c['inputs'].items():pin(p,value)
        for p,value in c['artifacts'].items():need(dict(fact(binary(p)),mode=Path(p).stat().st_mode&0o777)==value,'whole cross-pair artifact and mode')
        for lexical,resolved in c['aliases'].items():need(str(pin(lexical))==resolved,'whole cross-pair alias closure')
        for p,present in c['presence'].items():need(os.path.lexists(p)==present,'unchanged configuration presence')
        need(c['build']['status']=='passed'and c['build']['command_completed']is True and
             {k:c['build']['artifacts']['decoder.a'][k]for k in('bytes','sha256')}==fact(archive)==cpublic['archive'],
             'same actual fresh archive in original392 and cross-pair cohorts')
        need(cpublic['cases']==cross.public_cases(c['cases'])and cpublic['command_count']==len(c['commands'])and
             cpublic['commands_sha256']==digest(c['commands']),'whole compact cross-pair case and command projection')
        crows=commands(c,cdir);cases(c,crows,cross.PAIR_EXPECTED,cross.EXPECTED_STATUS,36,304,24,33,True)
        need(all(c[k]['status']=='passed'for k in('capture_codec_component','empty_namespace_component',
            'subentry_component','native_probe_component','maps_parse_component','seed_prerequisite'))and
            c['application_build']['copy_oracle']['status']=='passed'and
            [s['name']for s in c['component_oracles']]==list(joint.COMPONENT_ORDER)and
            all(s['status']=='passed'and s['summaries']==[joint.COMPONENT_SUMMARIES[s['name']]]for s in c['component_oracles']),
            'all cross-pair transport, authority, dispatch, copy, seed and namespace gates passed')
        handoff=c['cross_page_handoff_component']
        need(handoff['status']=='passed'and handoff['counts']==
             dict(eligibility=64,refusals=71,close=34,fresh=29,consume=18,total=216)and
             handoff['exit']==0 and handoff['native_operations']==0 and
             handoff['qualification_credit']is False and handoff['bounds']==BOUNDS['finite']and
             cpublic['cross_page_handoff_component']=={k:handoff[k]for k in
                 ('status','counts','exit','duration_ns','native_operations','qualification_credit')},
             'mandatory actual cross-page close predicates remain separate from native qualification')
        import io
        stream=io.StringIO();writer=csv.writer(stream,lineterminator='\n')
        writer.writerow(('revision','command','exit','duration_ns','status'))
        for row in c['commands']:writer.writerow((args.expect_revision,row['name'],row.get('exit'),row.get('duration_ns'),c['status']))
        need(pin(cp.with_suffix('.csv')).read_bytes()==stream.getvalue().encode(),'whole cross-pair command CSV projection')
        r.update(status='passed',whole_profile_qualified=True,original392=fact(jp),cross_pair522=fact(cp),archive=fact(archive))
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        try:
            need(source()==r['source']and all(fact(p)==v for p,v in inputs.items())and
                 all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),
                 'all source and retained qualification inputs unchanged')
            r['source_unchanged']=True
        except BaseException as exc:r['error']=r['error']or type(exc).__name__+': '+str(exc)
        if r['error'] or not r['source_unchanged']:r.update(status='failed',whole_profile_qualified=False)
        r['inputs']=inputs;r['artifacts']=artifacts;save(private/'receipt.json',r)
        summary={k:r[k]for k in('schema','profile','status','expected_revision','cpu','source','source_unchanged',
            'cleanup_complete','whole_profile_qualified','whole_ls_eligibility_credit','performance_credit',
            'group_fault_qualification','required','bounds')}
        summary.update(receipt=fact(private/'receipt.json'),error_type=r['error'].split(':',1)[0]if r['error']else None,
            original392=r.get('original392'),cross_pair522=r.get('cross_pair522'),archive=r.get('archive'))
        hw=dict(r['hardware']);flags=hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        summary.update(hardware=hw,reproduce=['cpuset-alloc','run','--cores','1','--','python3','-B',
            'evaluation/inprocess/cross_pair_qualification.py','--expect-revision',args.expect_revision,
            '--joint-receipt',str(args.joint_receipt.relative_to(ROOT)),
            '--cross-pair-receipt',str(args.cross_pair_receipt.relative_to(ROOT))])
        payload=(json.dumps(summary,sort_keys=True)+'\n').encode();need(len(payload)<=32768 and b'/home/'not in payload,'compact qualification projection')
        with public.open('xb')as f:f.write(payload)
        with public.with_suffix('.csv').open('x',newline='')as f:
            w=csv.writer(f,lineterminator='\n');w.writerow(('revision','status','original392_required','cross_pair522_required','whole_profile_qualified'))
            w.writerow((args.expect_revision,r['status'],1,1,int(r['whole_profile_qualified'])))
    print(json.dumps(dict(status=r['status'],receipt=str(public.relative_to(ROOT)))))
    return int(r['status']!='passed')

if __name__=='__main__':raise SystemExit(main())
