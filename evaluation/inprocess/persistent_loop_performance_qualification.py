"""Authenticate the original392/522 gate, including its original five predecessors.

The copied inner validation is the existing qualification body, without a child,
publication, revision exception, or changed comparison. Both archive profiles stay
distinct: this gate must match the original native41 ten-source archive.
"""
import csv
import io
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace
from checks import source
from page_selected import fact,need
from persistent_dynamic import BOUNDS,digest,named
from scalar_reuse_performance import closed
import persistent_joint_startup as joint
import cross_pair_loop_helpers as cross
ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent

def authenticate(public_path, expected_sha256, current, pin, binary, old_archive):
    public_path=pin(public_path)
    need(public_path.parent==HERE/'results' and public_path.suffix=='.json' and
         re.fullmatch('[0-9a-f]{64}',expected_sha256) is not None and
         fact(public_path)['sha256']==expected_sha256 and public_path.stat().st_size<=32768,
         'explicit original392/522 qualification receipt')
    public=json.loads(public_path.read_bytes())
    receipt=pin(ROOT/'target/evaluation/inprocess'/public_path.stem/'receipt.json')
    need(fact(receipt)==public['receipt'],'whole actual qualification receipt')
    actual=json.loads(receipt.read_bytes())
    need(actual['schema']==public['schema']==1 and
         actual['profile']==public['profile']=='persistent-cross-pair-qualification-v1' and
         actual['status']==public['status']=='passed' and
         actual['source']==public['source']==current['source']==source() and
         actual['expected_revision']==public['expected_revision']==current['revision'] and
         actual['cpu']==public['cpu']==current['cpu'] and actual['hardware']==current['hardware'] and
         actual['bounds']==public['bounds']==BOUNDS and actual['required']==public['required']==['original392','cross_pair522'] and
         actual['source_unchanged'] is public['source_unchanged'] is True and
         actual['cleanup_complete'] is public['cleanup_complete'] is True and
         actual['whole_profile_qualified'] is public['whole_profile_qualified'] is True and
         actual['error'] is None and public['error_type'] is None and
         all(actual[k] is public[k] is False for k in ('whole_ls_eligibility_credit','performance_credit','group_fault_qualification')),
         'passed original qualification on exact current source/CPU/hardware; no historical substitution')
    hw=dict(actual['hardware']); flags=hw.pop('isa_flags')
    hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    need(public['hardware']==hw,'whole original qualification hardware projection')
    def retained():
        need(fact(receipt)==public['receipt'],'immutable original qualification receipt')
        for p,v in actual['inputs'].items(): need(fact(pin(p))==v,'whole original qualification input')
        for p,v in actual['artifacts'].items():
            item=binary(p); need(dict(fact(item),mode=item.stat().st_mode&0o777)==v,'whole original qualification artifact')
    retained()
    reproduction=public['reproduce']
    need(len(reproduction)==14 and reproduction[:8]==['cpuset-alloc','run','--cores','1','--','python3','-B',
        'evaluation/inprocess/cross_pair_qualification.py'] and
        reproduction[8:11]==['--expect-revision',current['revision'],'--joint-receipt'] and
        reproduction[12]=='--cross-pair-receipt','actual unchanged qualification invocation')
    args=SimpleNamespace(expect_revision=current['revision'],joint_receipt=ROOT/reproduction[11],
                         cross_pair_receipt=ROOT/reproduction[13])
    r=dict(source=current['source'],expected_revision=current['revision'],cpu=current['cpu'],hardware=current['hardware'])
    cpu=current['cpu']
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
    crows=commands(c,cdir);cases(c,crows,cross.PAIR_EXPECTED,cross.EXPECTED_STATUS,36,320,24,33,True)
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
    need(r['archive']==actual['archive']==public['archive']==old_archive and
         r['original392']==actual['original392']==public['original392'] and
         r['cross_pair522']==actual['cross_pair522']==public['cross_pair522'],
         'whole original qualification joined to the separate native41 archive')
    for name in ('fixed','dynamic','group','resident','retained'):
        need(r[name+'_prerequisite']==actual[name+'_prerequisite'],'unchanged original qualification predecessor')
    stream=io.StringIO(); writer=csv.writer(stream,lineterminator='\n')
    writer.writerow(('revision','status','original392_required','cross_pair522_required','whole_profile_qualified'))
    writer.writerow((current['revision'],'passed',1,1,1))
    need(pin(public_path.with_suffix('.csv')).read_bytes()==stream.getvalue().encode(),'whole original qualification CSV')
    retained()
    return dict(file=str(public_path.relative_to(ROOT)),**fact(public_path),receipt=fact(receipt),
        status='passed',original392=r['original392'],cross_pair522=r['cross_pair522'],archive=r['archive'],
        source_sha256=digest(current['source']),cpu=current['cpu'],hardware_sha256=digest(current['hardware']),
        whole_profile_qualified=True,performance_credit=False)
