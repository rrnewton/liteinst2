"""Authenticate the exact completed return-head collector; never replay readers."""
import importlib.util
import json
from pathlib import Path
import re
import struct
from types import SimpleNamespace

from call_owner import custody
from ret_owner import prerequisites as old
from ret_dispatch.run import LINK_NAMES
from scalar_span_trace_build import fast_bytes_completed

ROOT = custody.ROOT
SOURCE = 'evaluation/inprocess/call_return_heads/SOURCE.json'
BOUNDS = {'release_build':[30,512<<20,16<<20,60],
          'metadata':[30,512<<20,64<<20,60], 'inspect':[10,256<<20,4<<20,20],
          'native':[5,512<<20,16<<20,15], 'program':[30,512<<20,16<<20,60],
          'seed':[5,512<<20,16<<20,15], 'finite':[5,512<<20,16<<20,15]}
CASES = [('subject-'+lane+'-1-0',1,lane) for lane in ('native','maintained','differential')]
RESULT = dict(native_subjects=1,gated_subjects=2,full_builds=2,byte_oracles=2,seed_prerequisites=1,
    native_frames=10,application_controls=60,owner_controls=496,pair_controls=104,
    terminal_controls=146,tls_controls=66,probe_controls=44,subentry_controls=38,effect_controls=24,
    finite_prerequisites=4,original_owner_subjects=9,fresh_components=9,owner_pairs=2,
    plan_version=8,return_head_index=5,raw_bytes=1261760,record_bytes=1261824,record_limit=4194304,
    archive_builds=0,whole_profile_qualified=False,qualification_credit=False,performance_credit=False)


def check(path, sha256, current, pin, binary, archive, fresh_build):
    need = old.need
    def keep(name):
        p = pin(name); binary(p)
        return p
    path = keep(path)
    need(path.is_relative_to(ROOT/'target/evaluation/inprocess') and path.name=='receipt.json' and
         re.fullmatch('[0-9a-f]{64}',sha256) is not None and custody.fact(path)['sha256']==sha256,
         'explicit whole completed return-head receipt')
    p = custody.load(path)
    need(p['schema']==1 and p['profile']=='public-call-return-heads-owner-v1' and p['status']=='passed' and
         p['revision']==current['revision'] and p['source']==current['source'] and
         p['cpu']==current['cpu']==3 and p['hardware']==current['hardware'] and
         p['bounds']==BOUNDS and p['result']==RESULT and
         p['pending']==['original392','original522','ten_run_DR'] and p['archive_builds']==0 and
         p['qualification_credit'] is False and p['performance_credit'] is False and
         p['error'] is None and p['final_errors']==[] and
         all(p[k] is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete')),
         'complete original-bound v8 observation on this clean source/CPU/hardware, no qualification')
    source_path = keep(ROOT/SOURCE)
    need(p['inputs'][str(source_path)]==custody.fact(source_path), 'whole actually executed installed return-head collector source')
    manifest = custody.load(source_path)
    for group in ('inputs','artifacts'):
        for name,wanted in p[group].items():
            need(custody.fact(keep(name))==wanted, 'whole retained return-head '+group)
    for name,wanted in manifest['inputs'].items():
        q=keep(ROOT/name)
        need(custody.fact(q)==wanted==p['inputs'][str(q)], 'executed frozen input, not a later candidate')
    for name,wanted in manifest['artifacts'].items():
        q=keep(source_path.parent/name)
        need(custody.fact(q)==wanted==p['inputs'][str(q)], 'whole executed collector artifact')
    for name,target in p['aliases'].items():
        need(str(keep(name))==target, 'whole retained input alias')
    expected_context={}
    for directory,names in manifest['source_roster'].items():
        for name,wanted in names.items():
            relative=str(Path(directory)/name);q=keep(ROOT/relative)
            need(custody.fact(q)==wanted==p['inputs'][str(q)] and relative not in expected_context,
                 'every exact installed source roster member, no duplicated name')
            expected_context[relative]=dict(origin=relative,copy=False,**wanted)
    expected_links={}
    selected=ROOT/'tools/page-entry/selected'
    for case in manifest['components']:
        observed_aliases={}
        for original,alias in case['source_aliases'].items():
            a=selected/original;declared=selected/alias
            need(a.parent==declared.parent and (original,alias) in
                 (('tests/call_dispatch/model.c','tests/call_dispatch/call_model.c'),
                  ('tests/ret_dispatch/model.c','tests/ret_dispatch/ret_model.c')),
                 'only original exact source-owned model aliases')
            b=path.parent/'components'/case['name']/'source-aliases'/a.parent.name/declared.name
            header=b.with_name('model.h');observed_aliases[str(a)]=str(b)
            expected_links[str(b)]=str(keep(a));expected_links[str(header)]=str(keep(a.with_name('model.h')))
        need(p['components'][case['name']]['source_aliases']==observed_aliases,
             'exact bounded temporary aliases of installed models and local headers')
    need(p['context']==expected_context and p['context_links']==expected_links and
         p['namespace_aliases']=={}, 'all installed source entries, exact diagnostic aliases and empty dependency namespace')
    for name,target in expected_links.items():
        need(Path(name).is_symlink() and str(Path(name).readlink())==target and str(keep(name))==target,
             'every actual source/header diagnostic alias remains exact')
    for name,present in p['loader_presence'].items():
        need(Path(name).exists()==present, 'same loader configuration presence')
    component_names=[x['name'] for x in manifest['components']]
    tool_names=('cc','nm','readelf','git','sh','python','cc1','collect2','as','ld')
    component_commands=['components-tool-'+x+'-dependencies' for x in tool_names]
    component_commands+=['components-link-'+x for x in LINK_NAMES]+['components-archive-exports']
    component_commands+=['components-'+name+'-'+step for name in component_names
                         for step in ('headers','build','dependencies','component')]
    commands=(old.CALL_PREFIX[:12]+component_commands+old.CALL_PREFIX[12:]+
        [lane+'-'+name.replace('whole-call-owner-layout','whole-ret-owner-layout')
         for lane in ('maintained','differential') for name in old.CALL_LANE]+[x[0] for x in CASES])
    need([c['name'] for c in p['commands']]==commands and len(commands)==len(set(commands)),
         'fixed complete nine-component/three-subject schedule, no retries or omitted gates')
    records={label for label,_,lane in CASES if lane!='native'}
    for c in p['commands']:
        need(type(c['exit']) is int and c['exit']==c['expected_exit']==0 and c['reaped'] is True and
             c['timed_out'] is False and c['error'] is None and c['cleanup_errors']==[] and
             all(x['closed'] is True for x in c['descriptors']) and c['bounds']==BOUNDS[c['profile']] and
             c['capture_limit']==16<<20, 'every original bounded command completed and reaped')
        if c['name'].startswith('components-'):
            need(c['profile']==('finite' if c['name'].endswith('-component') else 'release_build'),
                 'all original finite component and compile bounds')
        need(set(c['captures'])==({'stdout','stderr','record'} if c['name'] in records else {'stdout','stderr'}),
             'exact native/gated stream ownership')
        for stream,f in c['captures'].items():
            q=path.parent/f['file']
            need(q.parent==path.parent and not q.is_symlink() and
                 old.value(custody.fact(keep(q)))==old.value(f) and
                 p['artifacts'][str(q)]==custody.fact(q), 'whole actual command capture')
            if stream=='record':need(f['bytes']==1261824<4<<20, 'complete unchanged protected record cap')
    reuse=p['archive_reuse']; retained_build=reuse['build']
    archive_path=old.child(p,reuse['receipt'],keep)
    checked_archive,checked_build,_,_,_=custody.check_archive(
        archive_path,custody.fact(archive_path)['sha256'],current,keep)
    need(reuse['archive']==custody.fact(checked_archive)==custody.fact(archive) and
         checked_build==retained_build and reuse['cpu']==3 and reuse['fresh_build'] is False and
         reuse['source_tools_features_verified'] is True and reuse['prior_status']=='passed' and
         reuse['prior_owner_credit'] is False, 'same complete retained decoder and source authority')
    need(all(retained_build[k]==fresh_build[k] for k in
             ('dep_info','decoder_features','archive_text_exports','cargo_configuration')) and
         set(retained_build['tools'])==set(fresh_build['tools']) and
         all(old.value(retained_build['tools'][n])==old.value(fresh_build['tools'][n])
             for n in retained_build['tools']), 'fresh archive has exact source/tool/configuration/exports')
    # The source-owned original helper rechecks the complete installed nine-case
    # gate; only these already-authenticated retained chain fields augment current.
    prior_current=dict(current,archive_reuse=reuse,finite_prerequisites=p['finite_prerequisites'])
    original=p['original_owner_prerequisite']; original_path=old.child(p,original['receipt'],keep)
    need(old.value(original['receipt'])==current['ret_owner_prerequisite']['receipt'],
         'the same complete original-nine prerequisite already required by this program')
    helper_path=keep(source_path.parent/'original_owner.py')
    spec=importlib.util.spec_from_file_location('return_heads_original_gate',helper_path)
    need(spec is not None and spec.loader is not None, 'exact source-owned metadata gate loader')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    checked=helper.check(SimpleNamespace(ret_owner_receipt=original_path,
        ret_owner_receipt_sha256=custody.fact(original_path)['sha256']),prior_current,keep,archive,retained_build)
    need(checked==original, 'whole installed original-nine gate plus exact version7 raw/session supplement')
    need(set(p['components'])==set(component_names) and len(component_names)==9,
         'all eight original off/on cohorts and additive return-head component')
    for case in manifest['components']:
        name=case['name'];state=p['components'][name]; row=old.row(p,'components-'+name+'-component')
        result={k:int(v) for k,v in (word.split('=') for word in case['stdout'].split()[1:])}
        need(state['status']=='passed' and state['return_heads']==case['return_heads'] and
             state['recipe']==case['recipe_fact'] and state['result']==result and
             old.captured(path,p,row['name'],'stdout')==case['stdout'].encode() and
             old.captured(path,p,row['name'],'stderr')==b'' and
             custody.fact(keep(row['argv'][0]))==state['binary'],
             'each complete actual component population and executed binary')
    seed=p['seed_prerequisite'];row=old.row(p,'seed-prerequisite')
    need(seed['status']=='passed' and seed['launched'] is True and seed['exit']==0 and
         seed['timed_out'] is False and seed['pid']==row['pid'] and seed['format']['cpu']==3 and
         seed['bounds']==row['bounds']==BOUNDS['seed'] and seed['whole_process_ns']==row['duration_ns'] and
         seed['captures']=={k:old.value(v) for k,v in row['captures'].items()} and
         seed['profile']['record_sha256']==row['captures']['stdout']['sha256'] and
         seed['profile']['pid']==row['pid'] and seed['profile']['cpu']==3,
         'complete actual original-bound whole-state seed')
    need(set(p['lanes'])=={'maintained','differential'}, 'both actual v8 mapping lanes')
    for lane in ('maintained','differential'):
        state=p['lanes'][lane];build=state['release_build'];binding=build['persistent_binding']
        need(build['status']=='passed' and build['ret_owner_capture'] is True and build['capture'] is True and
             build['profile']=='persistent-call-return-heads-owner-'+
               ('differential' if lane=='differential' else 'capture')+'-v1' and
             binding['call_return_heads'] is True and binding['plan_version']==8 and
             binding['ret_dispatch'] is True and binding['call_dispatch'] is True and
             binding['typed_capture'] is True and binding['maps_differential']==(lane=='differential') and
             build['archive']==old.value(custody.fact(archive)) and
             state['schema']==dict(types=128,fields=1388,raw_bytes=1261760,record_bytes_observed=0,
                                  schema_only=True,owner_credit=0), 'two complete v8 builds and exact schema')
        fast_bytes_completed(build,p['commands'],keep)
    need([(c['label'],c['mode'],c['mapping_lane']) for c in p['cases']]==CASES,
         'native then maintained/differential mode1, no substituted old poison case')
    for case,(label,mode,lane) in zip(p['cases'],CASES,strict=True):
        row=old.row(p,label);gated=lane!='native'
        need(case['status']=='passed' and case['launched'] is True and case.get('error') is None and
             case['lane']==('gated' if gated else 'native') and case['control']==0 and
             case['exit']==case['expected_exit']==0 and case['timed_out'] is False and
             case['captures']==row['captures'] and case['whole_process_ns']==row['duration_ns'] and
             case['bounds']==row['bounds']==BOUNDS['program' if gated else 'native'],
             'each fresh bounded process joins its complete actual result')
        if not gated:
            old.ledger(case['application_controls'],60,row['captures']['stdout']['sha256'],'original_sha256')
            need(row['captures']['stderr']['bytes']==0, 'complete native reference stderr empty')
            continue
        old.ledger(case['owner_controls'],248,row['captures']['record']['sha256'],'source_sha256')
        old.ledger(case['pair_controls'],52)
        need(case['owner_record_sha256']==row['captures']['record']['sha256'], 'whole actual owner input')
        for key,count in (('terminal',73),('tls',33),('probe',22),('subentry',19),('effect',12)):
            old.ledger(case[key+'_controls'],count,row['captures']['stderr']['sha256'])
        expected=dict(observed_ret_owner=1,mode=1,return_head_observation=True,plan_version=8,
            directory_heads=8,return_head_index=5,invocations=1,native_instructions=9,native_full_frames=10,
            generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
            modeled_completed_in_generated=7,generated_ret_load=1,cached_call=1,cached_ret_hit=1,
            loaded_miss=0,private_C3=0,consumed_word_poisoned=0,original_return_pc=p['application_layout']['page']+0x60d,
            stack_bytes=520,measured_interior_signals=0,lifetime_mode=2,registration_epoch=0,
            registration_calls=0,word_observed=0,qualification_credit=False,performance_credit=False)
        need(case['pair']==expected and case['owner_summary']==dict(mode=1,cold_publications=1,completed=1,
            domain_members=1,closed_pages=17,anchor_released=1,interior_signals=0,lifetime_mode=2,
            registration_epoch=0,registration_calls=0,word_observed=0,cached_ret_hits=1,loaded_misses=0,
            consumed_word_poisoned=0), 'exact full-state cached return-head result, no loaded-miss credit')
        raw=old.captured(path,p,label,'record');layout=custody.load(keep(path.parent/lane/'layout.json'))
        types=layout['types']
        def field(kind,key):return types[kind]['fields'][key]['offset']
        at=field('prto_wire','payload')+field('pe_payload','plan')
        need(struct.unpack_from('<I',raw,at+field('li2_pg_compact','version'))[0]==8 and
             struct.unpack_from('<I',raw,at+field('li2_pg_compact','heads'))[0]==8,
             'literal actual v8 eight-head observation')
    return dict(receipt=old.value(custody.fact(path)),source=old.value(custody.fact(source_path)),
        result=RESULT,components=9,owner_subjects=3,original_owner_subjects=9,
        executions_here=0,controls_replayed=0,qualification_credit=False,performance_credit=False)
