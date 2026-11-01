"""Complete source-owned finite prerequisite and decoder archive custody; no qualification."""
import hashlib
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
FEATURES = ['scalar-region','scalar-span','linked-epoch','mov-guard']
DECODER = tuple('tools/page-entry/selected/decoder/src/'+x+'.rs' for x in
    ('lib','abi','arena','decode','scan','tf','write_footprint','admission_oneshot','region','mov_guard'))
COMPONENT_STDOUT = {
 'call_dispatch': b'call-dispatch descriptors=16 decoded=736 models=4111 forms=512 arguments=8 bindings=12 corruptions=16 interiors=466 geometry=4 recovery_controls=8\n',
 'call_dispatch_plan': b'call-dispatch-plan plans=51 models=1105 refusals=6 geometry=12 capacities=2 corruptions=17 interiors=466 compact_recoveries=164070\n'}


def need(ok, message):
    if not ok: raise ValueError(message)


def fact(path):
    p=Path(path);need(p.is_file() and not p.is_symlink(),'whole regular prerequisite file')
    b=p.read_bytes()
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=format(p.stat().st_mode&0o7777,'04o'))


def unique(pairs):
    d=dict(pairs);need(len(d)==len(pairs),'duplicate prerequisite JSON field');return d


def load(path):
    return json.loads(Path(path).read_bytes(),object_pairs_hook=unique)


def whole_receipt(path, expected_sha256, current, pin, profile, status):
    path=pin(path);need(re.fullmatch('[0-9a-f]{64}',expected_sha256) is not None and
        fact(path)['sha256']==expected_sha256,'explicit whole prerequisite receipt identity')
    old=load(path)
    need(old['profile']==profile and old['status']==status and
         old['revision']==current['revision'] and old['source']==current['source'] and
         old['cpu']==current['cpu'] and old['hardware']==current['hardware'],
         'same exact source revision, CPU, hardware and typed prerequisite')
    need(all(old[k] is True for k in ('source_unchanged','inputs_unchanged','cleanup_complete')) and
         old['error'] is None and old['final_errors']==[] and
         old['qualification_credit'] is False and old['performance_credit'] is False,
         'complete closed unqualified prerequisite, never inherit failed origin success')
    for key in ('inputs','artifacts'):
        for name,wanted in old[key].items():
            need(fact(pin(name))==wanted,'whole prerequisite '+key+': '+name)
    for name,target in old['aliases'].items():
        need(str(pin(name))==target,'whole prerequisite alias')
    for name,target in old.get('context_links',{}).items():
        need(Path(name).is_symlink() and os.readlink(name)==target and
             pin(name)==Path(target).resolve(strict=True),'whole prerequisite context link')
    for name,wanted in old['loader_presence'].items():
        need(Path(name).exists()==wanted,'same loader configuration presence')
    names=[]
    for row in old['commands']:
        names.append(row['name'])
        need(row['exit']==row['expected_exit']==0 and row['error'] is None and
             row['timed_out'] is False and row['reaped'] is True and row['cleanup_errors']==[] and
             all(x['closed'] is True for x in row['descriptors']) and row['capture_limit']==16<<20 and
             row['bounds'] in old['bounds'].values(),'every prerequisite process bounded, successful and reaped')
        need(set(row['captures'])=={'stdout','stderr'},'both whole prerequisite captures')
        for value in row['captures'].values():
            q=path.parent/value['file'];need(q.parent==path.parent and not q.is_symlink(),
                                          'contained whole prerequisite capture')
            actual=fact(pin(q));need(actual==old['artifacts'][str(q)] and
                {k:actual[k] for k in ('bytes','sha256')}=={k:value[k] for k in ('bytes','sha256')},
                'capture identity joins actual process and retained artifact')
    need(names and len(names)==len(set(names)),'nonempty unique prerequisite command schedule')
    return old


def _record_archive_configuration(current, receipt_sha256, actual, expected):
    # cargo_configuration returns location labels/status/digests, never paths
    # or configuration contents. Retain this one read even when equality fails.
    current.setdefault('archive_configuration_observations', []).append(
        dict(receipt_sha256=receipt_sha256, actual=actual, expected=expected))
    return actual


def check_archive(path, sha256, current, pin):
    from checks import admission
    from page_selected_generic_build import package_check, PROFILES
    old=whole_receipt(path,sha256,current,pin,'call-decoder-archive-v1','passed')
    build=old['build'];environment=dict(build['environment'])
    need(old['bounds']==PROFILES and old['archive_builds']==1 and old['subjects']==0 and
         old['owner_credit'] is False,'separate original bounded Build preparation only')
    archive=pin(build['artifacts']['decoder.a']['path']);a=fact(archive)
    need(archive.name=='decoder.a' and old['archive']==a and
         all(a[k]==build['artifacts']['decoder.a'][k] for k in ('bytes','sha256')) and
         int(a['mode'],8)==build['artifacts']['decoder.a']['mode'],
         'whole actual retained archive in place, no recopy')
    need(build['status']=='passed' and build['started'] is True and build['command_completed'] is True and
         build['configuration_unchanged'] is True and build['final_errors']==[] and
         build['registry_before']==build['registry_after'] and build['decoder_features']==FEATURES and
         environment['LI2_DECODER_FEATURES']=='linked-epoch,mov-guard' and
         environment['CARGO_TARGET_DIR']==str(ROOT/'target') and
         _record_archive_configuration(current,sha256,admission.cargo_configuration(environment),
                                       build['cargo_configuration'])==build['cargo_configuration'],
         'actual source/features/configuration decoder build')
    need([package_check(x) for x in build['registry_before']]==build['registry_before'],
         'whole locked registry package contents and archives')
    need(set(build['dep_info'])==set(DECODER) and len(build['dep_info'])==10,
         'all ten and only actual compiled decoder sources')
    for name,wanted in build['dep_info'].items():
        q=pin(ROOT/name);actual=fact(q)
        need({k:actual[k] for k in ('bytes','sha256')}==wanted and actual==old['inputs'][str(q)],
             'same complete source bytes compiled into the archive')
    for name in ('Cargo.toml','Cargo.lock'):
        q=pin(ROOT/'tools/page-entry/selected/decoder'/name)
        need(fact(q)==old['inputs'][str(q)],'actual manifest and lock unchanged')
    for name,wanted in build['tools'].items():
        q=pin(wanted['path']);need(all(fact(q)[k]==wanted[k] for k in ('bytes','sha256')) and
             fact(q)==old['inputs'][str(q)],'whole actual retained build tool')
    rows=[x for x in old['commands'] if x['name']=='archive-text-exports']
    need(len(rows)==1 and rows[0]['captures']['stderr']['bytes']==0,'whole actual archive exports')
    exports=(Path(path).resolve().parent/rows[0]['captures']['stdout']['file']).read_bytes()
    need(exports and old['exports']==dict(bytes=len(exports),sha256=hashlib.sha256(exports).hexdigest()),
         'exact complete retained archive export bytes')
    return archive,build,environment,exports,old


def check_components(path, sha256, current, pin, archive):
    from page_selected import ENV
    old=whole_receipt(path,sha256,current,pin,'experimental-call-components-v1','components_passed')
    need(old['bounds']=={'build':[30,512<<20,16<<20,60],'component':[5,512<<20,16<<20,15]} and
         old['archive']==fact(archive) and old['archive_builds']==0 and
         old['archive_source_provenance_verified'] is False and
         old['generated_execution']==old['native_execution']==0 and
         all(old[k] is False for k in ('owner_credit','qualification_credit','performance_credit')),
         'complete finite components; archive provenance remains separate')
    need(list(old['components'])==list(COMPONENT_STDOUT),'both original model populations in fixed order')
    for name,expected in COMPONENT_STDOUT.items():
        model=old['components'][name]
        result={k.decode():int(v) for k,v in re.findall(rb'(\w+)=(\d+)',expected)}
        need(model['status']=='passed' and model['diagnostic_only_additions']==['-save-temps=obj','-Wl,--trace'] and
             model['result']==result,'exact complete emitter/planner counts')
        rows=[x for x in old['commands'] if x['name']==name+'-component']
        need(len(rows)==1 and rows[0]['bounds']==old['bounds']['component'] and
             rows[0]['captures']['stderr']['bytes']==0 and
             (Path(path).resolve().parent/rows[0]['captures']['stdout']['file']).read_bytes()==expected,
             'whole actual component stdout and completion')
    need(all(row['environment']==ENV for row in old['commands']),'same original component environment')
    return old
