"""Reproducible TRUE-input adoption gate; no native qualification/timing credit."""
import json
import os
from pathlib import Path
from page_selected import need
from maps_view import fact,digest
import linked_true_regression as producer

ROOT=Path(__file__).resolve().parents[2]
PROFILE='linked-true-before-first-rseq-v1'
ADOPTED={'evaluation/inprocess/linked_epoch_performance_reports.py': {'bytes': 30226, 'sha256': '4c13da285f9fd260bd2d894f34ff449143337bb1de922ee1b38be8780de2e7dc'}, 'evaluation/inprocess/linked_true_repeat_reports.py': {'bytes': 13520, 'sha256': '5c0b3377d28f784c26473032c5ba141aa7269fca102e7e6633bb232b166fd81f'}, 'evaluation/inprocess/maps_view.py': {'bytes': 34640, 'sha256': '6df3b322e000451bf7fe00b27962be40f1c9ff2601629018c89670c431f03ac7'}, 'evaluation/inprocess/page_cost_reports.py': {'bytes': 17797, 'sha256': '3bcdfb8fcab5286cbe442226588e2dab4dcb2bd41c1a720424e494986216b9ee'}, 'evaluation/inprocess/scalar_reuse_performance_reports.py': {'bytes': 5644, 'sha256': '47454bbce3b67746f7ccff9668422aa31adbd728263af69d2fac9102314e5a4d'}, 'evaluation/inprocess/unrolled_hash_performance.py': {'bytes': 29912, 'sha256': 'b39f675c12733f6cf8480e11f019720f7f194204a5777f706ac0819438e5454f'}, 'evaluation/inprocess/unrolled_hash_reports.py': {'bytes': 6351, 'sha256': 'b90f5f7686ca853f29c35af54717bacfc4ef1e5341ccba4554314ba3b3c690f0'}}


def prerequisite(path,pin,binary):
    path=pin(path)
    need(path.name=='RESULT.json'and path.is_relative_to(ROOT/'target'), 'private reproducible regression result')
    root=path.parent
    actual=json.loads(path.read_bytes())
    need(actual['profile']=='linked-true-reproducible-regression-v1'and
         actual['status']=='passed'and actual['cleanup_complete']is True and
         actual['inputs_unchanged']is True and actual['errors']==actual['final_errors']==[] and
         all(actual[k]is False for k in('current_revision_credit','native_qualification_credit','performance_credit'))and
         digest([actual['native_input_subjects_planned'],actual['native_input_subjects']])==digest([2,2]),
         'closed two-input/three-reader regression with no qualification/performance credit')
    script=pin(ROOT/producer.SCRIPT)
    need(actual['producer']==fact(script), 'actual tracked producer is the current exact source')
    source_path=binary(root/'SOURCES.json')
    need(fact(source_path)==actual['sources'], 'actual closed source manifest')
    sources=json.loads(source_path.read_bytes())
    need(sources['producer']==actual['producer']and sources['producer_revision']==actual['producer_revision']and
         type(sources['cpu'])is int and sources['cpu']==actual['cpu']and
         sources['shared_cargo_target']==str(ROOT/'target')and
         set(sources['snapshots'])=={'unused','positive','candidate'},
         'exact producer revision, reserved CPU and one shared Cargo target')
    for name,revision in (('unused',producer.OLD),('positive',producer.POSITIVE),
                          ('candidate',actual['producer_revision'])):
        spec=sources['snapshots'][name]
        need(spec['revision']==revision,'fixed runtime/reader source role')
        producer.source_check(root/'snapshots'/name,spec)
        for rel,row in spec['files'].items():
            f=binary(root/'snapshots'/name/rel)
            need(digest(fact(f))==digest({k:row[k]for k in('bytes','sha256')}),'actual full source snapshot')
    need(tuple(c['name']for c in actual['generators'])==('unused','positive'), 'two sequential actual input generators')
    generated={}
    for kind,generator in zip(('unused','positive'),actual['generators'],strict=True):
        need(type(generator['exit'])is int and generator['exit']==0 and generator['reaped']is True and
             generator['argv']==[generator['argv'][0],'-I','-S','-B',str(script),'--generate',kind,
                '--output',str(root),'--sources-sha256',actual['sources']['sha256']],
             'exact isolated producer invocation')
        pin(generator['argv'][0])
        for stream in('stdout','stderr'):
            p=binary(root/(kind+'-producer.'+stream))
            need(fact(p)==generator['captures'][stream], 'actual input-producer capture')
            if stream=='stderr':need(p.read_bytes()==b'', 'input producer completed without Python diagnostics')
        private=root/kind;input_path=binary(private/'input.json')
        need(fact(input_path)==actual['inputs'][kind], 'actual generator closure receipt')
        need(json.loads((root/(kind+'-producer.stdout')).read_bytes())==dict(kind=kind,status='generated_input',input=fact(input_path)),
             'actual producer result names its complete input closure')
        generated[kind]=r=json.loads(input_path.read_bytes())
        need(type(r['cpu'])is int and r['cpu']==sources['cpu'], 'one CPU across both generated inputs')
        producer.input_data(root,kind)
        build=r['build'];release=r['release_build']
        need(build['status']=='passed'and build['started']is True and build['command_completed']is True and
             build['final_errors']==[]and build['configuration_unchanged']is True and
             digest(build['registry_before'])==digest(build['registry_after'])and release['status']=='passed',
             'fresh completed source-owned builds and unchanged registry/configuration closure')
        archive=build['artifacts']['decoder.a']
        need(fact(binary(archive['path']))=={k:archive[k]for k in('bytes','sha256')}and
             release['archive']=={k:archive[k]for k in('bytes','sha256')}, 'actual release owns the fresh retained decoder archive')
        for name,want in build['dep_info'].items():
            need(want=={k:sources['snapshots'][kind]['files'][name][k]for k in('bytes','sha256')},
                 'archive source identities match the exact historical snapshot')
        expected_bounds=dict(build=[120,2<<30,128<<20,150],metadata=[30,512<<20,64<<20,60],
                             inspect=[10,256<<20,4<<20,20],release_build=producer.PROGRAM,
                             program=producer.PROGRAM,finite=[5,512<<20,16<<20,15])
        need(digest(r['bounds'])==digest(expected_bounds), 'every original build/program/oracle bound retained')
        need(r['commands']and len({c['name']for c in r['commands']})==len(r['commands']), 'unique actual commands')
        for command in r['commands']:
            need(command['profile']in expected_bounds and
                 digest([command['bounds'],command['exit'],command['expected_exit']])==
                    digest([expected_bounds[command['profile']],0,0])and
                 command['reaped']is True and command['timed_out']is False and command['error']is None and
                 command['cleanup_errors']==[]and all(d['closed']is True for d in command['descriptors']),
                 'all generated-input commands completed under original caps with full cleanup')
            command_path=binary(private/(command['name']+'.json'))
            need(digest(json.loads(command_path.read_bytes()))==digest(command), 'complete actual command row')
            for stream,capture in command['captures'].items():
                need(Path(capture['file']).name==capture['file'],'flat command capture name')
                p=binary(private/capture['file'])
                need(fact(p)=={k:capture[k]for k in('bytes','sha256')}, 'complete actual command capture')
        for name,want in r['inputs'].items():need(fact(pin(name))==want,'all source/tool/input bytes unchanged')
        for name,want in r['artifacts'].items():
            p=binary(name)
            need(digest(dict(fact(p),mode=p.stat().st_mode&0o777))==digest(want),'all retained artifact bytes/modes unchanged')
        for name,resolved in r['aliases'].items():need(str(Path(name).resolve(strict=True))==resolved,'all lexical source/tool aliases unchanged')
        for name,present in r['configuration_presence'].items():need(os.path.lexists(name)is present,'loader configuration presence unchanged')
        for name,value in r['namespace_aliases'].items():need(Path(name).is_symlink()and os.readlink(name)==value,'actual sealed namespace aliases unchanged')
        for name,want in r['executed_modules'].items():
            need(want=={k:sources['snapshots'][kind]['files'][name][k]for k in('bytes','sha256')},
                 'actual historical generator imported only its authenticated source')
    need(digest(generated['unused']['hardware'])==digest(generated['positive']['hardware']),
         'same actual hardware for both input-generation domains')
    commands=actual['commands'];names=('historical-unused','candidate-unused','candidate-positive')
    need(tuple(c['name']for c in commands)==names and
         digest(actual['bounds'])==digest(dict(address_space=256<<20,core=0,cpu_seconds=3,file_size=1<<20,wall_seconds=10)),
         'three original bounded reader children')
    outputs=[]
    for name,c in zip(names,commands):
        need(type(c['exit'])is int and c['exit']==0 and c['reaped']is True and
             c['timed_out']is False and c['cleanup_errors']==[]and
             c['argv']==[c['argv'][0],'-I','-S','-B',str(script),'--reader',name,
                '--output',str(root),'--sources-sha256',actual['sources']['sha256']],
             'actual isolated reader child completed cleanly')
        pin(c['argv'][0])
        captured={}
        for stream in('stdout','stderr'):
            file=binary(path.parent/(name+'.'+stream))
            need(digest(fact(file))==digest(c['captures'][stream]),'exact retained regression '+stream)
            captured[stream]=file.read_bytes()
        need(captured['stderr']==b'','empty regression child stderr')
        output=json.loads(captured['stdout'])
        need(output['name']==name and output['status']=='passed'and
             all(output[k]is False for k in('current_revision_credit','native_qualification_credit','performance_credit'))and
             type(output['native_subjects'])is int and output['native_subjects']==0,
             'actual reader-only result without qualification credit')
        kind='positive'if name=='candidate-positive'else'unused'
        native=next(c for c in generated[kind]['commands']if c['name']=='true')
        need(all(output[stream+'_sha256']==native['captures'][stream]['sha256']for stream in('stdout','stderr')),
             'reader accepted these actual fresh TRUE captures')
        which='unused'if name=='historical-unused'else'candidate'
        for module,want in output['executed_modules'].items():
            need(want=={k:sources['snapshots'][which]['files'][module][k]for k in('bytes','sha256')},
                 'reader executed exact snapshot source')
            if which=='candidate':need(fact(pin(ROOT/module))==want,'current transitive reader source still exact')
        outputs.append(output)
    old,new,positive=outputs
    need(old['default_keywords_omitted']is new['default_keywords_omitted']is True and
         all(digest(old[k])==digest(new[k])for k in('accepted','summary','refusals','unused_refusals','terminal_refusals'))and
         len(old['refusals'])==len(set(old['refusals']))==218 and
         len(old['unused_refusals'])==len(set(old['unused_refusals']))==180 and
         len(old['terminal_refusals'])==len(set(old['terminal_refusals']))==216,
         'genuine old unused default rows, summary, all218 names and unused180 remain exact')
    need(positive['profile']==PROFILE and len(positive['refusals'])==len(set(positive['refusals']))==445 and
         len(positive['positive_refusals'])==len(set(positive['positive_refusals']))==55 and
         positive['default_refusal']=='entire unused REP report is canonical empty, with only initialization flags',
         'distinct positive445/55 and unchanged default rejection; historical failed results remain separate')
    for name,want in ADOPTED.items():
        need(digest(fact(pin(ROOT/name)))==digest(want),'exact reviewed positive REP dependency '+name)
        if name!='evaluation/inprocess/unrolled_hash_performance.py':
            need(digest(positive['executed_modules'][name])==digest(want),
                 'the retained regression executed this exact candidate reader '+name)
    return dict(**fact(path),status='passed',producer=fact(script),
        scope='fresh inputs from fixed historical runtimes; reader adoption regression only',
        old_default=218,old_unused=180,old_terminal=216,positive=445,positive_repeat=55,native_input_subjects=2,
        current_revision_credit=False,native_qualification_credit=False,performance_credit=False)
