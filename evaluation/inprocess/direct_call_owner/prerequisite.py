"""Authenticate the completed E8 experiment without replaying any reader or subject."""
import hashlib
from pathlib import Path
import re
import shlex
import struct
from call_owner import custody
from ret_owner import prerequisites as old

need = old.need
ROOT = custody.ROOT


def dynamic(path):
    """Read actual ELF strings for dependency-closure joins; no loading."""
    b = Path(path).read_bytes()
    need(b[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', b, 18)[0] == 62, 'actual ELF64')
    off = struct.unpack_from('<Q', b, 32)[0]
    size, count = struct.unpack_from('<HH', b, 54)
    need(size == 56 and 0 < count <= 64 and off+size*count <= len(b), 'bounded ELF headers')
    rows = [struct.unpack_from('<IIQQQQQQ', b, off+i*size) for i in range(count)]
    tables = [p for p in rows if p[0] == 2]
    need(len(tables) == 1, 'one actual dynamic table')
    p = tables[0]
    need(p[5] % 16 == 0 and p[2]+p[5] <= len(b), 'whole dynamic table')
    tags = []
    for offset in range(p[2], p[2]+p[5], 16):
        tag, value = struct.unpack_from('<QQ', b, offset)
        if not tag:
            break
        tags.append((tag, value))
    else:
        raise ValueError('terminated dynamic table')
    def one(tag):
        values = [v for t, v in tags if t == tag]
        need(len(values) == 1, 'one string-table field')
        return values[0]
    address, length = one(5), one(10)
    segments = [p for p in rows if p[0] == 1 and p[3] <= address and address+length <= p[3]+p[5]]
    need(len(segments) == 1, 'whole LOAD-owned dynamic strings')
    p = segments[0]
    offset = p[2]+address-p[3]
    strings = b[offset:offset+length]
    need(len(strings) == length, 'whole dynamic strings')
    def name(value):
        need(value < len(strings) and b'\0' in strings[value:], 'bounded dynamic name')
        return strings[value:strings.index(b'\0', value)].decode('ascii')
    needed = [name(v) for t, v in tags if t == 1]
    sonames = [name(v) for t, v in tags if t == 14]
    need(len(sonames) <= 1 and len(set(needed)) == len(needed), 'unambiguous dynamic dependencies')
    need(not any(t in (15, 29, 0x7FFFFFFD, 0x7FFFFFFF, 0x6FFFFEFC, 0x6FFFFEFB) for t, v in tags),
         'no search/filter/audit overrides')
    return {'needed': needed, 'soname': sonames[0] if sonames else None}


def native_compact(observed):
    need(observed['status']=='finite_native_comparisons_passed' and
         observed['native_pairs']==24 and observed['native_lanes']==48 and
         all(observed[k] is False for k in ('old217_cases_replaced','old136_cases_replaced',
             'owner_credit','production_admission_credit','qualification_credit','performance_credit')),
         'complete additive E8 native comparison with all original gates separate')
    pairs=observed['pairs']
    need(len(pairs)==24 and [p['id'] for p in pairs]==list(range(24)) and
         [sum(p['group']==g for p in pairs) for g in range(12)]==[2]*12 and
         sum(p['actual_generated_trace_boundaries'] for p in pairs)==140 and
         sum(p['pre_push_full_frame_sha256'] is not None for p in pairs)==4 and
         sum(p['return_page_observed_unmapped'] for p in pairs)==4,
         'all exact low/high signed/fault/full-frame/page-end observations')
    return dict(status=observed['status'],native_pairs=24,native_lanes=48,
        groups=[dict(group=g,pairs=2) for g in range(12)],full_frames=100,
        pre_push_full_frames=4,actual_generated_trace_boundaries=140,
        committed_once=sum(p['committed_once'] for p in pairs),
        no_effect_misses=sum(p['no_effect_miss'] for p in pairs),
        injected_stack_faults=sum(p['injected_stack_fault'] for p in pairs),
        return_page_observed_unmapped=4,raw_sources=observed['sources'],
        old217_cases_replaced=False,old136_cases_replaced=False,
        owner_credit=False,production_admission_credit=False,
        qualification_credit=False,performance_credit=False)


def check(path, sha256, current, pin, archive, build, manifest):
    bound=manifest['direct_native_prerequisite']
    source=pin(ROOT/bound['source']); m=custody.load(source)
    need(custody.fact(source)==bound['source_fact'],
         'whole source-bound installed direct-E8 collector')
    path,p=old.closed(path,sha256,current,pin,'public-direct-call-components-native-v1','passed',
                      m['bounds'],m['commands'])
    need(len(p['commands'])==132 and
         p['inputs'][str(source)]==custody.fact(source) and
         p['emitted_execution']==24 and p['owner_credit']==p['archive_builds']==0,
         'explicit complete15-component/two-chunk receipt at current source; no owner inference')
    for name,wanted in m['inputs'].items():
        q=pin(ROOT/name)
        need(custody.fact(q)==wanted==p['inputs'][str(q)],'same whole executed E8 source input')
    for name,wanted in m['artifacts'].items():
        q=pin(source.parent/name)
        need(custody.fact(q)==wanted==p['inputs'][str(q)],'same whole executed E8 collector artifact')
    selected=ROOT/'tools/page-entry/selected'
    links={}
    for case in m['components']:
        aliases={}
        for original,alias in case['source_aliases'].items():
            a=selected/original;declared=selected/alias
            need(a.parent==declared.parent and (original,alias) in
                 (('tests/call_dispatch/model.c','tests/call_dispatch/call_model.c'),
                  ('tests/ret_dispatch/model.c','tests/ret_dispatch/ret_model.c')),
                 'only exact predeclared model aliases')
            b=path.parent/'components'/case['name']/'source-aliases'/a.parent.name/declared.name
            aliases[str(a)]=str(b);links[str(b)]=str(pin(a));links[str(b.with_name('model.h'))]=str(pin(a.with_name('model.h')))
        need(p['components'][case['name']]['source_aliases']==aliases,'exact actual component model/header aliases')
    links[str(path.parent/'probe_assembly.S')]=str(pin(selected/'tests/direct_call_native/probe.S'))
    need(p['context_links']==links,'all and only original component and native diagnostic aliases')
    need(p['ret_owner_prerequisite']==current['ret_owner_prerequisite'] and
         p['return_heads_prerequisite']==current['return_heads_prerequisite'] and
         p['prerequisites']==dict(original_nine=current['ret_owner_prerequisite'],
                                 return_heads=current['return_heads_prerequisite']),
         'identical complete original-nine and return-head gates, rechecked by this collector')
    reuse=p['archive_reuse']
    need(reuse['archive']==custody.fact(archive) and reuse['release_build']==build and
         reuse['receipt']==current['archive_reuse']['receipt'] and reuse['fresh_build'] is False and
         reuse['source_tools_features_verified'] is True and reuse['qualification_credit'] is False,
         'same retained archive, complete actual decoder/tool/configuration record and no rebuild')
    finite={'emitted-inspection','native-0','native-1','read-all-chunks'}
    for c in p['commands']:
        profile=('finite' if c['name'].endswith('-component') else 'release_build') if c['name'].startswith('components-') else ('native' if c['name'] in finite else 'build')
        need(c['profile']==profile and c['bounds']==m['bounds'][profile],
             'each original exact build/native/component bound, not a tolerated alternative')
    def output(name,stream='stdout'):
        return old.captured(path,p,name,stream)
    def includes(name,units,required,reported,prefix):
        raw=output(name).decode().replace('\\\n',' ');rules=raw.splitlines()
        need(not output(name,'stderr') and len(rules)==len(units) and
             all(x.startswith(prefix+': ') for x in rules),'complete actual compiler-M rules')
        actual={str(pin(x)) for rule in rules for x in shlex.split(rule.split(':',1)[1])}
        need(actual==set(reported) and {str(pin(x)) for x in (*units,*required)}<=actual,
             'exact actual translation-unit/header closure, no omitted required header')
    component_results={}
    need(set(p['components'])=={x['name'] for x in m['components']} and len(m['components'])==15,
         'all original off/on/direct cohorts and additive E8 component')
    for case in m['components']:
        name=case['name'];state=p['components'][name];label='components-'+name
        c=old.row(p,label+'-component');binary=pin(c['argv'][0])
        result={k:int(v) for line in case['stdout'].splitlines() for k,v in
                (word.split('=') for word in line.split()[1:])}
        need(state['status']=='passed' and state['return_heads']==case['return_heads'] and
             state['direct_call']==case['direct_call'] and state['recipe']==case['recipe_fact'] and
             state['result']==result and output(label+'-component')==case['stdout'].encode() and
             output(label+'-component','stderr')==b'' and custody.fact(binary)==state['binary'] and
             state['diagnostic_only_additions']==['-save-temps=obj','-Wl,--trace'],
             'complete unchanged component population, mode, strict stdout and actual binary')
        argv=state['actual_argv'];units=[x for x in argv if x.endswith(('.c','.S'))]
        need([x for x in argv if x.endswith('.a')]==[str(archive)] and
             argv.count('-DLI2_PERSISTENT_CALL_RETURN_HEADS=1')==int(case['return_heads']) and
             argv.count('-DLI2_PERSISTENT_DIRECT_CALL=1')==int(case['direct_call']) and '-Werror' in argv and
             old.row(p,label+'-build')['argv']==argv[:-2]+state['diagnostic_only_additions']+argv[-2:],
             'exact recorded effective compiler invocation, strict mode and archive')
        includes(label+'-headers',units,[selected/x for x in case['headers']],state['headers'],'ret_component')
        need(not output(label+'-build','stderr') and
             {str(pin(x)) for x in output(label+'-build').decode().splitlines()}==set(state['link_inputs']),
             'all actual linker inputs and generated objects retained')
        for obj in state['link_inputs']:pin(obj)
        for obj,expected in [(str(binary),state['elf']),*state['runtime_objects'].items()]:
            need(dynamic(pin(obj))=={k:expected[k] for k in ('needed','soname')},
                 'actual full ELF dependency tags unchanged')
        component_results[name]=result
    binary=pin(path.parent/'direct-call-native');recipe=p['recipe'];argv=recipe['argv']
    need(custody.fact(binary)==p['binary'] and recipe['file']==custody.fact(pin(selected/'tests/direct_call_native/build.sh')) and
         recipe['diagnostic_only_additions']==['-save-temps=obj','-Wl,--trace'] and
         old.row(p,'build')['argv']==argv[:-2]+recipe['diagnostic_only_additions']+argv[-2:] and
         [x for x in argv if x.endswith('.a')]==[str(archive)] and '-Werror' in argv and '-no-pie' in argv,
         'exact strict native compiler recipe, actual executable and retained archive')
    units=[x for x in argv if x.endswith(('.c','.S'))];headers=set()
    need(len(units)==4,'all four actual native translation units')
    for i,unit in enumerate(units):
        raw=output('headers-'+str(i)).decode().replace('\\\n',' ');rules=raw.splitlines()
        need(not output('headers-'+str(i),'stderr') and len(rules)==1 and rules[0].startswith('probe: '),
             'complete actual native compiler-M rule')
        actual={str(pin(x)) for x in shlex.split(rules[0].split(':',1)[1])}
        need(str(pin(unit)) in actual,'actual native TU in its rule');headers|=actual
    need(headers==set(p['headers']) and {str(pin(selected/x)) for x in
         ('linked_call_dispatch.h','linked_jmp_domain.h','decoder.h')}<=headers,'complete native header closure')
    need(not output('build','stderr') and
         {str(pin(x)) for x in output('build').decode().splitlines()}==set(p['linked_inputs']) and
         str(archive) in p['linked_inputs'],'whole actual native linker closure')
    providers=output('native-providers');names=[m[1] for line in providers.decode().splitlines()
        if (m:=re.fullmatch(r'[0-9a-fA-F]+ T (\S+)',line))]
    required=['li2_cd_describe','li2_cd_direct_target','li2_cd_emit','li2_cd_validate','li2_cd_recover']
    need(not output('native-providers','stderr') and all(names.count(x)==1 for x in required) and
         p['native_providers']==dict(required=required,bytes=len(providers),sha256=hashlib.sha256(providers).hexdigest()),
         'all exact typed native providers and whole symbol census')
    inspected=custody.load(path.parent/old.row(p,'emitted-inspection')['captures']['stdout']['file'])
    need(not output('emitted-inspection','stderr') and inspected==p['emitted_inspection'] and
         inspected['elf_sha256']==p['binary']['sha256'] and inspected['status']=='source_bytes_inspected' and
         inspected['native_execution'] is False and inspected['qualification_credit'] is False,
         'actual bootstrap/epilogue byte inspection precedes the two subjects')
    for obj,expected in p['runtime_objects'].items():
        need(dynamic(pin(obj))==expected,'actual native complete runtime ELF tags')
    sonames=[x['soname'] for x in p['runtime_objects'].values() if x['soname'] is not None]
    need(len(sonames)==len(set(sonames)) and str(pin(inspected['interpreter'])) in p['runtime_objects'] and
         all(n in sonames for x in p['runtime_objects'].values() for n in x['needed']),
         'closed original native interpreter and DT_NEEDED roster')
    observed=custody.load(path.parent/old.row(p,'read-all-chunks')['captures']['stdout']['file'])
    need(not output('read-all-chunks','stderr') and observed['cpu']==current['cpu'] and len(observed['sources'])==2,
         'complete independent native reader output and same CPU')
    chunks=[]
    for i in range(2):
        c=old.row(p,'native-'+str(i));raw=output(c['name']);h=struct.unpack_from('<64Q',raw)
        need(not output(c['name'],'stderr') and len(raw)==8709312 and
             c['argv']==[str(binary),str(i)] and
             h[:15]==(0x314e454432494c,1,512,362864,67072,968,128,65536,16384,4096,24,i,12*i,12,24) and
             h[15:17]==(c['pid'],current['cpu']) and
             h[28:30]==(inspected['reload_address'],inspected['scratch_end_address']) and
             struct.unpack_from('<8Q',raw,len(raw)-64)==(0x3145454432494c,1,24,len(raw),0,0,0,0),
             'whole native raw extent/footer and actual PID/CPU/emitted bootstrap join')
        need(observed['sources'][i]==dict(chunk=i,pid=c['pid'],**old.value(c['captures']['stdout'])),
             'reader input joins the whole actual native capture')
        chunks.append(dict(chunk=i,pid=c['pid'],cpu=current['cpu'],duration_ns=c['duration_ns'],capture=c['captures']['stdout']))
        for local in range(12):
            pair=observed['pairs'][12*i+local]
            for lane,key in ((0,'original_record_sha256'),(1,'generated_record_sha256')):
                at=512+(2*local+lane)*362864;record=raw[at:at+362864]
                need(struct.unpack_from('<4Q',record)==(0x3152454432494c,362864,12*i+local,lane) and
                     hashlib.sha256(record).hexdigest()==pair[key],'all48 complete raw lanes join independent reader rows')
    need(chunks==p['native_chunks'],'all exact original native command records')
    native=native_compact(observed)
    expected=dict(components=component_results,component_cohorts=15,native=native,owner_subjects=0,
        original_nine_subjects_replayed=0,return_heads_subjects_replayed=0,qualification_credit=False,performance_credit=False)
    need(p['result']==expected,'whole retained result; component/native outcomes grant no E8 owner credit')
    return dict(receipt=old.value(custody.fact(path)),source=old.value(custody.fact(source)),
        component_cohorts=15,native_pairs=24,native_lanes=48,full_frames=100,trace_rows=140,
        executions_here=0,controls_replayed=0,owner_credit=False,qualification_credit=False,performance_credit=False)
