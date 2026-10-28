"""Reapply the unchanged three prerequisite readers to same-revision raw evidence."""
import hashlib,importlib.util,json,os,shlex,shutil
from pathlib import Path
from page_selected import fact,need,interpreter
import page_selected_oneshot_failure as failure
import page_selected_rseq_application as rseq
from page_selected_generic_build import ARTIFACTS as BUILD_ARTIFACTS

H=lambda b:hashlib.sha256(b).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def same(a,b,label):need(canonical(a)==canonical(b),label)


def rseq_build_custody(root,path,old,commands,pin,binary,capture):
    """Independent source-derived Build identities, not receipt-table self joins."""
    built=old['build'];tools=built['tools'];environment=built['environment']
    tool_names={'cc','sh','nm','readelf','git','cp','mkdir','python','rustup','cargo','rustc','cc1','collect2','as','ld'}
    need(set(tools)==tool_names and set(built['artifacts'])==set(BUILD_ARTIFACTS)|{'generic-observe'},
         'complete source-derived Build tool and retained artifact keys')
    def input_path(lexical,want):
        p=pin(lexical,want);name=str(p);lexical=str(Path(lexical).absolute())
        need(old['inputs'].get(name)==fact(p) and old['input_aliases'].get(lexical)==name,
             'mandatory actual tool/input/lexical alias custody')
        return name
    for name,row in tools.items():
        p=pin(row['path'],row)
        need(str(p)==row['path'] and old['inputs'].get(str(p))==fact(p) and
             any(v==str(p)for v in old['input_aliases'].values()),'each actual mandatory Build tool identity '+name)
    for name in ('cc','sh','nm','readelf','git','cp','mkdir'):
        value=shutil.which(name,path=environment['PATH']);need(value is not None,'actual Build PATH tool')
        need(input_path(value,tools[name])==tools[name]['path'],'actual source-selected PATH tool '+name)
    for name in ('cargo','rustc','cc1','collect2','as','ld'):
        row=commands['resolve-'+name];rust=name in ('cargo','rustc')
        expected=[tools['rustup']['path'],'which',name]if rust else [tools['cc']['path'],'-print-prog-name='+name]
        need(row['argv']==expected and not capture(path,row,'stderr'),'actual tool resolution invocation '+name)
        value=capture(path,row,'stdout').decode().strip();need(value and (not rust or Path(value).is_absolute()),'actual resolved tool spelling')
        lexical=value if Path(value).is_absolute()else shutil.which(value,path=environment['PATH'])
        need(lexical is not None and input_path(lexical,tools[name])==tools[name]['path'],'actual resolved tool result '+name)
    for name in ('cc','cargo','rustc','python'):
        row=commands['version-'+name]
        need(row['argv']==[tools[name]['path'],'-vV'if name=='rustc'else'--version'] and
             not capture(path,row,'stderr') and capture(path,row,'stdout').decode().strip()==built['versions'][name],
             'actual Build version/tool join '+name)
    for variable,name in (('LI2_CC','cc'),('LI2_CARGO','cargo'),('LI2_PYTHON','python'),('RUSTC','rustc')):
        need(environment[variable]==tools[name]['path'],'actual build-selected compiler '+name)
    command_tools={'source-paths':'git','cargo-metadata':'cargo','selected-build':'sh','archive-text-exports':'nm',
        'bridge-undefined':'nm','bridge-elf':'readelf','generic-observer-link':'cc','rseq-headers':'cc',
        'rseq-link':'cc','rseq-undefined':'nm','rseq-elf':'readelf','rseq-fast-memset-symbols':'nm','generate-images':'python'}
    command_tools.update({kind+'-'+name:'python'for name in rseq.NAMES for kind in ('make','gated')})
    for label,name in command_tools.items():need(commands[label]['argv'][0]==tools[name]['path'],'actual command tool '+label)
    for label in ('selected-build','generic-observer-link','rseq-headers','rseq-link'):
        same(commands[label]['environment'],environment,'actual build compiler environment '+label)
    need(commands['selected-build']['argv']==[tools['sh']['path'],str(root/'tools/page-entry/selected/build.sh')],
         'unchanged actual Build entry command')
    for name,row in built['artifacts'].items():
        expected=path.parent/'artifacts'/name;p=binary(pin(expected,row));actual=fact(p)
        need(row['path']==str(expected) and p==expected and old['artifacts'].get(str(p))==actual and
             p.stat().st_mode&0o777==row['mode'],'mandatory actual retained Build artifact '+name)
    archive=path.parent/'artifacts/decoder.a';a=str(archive)
    need(commands['archive-text-exports']['argv']==[tools['nm']['path'],'-g','--defined-only',a] and
         commands['generic-observer-link']['argv'].count(a)==commands['rseq-link']['argv'].count(a)==1 and
         commands['generic-observer-link']['argv'][-2:]==['-o',str(path.parent/'generic-observe')] and
         old['rseq_build']['archive']==fact(archive),'actual inspected and linked retained archive bytes')
    for name,version in (('decoder-rustc.txt','rustc'),('decoder-cargo.txt','cargo'),('cc-version.txt','cc')):
        need((path.parent/'artifacts'/name).read_text().strip()==built['versions'][version],'actual retained build compiler version')
    row=commands['rseq-fast-memset-body'];lexical=row['argv'][0]
    input_path(lexical,old['rseq_build']['fast_memset_tool'])
    need(pin(shutil.which('objdump',path=environment['PATH']))==Path(lexical) and
         row['argv'][1:]==['-d','-w','-M','att','--disassemble=memset',old['rseq_build']['argv'][-1]],
         'actual reset inspection tool and product')


def replay(root,paths,current,pin,binary,receipt):
    root=Path(root);selected=root/'tools/page-entry/selected'
    state=receipt['companions']=dict(status='failed',receipts={},cohorts={})
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    check=load('registered_positive_check',selected/'tests/oneshot_integrated/check.py')
    reports=load('registered_positive_reports',selected/'tests/oneshot_integrated/reports.py')
    record=load('registered_failure_record',selected/'tests/oneshot_failure/record.py')
    outcomes=load('registered_failure_outcomes',selected/'tests/oneshot_failure/outcomes.py')
    def read(path):return failure.decode(pin(path).read_bytes())
    def capture(path,row,kind):
        c=row['captures'][kind]
        need(Path(c['file']).name==c['file'],'prerequisite capture filename only')
        return pin(path.parent/c['file'],c).read_bytes()
    def namespace(directory):
        ns=read(directory/'namespace.json');read(directory/'launch.json')
        for row in ns['objects']:
            need(row['seals']==15 and row['device']>0 and row['inode']>0,'retained actual sealed dependency')
            for name in row['names']:
                path=directory/name;target='/proc/self/fd/'+str(row['fd'])
                need(path.is_symlink() and os.readlink(path)==target,'actual prerequisite namespace alias')
                receipt.setdefault('companion_namespace_aliases',{})[str(path)]=target
    def closed(label,path,profile,status,names,bounds):
        path=pin(path);old=read(path)
        need(old['profile']==profile and old['status']==status and old['expected_revision']==current['revision'] and
             old['source']==old['source_after']==current and old['source_unchanged'] is True and
             old['error'] is None and not old['final_errors'],'same-revision successful closed prerequisite '+label)
        same(old['bounds'],bounds,'unchanged prerequisite bounds '+label)
        if label=='rseq':
            inputs,aliases,artifacts=old['inputs'],old['input_aliases'],old['artifacts']
        else:
            for kind in ('inputs','aliases','artifacts'):same(old[kind+'_before'],old[kind+'_after'],'closed '+label+' '+kind)
            inputs,aliases,artifacts=(old[k+'_before']for k in ('inputs','aliases','artifacts'))
        for p,v in inputs.items():pin(p,v)
        for p,v in aliases.items():need(str(pin(p,inputs[v]))==v,'unchanged prerequisite lexical alias')
        for p,v in artifacts.items():
            q=binary(pin(p,v))
            if 'mode'in v:need(q.stat().st_mode&0o777==v['mode'],'unchanged prerequisite artifact mode')
        need([c['name']for c in old['commands']]==names,'complete ordered prerequisite commands '+label)
        for row in old['commands']:
            need(row['bounds']==bounds[row['profile']] and
                 row['capture_limit']==(16<<20 if label=='negative'else 65536 if row['profile']=='native'else 4<<20) and type(row['exit'])is int and
                 (row['expected_exit'] is None or row['exit']==row['expected_exit']) and
                 row['reaped']is True and row['timed_out']is False and not row['error'] and
                 not row['cleanup_errors'] and all(d['closed']is True for d in row['descriptors']) and
                 type(row['pid'])is int and row['pid']>0 and {'stdout','stderr'}<=row['captures'].keys(),
                 'actual prerequisite outcome, bounds and supervision '+row['name'])
            for kind in row['captures']:capture(path,row,kind)
            same(read(path.parent/(row['name']+'.json')),row,'retained prerequisite command row')
        state['receipts'][label]=dict(path=str(path),**fact(path))
        return path,old,{c['name']:c for c in old['commands']}
    # The old positive authenticator already requires all34 commands, actual
    # compiler-M/archive joins, complete source custody and both completed lanes.
    positive=pin(paths['positive']);old=failure.positive_receipt(positive,current,pin,binary)
    native=pin(positive.parent/'native.stdout',old['cases'][0]['stdout']).read_bytes()
    gated=pin(positive.parent/'gated.stdout',old['cases'][1]['stdout']).read_bytes()
    parsed=reports.reports(pin(positive.parent/'gated.stderr',old['cases'][1]['stderr']).read_bytes())
    reports.completed(parsed,old['cases'][1]['pid'])
    same(parsed,old['reports'],'unchanged six-owner full completion')
    same(check.compare_outputs(native,gated),old['outputs'],'unchanged complete positive output')
    need(not pin(positive.parent/'native.stderr',old['cases'][0]['stderr']).read_bytes(),'positive native stderr empty')
    state['receipts']['positive']=dict(path=str(positive),**fact(positive))
    for p,target in old['namespace_aliases'].items():
        need(Path(p).is_symlink() and os.readlink(p)==target,'positive namespace alias')
        receipt.setdefault('companion_namespace_aliases',{})[p]=target
    state['cohorts']['positive']=dict(status='passed',actual_processes=2,published=6,restored=6,completed=5,
        terminal_phase=7,output_sha256=H(canonical(old['outputs']).encode()))
    names=['failure-headers-'+str(i)for i in range(17)]+['oneshot-archive-exports','failure-owner-compile',
        'failure-bridge-link','failure-symbols','failure-gdb-version','failure-dwarf','failure-memset',
        'failure-undefined','original-symbols','carrier-make']+['failure-'+str(i)for i in range(1,50)]
    p,neg,commands=closed('negative',paths['negative'],'page-selected-oneshot-failure-v1','passed',names,failure.BOUNDS)
    need(neg['selected_case'] is None and neg['positive_source']==current and neg['positive_command_count']==34 and
         {k:neg['positive_receipt'][k]for k in ('bytes','sha256')}==fact(positive) and
         Path(neg['positive_receipt']['path']).resolve(strict=True)==positive and
         [c['mode']for c in neg['cases']]==list(range(1,50)),'all49 and exact fresh positive prerequisite')
    need(all(neg['inputs_before'].get(p)==v for p,v in old['inputs_before'].items()),
         'negative derivative retains every positive source/tool/header binding')
    same(failure.decode(capture(p,commands['failure-dwarf'],'stdout')),neg['layout'],'actual retained ELF/DWARF layout')
    link=neg['oneshot_build'];need(link['status']=='passed' and link['translation_units']==17 and
        link['argv']==commands['failure-bridge-link']['argv'] and link['owner_argv']==commands['failure-owner-compile']['argv'] and
        link['archive']=={k:old['build']['artifacts']['decoder.a'][k]for k in ('bytes','sha256')},'same complete negative product link and archive')
    need(set(link['headers'])==set(map(str,range(17))),'all17 negative include closures')
    for i in range(17):
        header=link['headers'][str(i)];row=commands['failure-headers-'+str(i)]
        same(header['argv'],row['argv'],'actual negative include invocation')
        rules=capture(p,row,'stdout').decode().replace('\\\n',' ').splitlines();prefix='li2_'+str(i)+': '
        need(len(rules)==1 and rules[0].startswith(prefix),'complete negative compiler-M rule')
        got={str(pin(x)):fact(x)for x in shlex.split(rules[0][len(prefix):])}
        same(got,header['files'],'all actual negative conditional inputs')
    for case in neg['cases']:
        mode=case['mode'];row=commands['failure-'+str(mode)];expected=record.expected(mode)
        need(case['error'] is None and case['pid']==row['pid'] and case['exit']==row['exit']==expected['exit'] and
             case['status']=='qualified_'+expected['operation'],'actual negative lane outcome')
        same(case['captures'],row['captures'],'actual negative lane captures');same(case['expected'],expected,'unchanged negative expected outcome')
        got=record.read(capture(p,row,'record'),neg['layout'],mode,row['pid'],neg['layout']['types']['failure_record']['bytes'])
        same(got,case['record'],'complete actual negative record replay')
        parsed=reports.reports(capture(p,row,'stderr'));same(parsed,case['reports'],'actual negative reports')
        out=capture(p,row,'stdout')
        namespace(p.parent/('failure-'+str(mode)+'.namespace'))
        if mode==47:
            outcomes.refused_site_completed(parsed,row['pid']);same(check.compare_outputs(native,out),case['output'],'unchanged refused-site fallback output')
        else:
            need(not out,'no application output from terminal negative operation');outcomes.terminal(parsed,row['pid'],expected)
    state['cohorts']['negative']=dict(status='passed',actual_processes=49,qualified_failed_operations=48,
        qualified_refused_original_sites=1,mode48_source_protection_after=neg['cases'][47]['record']['source_protection_after'],
        case_rows_sha256=H(canonical(neg['cases']).encode()))
    names=['source-paths','resolve-cargo','resolve-rustc','resolve-cc1','resolve-collect2','resolve-as','resolve-ld',
        'version-cc','version-cargo','version-rustc','version-python','cargo-metadata','selected-build',
        'archive-text-exports','bridge-undefined','bridge-elf','generic-observer-link','rseq-headers','rseq-link',
        'rseq-undefined','rseq-elf','rseq-fast-memset-symbols','rseq-fast-memset-body','generate-images']
    names += [kind+'-'+name for name in rseq.NAMES for kind in ('native','make','gated')]
    p,rs,commands=closed('rseq',paths['rseq'],'page-selected-rseq-application-fast-memset-v1',
        'passed_finite_inactive_profile',names,rseq.BOUNDS)
    rseq_build_custody(root,p,rs,commands,pin,binary,capture)
    for name in capture(p,commands['source-paths'],'stdout').split(b'\0'):
        if name and not name.startswith(b'evaluation/inprocess/results/'):
            path=pin(root/os.fsdecode(name));need(rs['inputs'].get(str(path))==fact(path),'complete rseq tracked-source enumeration')
    need(rs['build']['status']==rs['rseq_build']['status']=='passed' and rs['build']['command_completed']is True and
         not rs['build']['final_errors'] and rs['rseq_build']['fast_memset']is True and
         rs['rseq_build']['argv']==commands['rseq-link']['argv'],'complete actual finite-rseq release build')
    linked=rs['rseq_build'];archive=rs['build']['artifacts']['decoder.a']
    need(linked['observed']is True and linked['archive']=={k:archive[k]for k in ('bytes','sha256')} and
         linked['argv'].count(archive['path'])==1 and fact(pin(linked['argv'][-1]))==linked['binary'],
         'same actual rseq archive and observed bridge')
    units=[x for x in linked['argv']if x.endswith(('.c','.S'))]
    need(len(units)==14 and commands['rseq-headers']['argv'][-14:]==units,'all14 actual observed translation units')
    rules=capture(p,commands['rseq-headers'],'stdout').decode().replace('\\\n',' ').splitlines()
    need(len(rules)==14 and all(x.startswith('rseq_application: ')for x in rules),'all14 actual conditional include rules')
    got={str(Path(x).absolute()):fact(pin(x))for row in rules for x in shlex.split(row.split(':',1)[1])}
    same(got,linked['headers'],'entire actual rseq compiler-M closure')
    catalog=read(p.parent/'images/images.json');schema=read(root/'evaluation/inprocess/page_selected_rseq_schema.json')
    need([x['actual']['name']for x in catalog]==rseq.NAMES and [x['name']for x in rs['cases']]==rseq.NAMES,
         'all17 unchanged rseq rows')
    for item,case in zip(catalog,rs['cases']):
        spec=item['actual'];name=spec['name'];native_spec=item['native_prefix'] or spec
        original=pin(spec['original']);ip=pin(spec['interpreter'])
        need(interpreter(original)==ip and fact(original)['sha256']==spec['original_sha256'] and
             fact(ip)['sha256']==spec['interpreter_sha256'],'actual literal rseq original/interpreter')
        nrow=commands['native-'+name];grow=commands['gated-'+name]
        nout=capture(p,nrow,'stdout')
        need(not capture(p,nrow,'stderr') and not capture(p,nrow,'record'),'genuine unobserved native rseq prefix')
        rseq.compare.output(native_spec,nout)
        result=rseq.compare.check(spec,grow,capture(p,grow,'stdout'),capture(p,grow,'stderr'),capture(p,grow,'record'),nout,schema)
        same(result,{k:case[k]for k in result},'unchanged full rseq record comparator')
        need(case['native_kind']==('complete_operation'if spec['index']<2 else 'stopped_before_forbidden_operation'),
             'native prefix distinct from a completed forbidden operation')
        for name,value in case['namespace'].items():pin(p.parent/('namespace-'+spec['name'])/name,value)
        namespace(p.parent/('namespace-'+spec['name']))
    need(sum(c['outcome']=='completed'for c in rs['cases'])==2 and
         sum(c['outcome']=='required_refusal'for c in rs['cases'])==15 and all(c['accepted']for c in rs['cases']),
         'original two completions and15 required refusals remain distinct')
    state['cohorts']['rseq']=dict(status='passed',actual_processes=34,accepted=17,completed=2,required_refusals=15,
        case_rows_sha256=H(canonical(rs['cases']).encode()))
    state['status']='passed'
    finalize(receipt)
    return Path(old['namespace_plan']['roots'][0])


def summary(receipt):
    state=receipt.get('companions',{})
    return dict(status=state.get('status','unexecuted'),cohorts=state.get('cohorts',{}),
        receipts={k:{n:v[n]for n in ('bytes','sha256')}for k,v in state.get('receipts',{}).items()})


def finalize(receipt):
    need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in receipt.get('companion_namespace_aliases',{}).items()),
         'all prerequisite namespace aliases remain unchanged')
