"""File-only replay of the mandatory same-revision primitive prerequisite."""
import importlib.util
from pathlib import Path
import re
import shlex

from page_selected import ENV, fact, need
from page_selected_fast_memset import decode
import page_selected_fast_equal as primitive


def recipes(root, directory, tools):
    fixture=root/'tools/page-entry/selected/tests/fast_equal';selected=fixture.parents[1]
    lines=[x.strip()for x in (fixture/'build-oracle.sh').read_text().replace('\\\n',' ').splitlines()
           if x.strip().startswith('"$cc_bin" ')]
    need(len(lines)==2,'exact primitive object/link source recipes');result=[]
    for mode in ('scalar','fast'):
        values={'$cc_bin':tools['cc']['path'],'$owner_source':str(selected/'step_owner.c'),
            '$selected_context':str(selected),'$parent_context':str(selected.parent),
            '$fixture_dir':str(fixture),'$output_dir':str(directory/'build'),'$mode':mode,
            '$extra':'-DLI2_FAST_EQUAL=1'if mode=='fast'else ''}
        for index,line in enumerate(lines):
            argv=[]
            for word in shlex.split(line):
                for key,value in values.items():word=word.replace(key,value)
                need('$'not in word and '`'not in word,'closed primitive recipe substitution')
                if word:argv.append(word)
            result.append((mode,index,argv))
    return result


def command_plan(root,directory,r):
    tools={k:v['path']for k,v in r['tools'].items()};plan=[]
    def add(name,argv,profile='metadata'):plan.append((name,list(map(str,argv)),profile))
    for name in ('cc1','collect2','as','ld'):add('resolve-'+name,[tools['cc'],'-print-prog-name='+name])
    for name in ('cc','nm','objdump','readelf','ld','as','python'):add('version-'+name,[tools[name],'--version'])
    for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o',
                 'libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a'):
        add('link-input-'+name,[tools['cc'],'-print-file-name='+name])
    add('cc-specs',[tools['cc'],'-dumpspecs'])
    commands=recipes(root,directory,r['tools'])
    for mode,index,argv in commands:
        sources=[x for x in argv[1:-2]if x.endswith('.c')]
        flags=[x for x in argv[1:-2]if x not in sources and not x.endswith('.o')and x!='-c'and not x.startswith('-Wl,')]
        add('headers-'+mode+'-'+str(index),[tools['cc'],*flags,'-M','-MT','li2_equal_headers',*sources])
    for mode,index,argv in commands:add(('object-'if index==0 else 'link-')+mode,argv,'build')
    for mode in ('scalar','fast'):
        for kind,name in (('object','owner-'+mode+'.o'),('final','equal-'+mode)):
            path=directory/'build'/name
            add(mode+'-'+kind+'-symbols',[tools['nm'],'-S','--defined-only',path],'inspect')
            add(mode+'-'+kind+'-body',[tools['objdump'],'-d','-w','-M','att',path],'inspect')
        path=directory/'build'/('equal-'+mode)
        add(mode+'-elf',[tools['readelf'],'-h','-l','-d','-r','-W',path],'inspect')
        add(mode+'-libraries',[str(Path(r['inspection'][mode]['layout']['interpreter']).resolve(strict=True)),'--list',path])
    for name,mode,measured in primitive.NATIVE:
        add(name,[directory/'build'/('equal-'+mode),*(['m']if measured else [])],'native')
    need(len(plan)==50 and len({x[0]for x in plan})==50,'closed source-derived fifty primitive commands')
    return plan


def dependency(r,name,pin):
    """Require a derived dependency in both old custody maps, then repin it."""
    lexical=str(Path(name).absolute());resolved=pin(name);value=fact(resolved)
    need(r['aliases'].get(lexical)==str(resolved) and r['inputs'].get(str(resolved))==value,
         'mandatory actual dependency retained with lexical alias and complete bytes')
    return resolved


def libraries(r,mode,text,pin):
    # The caller has already matched this layout against the actual retained ELF.
    loader=dependency(r,r['inspection'][mode]['layout']['interpreter'],pin)
    found={};vdso=0
    for line in text.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
        match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'closed actual prerequisite library row')
        key=match[1]or'interpreter'
        if match[1]and match[1].startswith('/'):
            need(dependency(r,match[1],pin)==dependency(r,match[2],pin)==loader,
                 'both actual interpreter aliases name the actual ELF loader');key='interpreter'
        need(key not in found,'unique actual prerequisite dependency')
        path=dependency(r,match[2],pin);found[key]=dict(path=str(path),**fact(path))
    need(vdso==1 and set(found)=={'libc.so.6','interpreter'}and found['interpreter']['path']==str(loader),
         'only actual libc/interpreter and exactly one vdso')
    need(found==r['inspection'][mode]['libraries'],'complete actual library-list/layout/input join')


def replay(path,root,current_source,pin,binary):
    path=Path(path).absolute();need(path.name=='receipt.json'and not path.is_symlink(),'actual private primitive receipt')
    r=decode(pin(path).read_bytes());directory=path.parent
    need(r['schema']==1 and r['profile']=='page-selected-fast-equal-v1'and r['status']=='passed'and
         r['build_status']=='passed'and r['error']is None and r['final_errors']==[]and
         r['cleanup_complete']is True and r['source_unchanged']is True and r['rust_archive_used']is False,
         'passed complete primitive prerequisite, never a supplied or failed attempt')
    need(r['source']==r['source_after']==current_source and r['expected_revision']==current_source['revision'],
         'fresh primitive at exact current committed source')
    need(r['environment']==ENV and type(r['cpu'])is int and r['hardware'],'retained actual primitive environment/hardware')
    for name,before in r['inputs'].items():need(fact(pin(name))==before,'primitive input still exact')
    for alias,resolved in r['aliases'].items():need(str(pin(alias))==resolved,'primitive lexical alias still exact')
    for name,present in r['configuration_presence'].items():
        need(type(present)is bool and Path(name).exists()==present,'primitive loader configuration presence')
    need(r['configuration_presence']=={'/etc/ld.so.cache':Path('/etc/ld.so.cache').exists(),'/etc/ld.so.preload':False},
         'same closed loader configuration')
    for name,present in r['configuration_presence'].items():
        if present:dependency(r,name,pin)
    for name,v in r['tools'].items():need(fact(pin(v['path']))=={k:v[k]for k in ('bytes','sha256')},'actual primitive tool identity')
    fixture=root/'tools/page-entry/selected/tests/fast_equal';selected=fixture.parents[1]
    catalog=root/'evaluation/inprocess/page_selected_fast_equal_inputs.json'
    need(fact(pin(catalog))==r['input_catalog']and fact(pin(selected/'step_owner.c'))==r['owner_source'],
         'current tracked primitive input catalog and actual owner')
    cfg=decode(catalog.read_bytes());need(cfg['schema']==1 and len(cfg['sources'])==28 and
        len({x['path']for x in cfg['sources']})==28,'closed primitive tracked sources')
    for item in cfg['sources']:
        p=root/item['path'];need(not Path(item['path']).is_absolute()and '..'not in Path(item['path']).parts and
            fact(pin(p))=={k:item[k]for k in ('bytes','sha256')}==r['inputs'][str(p.resolve())],
            'every current primitive source joined to actual receipt')
    expected={str(directory/'build'/name)for name in ('owner-scalar.o','owner-fast.o','equal-scalar','equal-fast')}
    need(set(r['artifacts'])==expected,'all four actual primitive outputs')
    for name,v in r['artifacts'].items():
        p=Path(name);need(p.is_file()and not p.is_symlink()and dict(fact(p),mode=p.stat().st_mode&0o777)==v,
                         'exact retained primitive artifact bytes/mode');binary(p)
    plan=command_plan(root,directory,r)
    need([c['name']for c in r['commands']]==[x[0]for x in plan],'all fifty commands in exact source order')
    captures={}
    for c,(name,argv,profile) in zip(r['commands'],plan):
        need(c['argv']==argv and c['profile']==profile and c['bounds']==primitive.BOUNDS[profile]and
             c['capture_limit']==(65536 if profile=='native'else 4<<20)and c['environment']==ENV and
             type(c['expected_exit'])is int and c['expected_exit']==0 and type(c['exit'])is int and c['exit']==0 and
             type(c['pid'])is int and c['pid']>0 and c['reaped']is True and c['timed_out']is False and
             c['error']is None and c['cleanup_errors']==[]and all(x['closed']is True for x in c['descriptors']),
             'actual primitive command, bounds, outcome and cleanup')
        record=directory/(name+'.json');need(decode(pin(record).read_bytes())==c,'actual supervised command receipt')
        need(set(c['captures'])=={'stdout','stderr'},'complete primitive command captures');captures[name]={}
        for stream,cap in c['captures'].items():
            need(cap['file']==name+'.'+stream,'closed actual capture name');p=directory/cap['file']
            need(fact(pin(p))=={k:cap[k]for k in ('bytes','sha256')},'actual primitive capture extent/hash')
            captures[name][stream]=p.read_bytes()
        need(captures[name]['stderr']==b'','all accepted primitive stderr empty')
    for name,_,_ in plan:
        if name.startswith('link-input-'):
            value=captures[name]['stdout'].decode().strip()
            need(Path(value).is_absolute(),'actual absolute compiler link-input path')
            dependency(r,value,pin)
    # Exact compiler recipes must be the recipes whose conditional headers were
    # observed, not an unrelated successful metadata command in the same run.
    commands=recipes(root,directory,r['tools']);need(len(r['header_observations'])==4,'four conditional header observations')
    for observed,(mode,index,argv) in zip(r['header_observations'],commands):
        name='headers-'+mode+'-'+str(index);tu=argv[-3]if index==0 else str(fixture/'oracle.c')
        need(observed['mode']==mode and observed['command']==name and observed['argv']==argv and
             observed['translation_unit']==tu,'actual conditional header/compiler recipe join')
        text=captures[name]['stdout'].decode().replace('\\\n',' ')
        need(len(text.splitlines())==1 and text.startswith('li2_equal_headers: '),'one complete actual header rule')
        deps=shlex.split(text.split(':',1)[1]);need(deps and len(deps)==len(set(deps))and tu in deps and
             all(Path(x).is_absolute()for x in deps),'actual lexical source/header paths')
        actual={x:dict(resolved=str(pin(x)),**fact(x))for x in deps}
        need(actual==observed['headers']and all(r['aliases'][x]==v['resolved']and
             r['inputs'][v['resolved']]=={k:v[k]for k in ('bytes','sha256')}for x,v in actual.items()),
             'complete current header bytes/aliases joined to primitive closure')
        if index==0:need(str(selected/'tf_chain.inc')in actual and str(selected/'oneshot.h')in actual,'full primitive profile includes')
    for mode in ('scalar','fast'):
        actual={}
        for kind,name in (('object','owner-'+mode+'.o'),('final','equal-'+mode)):
            p=directory/'build'/name;symbols=captures[mode+'-'+kind+'-symbols']['stdout']
            actual[kind]=primitive.equal_inspect.body(p,symbols,captures[mode+'-'+kind+'-body']['stdout'],mode=='fast')
            need(actual[kind]==r['inspection'][mode][kind],'actual ELF helper/body replay')
            if kind=='final':need(primitive.equal_inspect.layout(p,symbols)==r['inspection'][mode]['layout'],
                                  'actual primitive whole record layout replay')
        need(primitive.equal_inspect.linked(actual['object'],actual['final']),'primitive complete object/final helper graph')
        libraries(r,mode,captures[mode+'-libraries']['stdout'],pin)
    spec=importlib.util.spec_from_file_location('li2_fast_equal_owner_check',pin(fixture/'check.py'))
    check=importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
    need(len(r['cases'])==6,'six actual primitive processes');baseline=None;intervals=[]
    for c,(name,mode,measured) in zip(r['cases'],primitive.NATIVE):
        out=captures[name]['stdout'];result=check.parse(out,mode=='fast',measured)
        expected_case=dict(name=name,mode=mode,measured=measured,accepted=True,actual_exit=0,
                           result=result,record=fact(directory/(name+'.stdout')))
        need(c==expected_case,'complete raw primitive case replay')
        if baseline is None:baseline=out[128:4736]
        need(out[128:4736]==baseline,'all complete functional records equal scalar')
        if measured:intervals+=result['nanoseconds']
    need(len(intervals)==32 and all(type(x)is int and x>0 for x in intervals),'all thirty-two genuine primitive intervals retained')
    return r,dict(status='passed',receipt=fact(path),revision=r['expected_revision'],commands=50,processes=6,
                  functional_processes=2,raw_intervals=intervals,inspection_sha256=primitive.digest(r['inspection']),
                  fast_object=r['artifacts'][str(directory/'build/owner-fast.o')],
                  application_performance_credit=False)


def match_tools(prerequisite,builder):
    for name in ('cc','cc1','collect2','as','ld','nm','objdump','readelf','python'):
        p=builder.tools[name];v=prerequisite['tools'][name]
        need(str(p)==v['path']and fact(p)=={k:v[k]for k in ('bytes','sha256')},
             'owner and primitive use the same actual compiler/subtools/inspectors')
