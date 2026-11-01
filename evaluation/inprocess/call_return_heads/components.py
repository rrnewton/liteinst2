"""Nine exact finite components, using the caller's unchanged bounded process owner.

The first eight are the full standalone and planner cohorts with the explicit
return-head mode off/on. The last is the additive graph component. No native
subject or archive build occurs here. Actual compiler-M, retained temporaries,
link trace, full ELF/runtime closure and strict stdout remain mandatory.
"""
from pathlib import Path
import re
import shlex
from call_owner import custody
from ret_dispatch import run as donor

need, fact, elf = donor.need, custody.fact, donor.elf
LINK_NAMES = donor.LINK_NAMES
FLAG = '-DLI2_PERSISTENT_CALL_RETURN_HEADS=1'


def run_all(builder,selected,private,manifest,pin,binary,owned_run,record):
    root=custody.ROOT;archive=pin(builder.paths['archive']);tools=builder.tools
    output_root=private/'components';output_root.mkdir()
    record['components']={};states=record['components']
    def run(label,argv,profile='release_build'):
        _,out,err=owned_run('components-'+label,argv,profile=profile,env=builder.environment)
        return out,err

    def runtime(label, program, allowed=None):
        image = elf(program); spelling = image['interpreter']
        need(spelling is not None, 'one actual executable interpreter')
        loader = pin(spelling)
        if allowed is not None:
            need(str(loader) in allowed, 'actual interpreter was bound before link')
        out, err = run(label+'-dependencies', [loader, '--list', program])
        need(not err, 'whole loader dependency listing stderr')
        dependencies = set()
        for line in out.decode().splitlines():
            line = line.strip()
            if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line): continue
            alias = re.fullmatch(r'(/[^ ]+) => (/[^ ]+) \(0x[0-9a-f]+\)', line)
            if alias:
                need(alias[1] == spelling and alias[2] == str(loader) and pin(alias[1]) == pin(alias[2]) == loader,
                     'only the exact actual interpreter alias/target')
                path = loader
            else:
                match = re.fullmatch(r'(?:[^ /]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)', line)
                need(match is not None, 'complete resolved runtime dependency grammar'); path = pin(match[1])
            if allowed is not None:
                need(str(path) in allowed, 'runtime dependency bound before link')
            dependencies.add(str(path))
        need(str(loader) in dependencies, 'complete actual loader closure')
        dynamic = {p: elf(p) for p in sorted(dependencies)}; sonames = {}
        for p, info in dynamic.items():
            if info['soname']:
                need(info['soname'] not in sonames, 'one actual file per runtime SONAME'); sonames[info['soname']] = p
        need('libc.so.6' in sonames and all(n in sonames for info in [image, *dynamic.values()] for n in info['needed']),
             'every actual DT_NEEDED edge closes over the bound runtime objects')
        return image, dynamic


    record['component_tool_runtime']={name:runtime('tool-'+name,path)[1]
        for name,path in tools.items()}
    link_inputs={str(archive)}
    for name in LINK_NAMES:
        out,err=run('link-'+name,[tools['cc'],'-print-file-name='+name]);value=out.decode().strip()
        need(not err and Path(value).is_absolute(),'prebound compiler-selected link input')
        link_inputs.add(str(pin(value)))
    pending=list(link_inputs)
    while pending:
        path=Path(pending.pop());data=path.read_bytes()
        if data.startswith((b'\x7fELF',b'!<arch>')):continue
        need(len(data)<4096 and b'GNU ld script' in data,'bounded recognized GNU linker script')
        for name in re.findall(r'/[^\s()]+',re.sub(r'/\*.*?\*/','',data.decode(),flags=re.S)):
            name=str(pin(name))
            if name not in link_inputs:link_inputs.add(name);pending.append(name)
    out,err=run('archive-exports',[tools['nm'],'-g','--defined-only',archive])
    need(not err,'whole archive census stderr')
    required=('li2_decoder_decode','li2_decoder_tf_classify','li2_decoder_write_footprint',
              'li2_decoder_span_describe','li2_decoder_region_describe','li2_decoder_link_none','li2_decoder_mov_store')
    names=[m[1] for line in out.decode().splitlines()
           if (m:=re.fullmatch(r'[0-9a-fA-F]+ T (\S+)',line))]
    need(all(names.count(name)==1 for name in required),'all exact decoder component providers')
    schedule=[name+'-'+mode for mode in ('off','on') for name in
        ('call_dispatch','ret_dispatch','call_dispatch_plan','ret_dispatch_plan')]+['call_return_heads-on']
    need([x['name'] for x in manifest['components']]==schedule,'nine exact complete component cohorts in order')
    for case in manifest['components']:
        name=case['name'];fixture=selected/'tests'/case['fixture'];recipe=pin(root/case['recipe'])
        need(fact(recipe)==case['recipe_fact'],'complete frozen source recipe bytes and mode')
        output_dir=output_root/name;output_dir.mkdir();output=output_dir/'component'
        units=[str(selected/x) for x in case['units']]
        for path in units:pin(path)
        text=recipe.read_text().replace('\\\n',' ')
        lines=[line.strip() for line in text.splitlines() if line.strip().startswith(('"$cc_bin" ','"$cc" '))]
        need(len(lines)==1,'one exact compiler recipe')
        replacements={'$cc_bin':tools['cc'],'$fixture':fixture,'$selected':selected,
                      '$archive':archive,'$output':output,'$source_dir':fixture,'$cc':tools['cc']}
        argv=[]
        for word in shlex.split(lines[0]):
            for key,value in replacements.items():word=word.replace(key,str(value))
            need('$' not in word and '`' not in word,'closed literal compiler argument');argv.append(word)
        need([x for x in argv if x.endswith(('.c','.S'))]==units and
             [x for x in argv if x.endswith('.a')]==[str(archive)] and argv[-2:]==['-o',str(output)],
             'all exact component TUs, one archive and exact output')
        original_argv=list(argv)
        mode=case['return_heads']
        need(type(mode) is bool and [x for x in argv if x.startswith('-DLI2_PERSISTENT_CALL_RETURN_HEADS')]
             ==([FLAG] if case['recipe_enables_return_heads'] else []),'exact literal mode in original recipe')
        if mode and not case['recipe_enables_return_heads']:argv.insert(1,FLAG)
        need(argv.count(FLAG)==int(mode),'full explicit flag-off/on cohort, no inherited on-mode credit')
        source_aliases={}
        for original,alias in case['source_aliases'].items():
            a=selected/original;declared=selected/alias
            need(a.parent==declared.parent and a.name=='model.c' and
                 (original,alias) in (('tests/call_dispatch/model.c','tests/call_dispatch/call_model.c'),
                                     ('tests/ret_dispatch/model.c','tests/ret_dispatch/ret_model.c')),
                 'only the two exact model aliases prevent diagnostic object basename collision')
            alias_dir=output_dir/'source-aliases'/a.parent.name;alias_dir.mkdir(parents=True)
            b=alias_dir/declared.name;header=alias_dir/'model.h'
            b.symlink_to(pin(a));header.symlink_to(pin(a.with_name('model.h')))
            record['context_links'][str(b)]=str(pin(a))
            record['context_links'][str(header)]=str(pin(a.with_name('model.h')))
            need(fact(pin(a))==fact(pin(b)) and b.is_symlink() and
                 fact(pin(header))==fact(pin(a.with_name('model.h'))) and header.is_symlink(),
                 'whole exact model and local header aliases; every alias stays in final custody')
            need(argv.count(str(a))==1,'one aliased source argument')
            argv[argv.index(str(a))]=str(b);source_aliases[str(a)]=str(b)
        actual_units=[source_aliases.get(x,x) for x in units]
        need(len({Path(x).stem for x in actual_units})==len(actual_units),'distinct retained generated-object names')
        flags=[x for x in argv[1:-2] if x not in actual_units and x!=str(archive) and not x.startswith(('-Wl,','-l'))]
        out,err=run(name+'-headers',[tools['cc'],*flags,'-M','-MT','ret_component',*actual_units])
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==len(actual_units) and all(x.startswith('ret_component: ') for x in rules),
             'every complete actual compiler-M rule')
        headers={str(pin(x)) for line in rules for x in shlex.split(line.split(':',1)[1])}
        need({str(Path(x).resolve()) for x in actual_units} |
             {str((selected/x).resolve()) for x in case['headers']} <= headers,
             'complete typed component header closure')
        additions=['-save-temps=obj','-Wl,--trace']
        out,err=run(name+'-build',argv[:-2]+additions+argv[-2:])
        need(not err,'strict original -Werror compiler/linker stderr')
        objects={str(output_dir/('component-'+Path(p).stem+'.o')) for p in actual_units}
        for unit in actual_units:
            for suffix in ('.i','.s','.o','.su'):binary(output_dir/('component-'+Path(unit).stem+suffix))
        trace=out.decode().splitlines()
        need(trace and all(Path(x).is_absolute() for x in trace),'whole absolute actual linker trace')
        linked={str(Path(x).resolve(strict=True)) for x in trace}
        need(objects|{str(archive)}<=linked<=link_inputs|objects,'all generated objects and only prebound link inputs')
        produced=binary(output);need(int(fact(produced)['mode'],8)&0o111,'actual executable component')
        image,dynamic=runtime(name,output,link_inputs)
        for path,expected in [(str(output),image),*dynamic.items()]:
            need(donor.native_dynamic(path)=={k:expected[k] for k in ('needed','soname')},
                 'whole actual dynamic tags, no search/filter/audit override')
        states[name]=dict(status='not_run',recipe=fact(recipe),original_argv=original_argv,
            actual_argv=argv,return_heads=mode,source_aliases=source_aliases,
            diagnostic_only_additions=additions,headers=sorted(headers),link_inputs=sorted(linked),
            runtime_objects=dynamic,elf=image,binary=fact(produced),result=None)
        out,err=run(name+'-component',[output],'finite')
        need(not err and out==case['stdout'].encode(),'exact complete component population and stdout')
        states[name].update(status='passed',result={k:int(v) for k,v in
            (word.split('=') for word in case['stdout'].split()[1:])})
    need(list(states)==schedule and all(x['status']=='passed' for x in states.values()),
         'all nine complete original and additive components passed; no native or owner inference')
