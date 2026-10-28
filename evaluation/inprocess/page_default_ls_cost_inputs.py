"""Same-revision footprint custody and a fresh, closed native loader graph."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tomllib
from checks import admission
from page_selected import ENV, bridge_check, fact, need
from page_selected_generic_build import ARTIFACTS, package_check
from page_selected_components import plain_executable
import page_selected_write_footprint as footprint

NAMES = ('resolve-cargo','resolve-rustc','resolve-cc1','resolve-collect2','resolve-as','resolve-ld',
         'version-cc','version-cargo','version-rustc','version-python','cargo-metadata','selected-build',
         'archive-text-exports','bridge-undefined','bridge-elf','generic-observer-link',
         'fixture-build','fixture-undefined','native')
TOOLS = {'cc','sh','nm','readelf','git','cp','mkdir','python','rustup','cargo','rustc','cc1','collect2','as','ld'}
DECODER = {'tools/page-entry/selected/decoder/src/'+name for name in
           ('lib.rs','abi.rs','arena.rs','decode.rs','scan.rs','tf.rs','write_footprint.rs','admission_oneshot.rs')}


def replay(path, root, current, pin):
    path=pin(path);r=json.loads(path.read_bytes());b=r['build'];directory=path.parent
    need(r['profile']=='page-selected-write-footprint-v1' and r['status']=='passed' and
         r['expected_revision']==current['revision'] and r['source']==current and
         r['source_unchanged'] is True and r['error'] is None and not r['final_errors'],
         'fresh passed exact-source footprint prerequisite')
    need(b['status']=='passed' and b['started'] is True and b['command_completed'] is True and
         b['configuration_unchanged'] is True and not b['final_errors'] and
         b['registry_before']==b['registry_after'] and
         r['inputs_before']==r['inputs_after'] and r['binaries_before']==r['binaries_after'],
         'complete footprint build and final custody')
    optional={key for key in ('HOME','CARGO_HOME','RUSTUP_HOME') if key in b['environment']}
    required=set(ENV)|{'LI2_CC','LI2_CARGO','LI2_PYTHON','RUSTC','CARGO_TARGET_DIR',
                       'CARGO_INCREMENTAL','CARGO_BUILD_JOBS','CARGO_NET_OFFLINE','RUSTFLAGS'}
    need(set(b['environment'])==required|optional, 'exact source-derived Build environment keys')
    need(admission.cargo_configuration(b['environment'])==b['cargo_configuration'], 'actual build configuration')
    for table in ('inputs_before','binaries_before'):
        need(r[table], 'nonempty prerequisite custody')
        for p,value in r[table].items():need(fact(pin(p))==value, 'actual prerequisite bytes')
    names=subprocess.check_output(['git','ls-files','-z','tools/page-entry','evaluation/inprocess'],cwd=root,timeout=5).split(b'\0')
    for name in names:
        if name and not name.startswith(b'evaluation/inprocess/results/'):
            p=pin(root/os.fsdecode(name));need(r['inputs_before'].get(str(p))==fact(p),'mandatory current source input')
    need(set(b['tools'])==TOOLS and set(b['artifacts'])==set(ARTIFACTS)|{'generic-observe'},
         'complete original tool and eight-artifact sets')
    tools={}
    for name,item in b['tools'].items():
        p=pin(item['path']);want={k:item[k]for k in ('bytes','sha256')}
        need(fact(p)==want==r['inputs_before'].get(str(p)), 'actual retained tool '+name);tools[name]=p
    artifacts={}
    for name,item in b['artifacts'].items():
        p=pin(item['path']);want={k:item[k]for k in ('bytes','sha256')}
        need(p==directory/'artifacts'/name and fact(p)==want==r['binaries_before'].get(str(p)) and
             p.stat().st_mode&0o777==item['mode'], 'actual retained build artifact '+name)
        prefix=[x for x in b['artifact_prefix']if x['name']==name]
        need(len(prefix)==1 and prefix[0]['copied'] is True and prefix[0]['source_before']==prefix[0]['result']==want and
             prefix[0]['mode']==item['mode'], 'completed artifact copy '+name);artifacts[name]=p
    need(set(b['dep_info'])==DECODER, 'exact eight-source archive extent')
    dep=artifacts['decoder.d'].read_text().strip();target=str(root/'target/release/libli2_page_selected_decoder.a')+': '
    need(dep.startswith(target) and '\n'not in dep, 'actual archive dep-info target')
    deps=shlex.split(dep[len(target):]);need(len(deps)==8 and set(deps)=={str(root/n)for n in DECODER},'actual complete archive dependency list')
    for name,value in b['dep_info'].items():need(fact(pin(root/name))==value, 'same current decoder source')
    for package in b['registry_before']:
        need(package_check(package)==package, 'actual locked registry source closure')
    commands=r['commands'];need([c['name']for c in commands]==list(NAMES),'complete ordered footprint command set')
    captures={};pids=[]
    early={k:v for k,v in b['environment'].items()if k in set(ENV)|{'HOME','CARGO_HOME','RUSTUP_HOME'}}
    need(all(b['environment'][k]==v for k,v in ENV.items()) and
         all(b['environment'][k]==str(tools[t]) for k,t in
             (('LI2_CC','cc'),('LI2_CARGO','cargo'),('LI2_PYTHON','python'),('RUSTC','rustc'))) and
         b['environment']['CARGO_TARGET_DIR']==str(root/'target') and
         b['environment']['CARGO_INCREMENTAL']=='0' and b['environment']['CARGO_BUILD_JOBS']=='1' and
         b['environment']['CARGO_NET_OFFLINE']=='true' and
         b['environment']['RUSTFLAGS']=='-C relocation-model=pic -C panic=abort -C force-unwind-tables=no',
         'original controlled build environment and selected tools')
    for c in commands:
        name=c['name'];native=name=='native'
        descriptors=c['descriptors']
        need(type(descriptors)is list and (descriptors==[] if not native else
             len(descriptors)==2 and all(type(x)is dict and set(x)=={'name','fd','closed'} and
                 type(x['fd'])is int for x in descriptors) and
             descriptors[0]['name']=='record' and descriptors[0]['fd']==3 and
             descriptors[1]['name']=='preparation' and descriptors[1]['fd']>3),
             'exact source-derived prerequisite descriptor inventory')
        need(type(c['pid'])is int and c['pid']>0 and type(c['exit'])is int and c['exit']==c['expected_exit']==0 and
             c['reaped'] is True and c['timed_out'] is False and c['error'] is None and not c['cleanup_errors'] and
             all(x['closed'] is True for x in c['descriptors']), 'actual completed prerequisite child')
        profile=('build'if name=='selected-build'else'fixture_link'if name=='fixture-build'else'native'if native else
                 'inspect'if name in ('archive-text-exports','bridge-undefined','bridge-elf','fixture-undefined')else'metadata')
        environment=early if name in ('resolve-cargo','resolve-rustc')else ENV if name=='native'else b['environment']
        pids.append(c['pid']);need(c['profile']==profile and c['bounds']==footprint.PROFILES[profile] and
            c['capture_limit']==(8192 if native else 1<<20) and c['environment']==environment,'unchanged prerequisite bounds/environment')
        need(json.loads(pin(directory/(name+'.json')).read_bytes())==c, 'exact retained prerequisite command row')
        expected={'stdout','stderr','record','preparation'}if native else {'stdout','stderr'}
        need(set(c['captures'])==expected, 'complete prerequisite captures')
        for stream,item in c['captures'].items():
            p=pin(directory/(name+'.'+stream));need(item['file']==p.name and fact(p)=={k:item[k]for k in ('bytes','sha256')},'actual retained prerequisite capture')
            captures[name,stream]=p.read_bytes()
    need(len(set(pids))==len(pids),'distinct actual prerequisite invocations')
    selected=root/'tools/page-entry/selected';archive=artifacts['decoder.a'];fixture=directory/'footprint-oracle'
    expected={}
    for name in ('cargo','rustc'):expected['resolve-'+name]=[tools['rustup'],'which',name]
    for name in ('cc1','collect2','as','ld'):expected['resolve-'+name]=[tools['cc'],'-print-prog-name='+name]
    for name in ('cc','cargo','rustc','python'):expected['version-'+name]=[tools[name],'-vV'if name=='rustc'else'--version']
    expected.update({'cargo-metadata':[tools['cargo'],'metadata','--manifest-path',selected/'decoder/Cargo.toml','--format-version','1','--locked','--offline'],
        'selected-build':[tools['sh'],selected/'build.sh'], 'archive-text-exports':[tools['nm'],'-g','--defined-only',archive],
        'bridge-undefined':[tools['nm'],'-u',artifacts['bridge-selected.so']],
        'bridge-elf':[tools['readelf'],'-h','-l','-d','-r','-W',artifacts['bridge-selected.so']],
        'generic-observer-link':[tools['cc'],'-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-I'+str(selected),
            '-Wl,--gc-sections,--exclude-libs,ALL,-z,noexecstack,--build-id=none',selected/'tests/generic/observe.c',archive,'-o',directory/'generic-observe'],
        'fixture-build':[tools['sh'],selected/'tests/write_footprint/oracle-build.sh',archive,fixture,selected],
        'fixture-undefined':[tools['nm'],'-u',fixture], 'native':[fixture]})
    for c in commands:need(c['argv']==list(map(str,expected[c['name']])), 'actual source-derived prerequisite argv '+c['name'])
    metadata=json.loads(captures['cargo-metadata','stdout']);need(not captures['cargo-metadata','stderr'] and
        Path(metadata['target_directory']).resolve()==root/'target','actual one-target Cargo metadata')
    locked={(x['name'],x['version']):x for x in tomllib.loads(pin(selected/'decoder/Cargo.lock').read_text())['package']}
    need({(x['name'],x['version'])for x in metadata['packages']}==set(locked),'complete actual locked package set')
    registry=[]
    for item in metadata['packages']:
        key=item['name'],item['version'];lock=locked[key];p=pin(item['manifest_path'])
        if 'checksum'not in lock:need(p==selected/'decoder/Cargo.toml' and item['source']is None,'actual local manifest')
        else:
            need(item['source']==lock['source'],'actual registry package identity')
            registry.append(package_check(dict(name=key[0],version=key[1],root=str(p.parent),checksum=lock['checksum'])))
    need(registry==b['registry_before'],'actual metadata-selected registry custody')
    for name in ('cargo','rustc','cc1','collect2','as','ld'):
        raw=captures['resolve-'+name,'stdout'].decode().strip();resolved=raw if Path(raw).is_absolute()else shutil.which(raw,path=ENV['PATH'])
        need(not captures['resolve-'+name,'stderr'] and resolved is not None and pin(resolved)==tools[name], 'actual selected subtool')
    for name in ('cc','cargo','rustc','python'):
        need(not captures['version-'+name,'stderr'] and captures['version-'+name,'stdout'].decode().strip()==b['versions'][name],'actual tool version')
    for name,version in (('decoder-rustc.txt','rustc'),('decoder-cargo.txt','cargo'),('cc-version.txt','cc')):
        need(artifacts[name].read_text().strip()==b['versions'][version], 'actual build compiler identity')
    for name in ('bridge-undefined','fixture-undefined'):need(captures[name,'stdout']==captures[name,'stderr']==b'', 'no unresolved prerequisite symbols')
    exports=captures['archive-text-exports','stdout'];need(not captures['archive-text-exports','stderr'],'actual archive inspection')
    for name in ('rust_eh_personality','li2_decoder_tf_classify','li2_decoder_write_footprint'):
        rows=[line.split()for line in exports.splitlines()if line.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()] and b['archive_text_exports'].get(name)==1,'actual sole archive definition')
    need(bridge_check(artifacts['bridge-selected.so'])==b['bridge_elf'] and plain_executable(fixture)==r['elf'],'actual prerequisite ELF metadata')
    need(fact(pin(fixture))==r['fixture_after']==r['binaries_before'].get(str(fixture)),'actual executed footprint ELF')
    native=captures['native','record'];need(fact(directory/'native.record')==r['record'] and footprint.verify(native)==r['result'],'unchanged full footprint reader')
    outcome=json.loads(pin(selected/'tests/write_footprint/OUTCOMES.json').read_bytes())['commands'][0]
    need(captures['native','stdout'].decode()==outcome['stdout'] and captures['native','stderr']==b'', 'actual footprint output')
    prep=json.loads(captures['native','preparation']);need(prep['mask']==0 and
        [x['signal']for x in prep['dispositions']]==[x for x in range(1,65)if x not in (9,19)] and
        all(x['after']==0 for x in prep['dispositions']), 'actual footprint signal preparation')
    return tools,archive,dict(receipt=fact(path),archive=fact(archive),commands=len(commands),result=r['result'],
                             source=r['source'],configuration=b['cargo_configuration'],environment=b['environment'])


def namespace_plan(root, library_root, pin):
    path=pin(root/'tools/page-entry/namespace.py');spec=importlib.util.spec_from_file_location('ls_cost_namespace',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original=pin('/bin/ls');main=module.parse(original.read_bytes());interpreter=pin(main['interpreter'])
    objects,description=module.plan(original,[library_root],bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interpreter)['sha256']))
    description['objects']=[]
    for item in objects:
        p=pin(item['path']);need(p.read_bytes()==item['bytes'],'actual namespace source bytes')
        for name in item['names']:need(pin(Path(library_root)/name)==p, 'actual explicit root alias')
        description['objects'].append(dict(source=str(p),names=item['names'],needed=item['info']['needed'],
            size=len(item['bytes']),sha256=fact(p)['sha256'],seals=module.SEALS))
    return module,description


def native_libraries(module,plan,output,pin):
    interpreter=pin(plan['interpreter']);expected={pin(x['source'])for x in plan['objects']}|{interpreter}
    rows={};vdso=0
    for line in output.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
        match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'closed native loader listing row');name,alias=match.groups();p=pin(alias)
        need(p in expected and str(p)not in rows,'unique planned native dependency');info=module.parse(p.read_bytes())
        need(info['elf_type']==3,'actual native dependency type')
        if name is None or name.startswith('/'):
            need(p==interpreter and(name is None or pin(name)==p),'actual native interpreter alias')
        else:
            owners=[x for x in plan['objects']if name in x['names']]
            need(len(owners)==1 and pin(owners[0]['source'])==p and info['soname']==name,'actual planned SONAME identity')
        rows[str(p)]=dict(**fact(p),needed=info['needed'],soname=info['soname'])
    need(vdso==1 and {Path(x)for x in rows}==expected,'complete actual native/namespace dependency equality')
    return rows
