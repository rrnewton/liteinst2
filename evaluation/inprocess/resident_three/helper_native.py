"""Fixed original-PC helper observations plus unchanged footprint oracle; no owner credit."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,json,os,re,shlex,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source,admission
from run import hardware
from page_selected import ENV,save
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand
from call_owner.custody import check_archive
from ret_dispatch.run import elf,native_dynamic,LINK_NAMES
from page_selected_components import plain_executable
from page_selected_write_footprint import verify as footprint_verify

BOUNDS={'build':[30,512<<20,16<<20,60],'native':[5,512<<20,16<<20,15]}
STAGED=('decoder.h','write_footprint.h','tf_owner.h','step_owner.h',
        'tests/generic/tf_controls.c','tests/decoder/support.c',
        'tests/write_footprint/oracle.c','tests/write_footprint/oracle.S',
        'tests/write_footprint/oracle-build.sh','tests/write_footprint/OUTCOMES.json')
NATIVE_SOURCES=('helper_tf.h','helper_tf.c',
                'tests/helper_tf_native/probe.c','tests/helper_tf_native/probe.S',
                'tests/helper_tf_native/build.sh','tests/helper_tf_native/read.py',
                'tests/helper_tf_native/frame.py')
UNITS=('tests/helper_tf_native/probe.c','tests/helper_tf_native/probe.S',
       'helper_tf.c','tests/generic/tf_controls.c','tests/decoder/support.c')

def need(ok,message):
    if not ok:raise ValueError(message)

def fact(path):
    p=Path(path);need(p.is_file() and not p.is_symlink(),'whole regular file: '+str(p))
    b=p.read_bytes()
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=format(p.stat().st_mode&0o777,'04o'))

def unique(pairs):
    d=dict(pairs);need(len(d)==len(pairs),'duplicate JSON field');return d

def load(path):
    return json.loads(Path(path).read_bytes(),object_pairs_hook=unique)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive-receipt',type=Path,required=True)
    parser.add_argument('--archive-receipt-sha256',required=True)
    parser.add_argument('--cpu',type=int,required=True)
    parser.add_argument('--expect-revision',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();private=args.output.absolute()
    need(private.parent==ROOT/'target/evaluation/inprocess' and not private.exists(),'fresh direct output child')
    need(not sys.flags.optimize and args.cpu>=0 and sorted(os.sched_getaffinity(0))==[args.cpu],
         'exact one externally reserved CPU argument')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}',args.archive_receipt_sha256),'explicit source and archive identities')
    private.mkdir();receipt=private/'receipt.json'
    r=dict(schema=1,profile='helper-tf-bounded-native-v1',status='failed',cpu=args.cpu,bounds=BOUNDS,
        commands=[],inputs={},aliases={},artifacts={},loader_presence={},error=None,final_errors=[],
        chunks={str(p)+'-'+str(c):dict(status='not_run',result=None) for p,c in ((0,0),(0,1),(1,0),(1,1))},
        footprint=dict(status='not_run',result=None),
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,
        archive_builds=0,runtime_owner_credit=False,qualification_credit=False,performance_credit=False)

    def pin(path):
        alias=Path(path).absolute();p=alias.resolve(strict=True);v=fact(p)
        need(str(p) not in r['inputs'] or r['inputs'][str(p)]==v,'stable whole input')
        need(str(alias) not in r['aliases'] or r['aliases'][str(alias)]==str(p),'stable input alias')
        r['inputs'][str(p)]=v;r['aliases'][str(alias)]=str(p);return p

    def artifact(path):
        p=Path(path).absolute();need(p.is_relative_to(private),'contained artifact')
        v=fact(p);need(str(p) not in r['artifacts'] or r['artifacts'][str(p)]==v,'immutable artifact')
        r['artifacts'][str(p)]=v;return p

    def closure():
        need(all(fact(p)==v for p,v in r['inputs'].items()),'all inputs unchanged')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in r['aliases'].items()),'all aliases unchanged')
        need(all(fact(p)==v for p,v in r['artifacts'].items()),'all completed artifacts unchanged')
        need(all(Path(p).exists()==v for p,v in r['loader_presence'].items()),'loader configuration unchanged')
        need(sorted(os.sched_getaffinity(0))==[args.cpu],'same exact reserved CPU argument')

    def command(name,argv,kind='build',strict=True,record=False,step=False):
        closure();need(not any(x['name']==name for x in r['commands']),'unique fixed command, no retry')
        row=dict(name=name,argv=list(map(str,argv)),bounds=BOUNDS[kind],environment=dict(ENV),
                 capture_limit=8192 if step else 16<<20,expected_exit=0)
        r['commands'].append(row);save(receipt,r)
        caught=None
        try:invoke(row,private,args.cpu,record=record,step=step)
        except Exception as e:caught=repr(e)
        finally:
            for value in row.get('captures',{}).values():
                p=artifact(private/value['file'])
                need(all(fact(p)[k]==value[k] for k in ('bytes','sha256')),'whole actual command capture')
            if (private/(name+'.json')).is_file():artifact(private/(name+'.json'))
            save(receipt,r)
        ok=(caught is None and row['exit']==0 and row['error'] is None and row['timed_out'] is False and
            row['reaped'] is True and row['cleanup_errors']==[] and all(d['closed'] for d in row['descriptors']))
        if strict:need(ok,'closed successful command: '+name+' '+str(caught))
        out=(private/(name+'.stdout')).read_bytes() if (private/(name+'.stdout')).is_file() else b''
        err=(private/(name+'.stderr')).read_bytes() if (private/(name+'.stderr')).is_file() else b''
        return row,out,err,ok

    def runtime(label,program,allowed=None):
        image=elf(program);spelling=image['interpreter']
        need(spelling is not None,'one actual executable interpreter')
        loader=pin(spelling)
        if allowed is not None:need(str(loader) in allowed,'prebound actual interpreter')
        _,out,err,_=command(label+'-dependencies',[loader,'--list',program])
        need(not err,'clean complete loader listing')
        dependencies=set()
        for line in out.decode().splitlines():
            line=line.strip()
            if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):continue
            alias=re.fullmatch(r'(/[^ ]+) => (/[^ ]+) \(0x[0-9a-f]+\)',line)
            if alias:
                need(alias[1]==spelling and alias[2]==str(loader) and pin(alias[1])==pin(alias[2])==loader,
                     'only actual loader alias')
                p=loader
            else:
                match=re.fullmatch(r'(?:[^ /]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)',line)
                need(match is not None,'complete loader grammar');p=pin(match[1])
            if allowed is not None:need(str(p) in allowed,'prebound runtime object')
            dependencies.add(str(p))
        need(str(loader) in dependencies,'whole loader closure')
        dynamic={p:elf(p) for p in sorted(dependencies)};sonames={}
        for p,item in dynamic.items():
            if item['soname']:
                need(item['soname'] not in sonames,'unique runtime SONAME');sonames[item['soname']]=p
        need('libc.so.6' in sonames and all(n in sonames for item in [image,*dynamic.values()] for n in item['needed']),
             'every actual DT_NEEDED edge closed')
        if allowed is not None:
            for p,item in [(str(program),image),*dynamic.items()]:
                need(native_dynamic(p)=={k:item[k] for k in ('needed','soname')},'no hidden loader search/audit overrides')
        return dict(elf=image,objects=dynamic)

    try:
        r['source']=source();r['revision']=r['source']['revision'];r['hardware']=hardware(args.cpu)
        need(r['revision']==args.expect_revision,'exact clean current revision')
        pin(__file__);pin(admission.__file__)
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).is_file():pin(p)
        archive_receipt=pin(args.archive_receipt)
        archive,build,_,exports,old=check_archive(archive_receipt,args.archive_receipt_sha256,r,pin)
        r['archive']=dict(path=str(archive),**fact(archive),receipt=dict(path=str(archive_receipt),**fact(archive_receipt)),
                          built_revision=old['revision'],current_decoder_source_bytes_verified=True,
                          whole_archive_validator=True,same_source_as_current=True,qualification_credit=False)
        tools={name:pin(build['tools'][name]['path']) for name in ('cc','cc1','collect2','as','ld','nm','git')}
        tools['python']=pin(sys.executable)
        need(fact(tools['python'])==fact(pin(build['tools']['python']['path'])),'same retained Python tool identity')
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            r['loader_presence'][name]=Path(name).exists()
            if r['loader_presence'][name]:pin(name)
        need(not r['loader_presence']['/etc/ld.so.preload'],'no global preload')
        r['tool_runtime']={name:runtime('tool-'+name,p) for name,p in tools.items()}
        link_inputs={str(archive)}
        for name in LINK_NAMES:
            _,out,err,_=command('link-'+name,[tools['cc'],'-print-file-name='+name]);p=out.decode().strip()
            need(not err and Path(p).is_absolute(),'compiler-selected whole link input');link_inputs.add(str(pin(p)))
        pending=list(link_inputs)
        while pending:
            p=Path(pending.pop());data=p.read_bytes()
            if data.startswith((b'\x7fELF',b'!<arch>')):continue
            need(len(data)<4096 and b'GNU ld script' in data,'bounded known linker script')
            for name in re.findall(r'/[^\s()]+',re.sub(r'/\*.*?\*/','',data.decode(),flags=re.S)):
                name=str(pin(name))
                if name not in link_inputs:link_inputs.add(name);pending.append(name)
        _,_,err,_=command('compiler-specs',[tools['cc'],'-dumpspecs']);need(not err,'complete compiler specs')
        _,out,err,_=command('archive-exports',[tools['nm'],'-g','--defined-only',archive])
        need(not err and out==exports,'fresh exact retained archive exports')
        selected=private/'source/tools/page-entry/selected'
        staging={name:SELECTED/name for name in (*STAGED,*NATIVE_SOURCES)}
        for name,origin in staging.items():
            origin=pin(origin);p=selected/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(origin.read_bytes());p.chmod(origin.stat().st_mode&0o777)
            need(fact(p)==fact(origin),'exact regular source staging');artifact(p)
        r['staging']={str(selected/name):dict(origin=str(origin),**fact(origin)) for name,origin in staging.items()}
        fixture=selected/'tests/helper_tf_native';output=private/'helper-tf'
        rows=recipe(fixture/'build.sh','"$cc_bin"');need(len(rows)==1,'one original strict recipe')
        argv=expand(rows[0],{'$cc_bin':tools['cc'],'$selected':selected,'$fixture':fixture,
                             '$archive':archive,'$output':output})
        units=[str(selected/x) for x in UNITS]
        need([x for x in argv if x.endswith(('.c','.S'))]==units and
             [x for x in argv if x.endswith('.a')]==[str(archive)] and argv[-2:]==['-o',str(output)] and
             '-Wall' in argv and '-Wextra' in argv and '-Werror' in argv and
             not any(x.startswith('-Wno-') for x in argv),'exact flags, five sources, archive and output')
        flags=[x for x in argv[1:-2] if x not in units and x!=str(archive) and not x.startswith(('-Wl,','-l'))]
        _,out,err,_=command('headers',[tools['cc'],*flags,'-M','-MT','li2_helper_tf',*units])
        rules=out.decode().replace('\\\n',' ').splitlines();headers={}
        need(not err and len(rules)==len(units),'one actual compiler-M rule per TU')
        for unit,line in zip(units,rules):
            need(line.startswith('li2_helper_tf: '),'exact dependency target')
            names=shlex.split(line.split(':',1)[1]);need(unit in names,'actual source in its rule')
            for name in names:
                need(Path(name).is_absolute(),'absolute actual dependency');p=pin(name)
                headers[name]=dict(resolved=str(p),**fact(p))
        need({str(selected/x) for x in ('helper_tf.h','decoder.h','tf_owner.h','step_owner.h','write_footprint.h')}
             <=set(headers),'whole typed header closure')
        r['build']=dict(original_argv=argv,diagnostic_additions=[],headers=headers,link_inputs=sorted(link_inputs))
        _,out,err,_=command('build',argv);need(out==err==b'','strict unchanged compiler recipe, no diagnostics')
        artifact(output)
        for p in private.glob('*.su'):artifact(p)
        need(output.stat().st_mode&0o111,'actual executable output')
        loader=str(pin(elf(output)['interpreter']));link_inputs.add(loader)
        r['build']['runtime']=runtime('native',output,link_inputs)
        r['build']['binary']=dict(path=str(output),**fact(output))
        inspector=pin(HERE/'helper_inspect.py')
        _,out,err,_=command('inspection',[tools['python'],'-I','-S','-B',inspector,output],'native')
        inspected=json.loads(out,object_pairs_hook=unique)
        need(not err and inspected['status']=='source_bytes_inspected' and
             inspected['elf_sha256']==fact(output)['sha256'] and inspected['native_execution'] is False and
             inspected['qualification_credit'] is False,'full actual x87/XMM/mask/bootstrap/return/handler inspection')
        r['inspection']=inspected
        reader=pin(fixture/'read.py');pin(fixture/'frame.py')
        # The historical 38-row oracle is built from its exact source recipe.
        # It is a separate prerequisite and cannot be satisfied by new forms.
        footprint_fixture=selected/'tests/write_footprint';footprint_output=private/'footprint-oracle'
        footprint_rows=recipe(footprint_fixture/'oracle-build.sh','"$cc_bin"')
        need(len(footprint_rows)==1,'one unchanged footprint recipe')
        footprint_argv=expand(footprint_rows[0],{'$cc_bin':tools['cc'],'$selected_dir':selected,
            '$source_dir':footprint_fixture,'$archive':archive,'$output':footprint_output})
        footprint_units=[str(footprint_fixture/x) for x in ('oracle.c','oracle.S')]
        need([x for x in footprint_argv if x.endswith(('.c','.S'))]==footprint_units and
             [x for x in footprint_argv if x.endswith('.a')]==[str(archive)] and
             footprint_argv[-2:]==['-o',str(footprint_output)] and
             all(x in footprint_argv for x in ('-nostdlib','-static','-Wall','-Wextra','-Werror')) and
             not any(x.startswith('-Wno-') for x in footprint_argv),'complete old footprint source-owned strict recipe')
        footprint_flags=[x for x in footprint_argv[1:-2] if x not in footprint_units and x!=str(archive) and not x.startswith('-Wl,')]
        _,out,err,_=command('footprint-headers',[tools['cc'],*footprint_flags,'-M','-MT','li2_footprint',*footprint_units])
        rules=out.decode().replace('\\\n',' ').splitlines();footprint_headers={}
        need(not err and len(rules)==2,'both actual footprint compiler-M rules')
        for unit,line in zip(footprint_units,rules):
            need(line.startswith('li2_footprint: '),'exact footprint dependency target')
            names=shlex.split(line.split(':',1)[1]);need(unit in names,'actual footprint TU in its rule')
            for name in names:
                need(Path(name).is_absolute(),'absolute actual footprint dependency');p=pin(name)
                footprint_headers[name]=dict(resolved=str(p),**fact(p))
        need({str(selected/x) for x in ('decoder.h','write_footprint.h')}<=set(footprint_headers),'whole original footprint typed headers')
        _,out,err,_=command('footprint-build',footprint_argv,'native')
        need(out==err==b'','unchanged strict footprint recipe and original5/15 link bounds')
        artifact(footprint_output)
        footprint_elf=plain_executable(footprint_output)
        _,out,err,_=command('footprint-undefined',[tools['nm'],'-u',footprint_output])
        need(out==err==b'','no unresolved original footprint imports')
        r['footprint']['build']=dict(original_argv=footprint_argv,diagnostic_additions=[],headers=footprint_headers,
            elf=footprint_elf,binary=dict(path=str(footprint_output),**fact(footprint_output)))
        footprint_reader=pin(HERE/'footprint_read.py')
        for module in tuple(sys.modules.values()):
            p=getattr(module,'__file__',None)
            if p and Path(p).is_file():pin(p)
        maps=Path('/proc/self/maps').read_bytes();(private/'python-maps.txt').write_bytes(maps);artifact(private/'python-maps.txt')
        for line in maps.decode().splitlines():
            fields=line.split(None,5)
            if len(fields)==6 and fields[5].startswith('/'):
                need(not fields[5].endswith(' (deleted)'),'live Python mapped input');pin(fields[5])
        # Keep the complete old oracle gate before any helper observation.
        row,out,err,_=command('footprint-native',[footprint_output],'native',record=True,step=True)
        expected=load(footprint_fixture/'OUTCOMES.json')['commands'][0]
        need(out.decode()==expected['stdout'] and err==b'','exact original footprint stdout and clean stderr')
        _,out,err,_=command('footprint-read',[tools['python'],'-I','-S','-B',footprint_reader,
            private/'footprint-native.record'],'native')
        footprint=json.loads(out,object_pairs_hook=unique)
        need(not err and footprint['profile']=='page-selected-write-footprint-v1' and footprint['status']=='passed' and
             [footprint['result'][x] for x in ('cases','actual_instructions','supplied_refusals','api_controls',
               'old_cases','added_register_only_cases')]==[38,30,8,6,34,4] and footprint['result']['sealed_stats_unchanged'] is True and
             footprint['raw_bytes']==row['captures']['record']['bytes']==1270344 and
             footprint['raw_sha256']==row['captures']['record']['sha256'],'complete unchanged footprint reader/capture join')
        r['footprint'].update(status='passed',result=footprint['result'],raw=row['captures']['record'])
        # Four fixed independent chunks run once even if an earlier chunk or
        # reader fails. No incomplete observation becomes a successful case.
        for placement,chunk in ((0,0),(0,1),(1,0),(1,1)):
            key=str(placement)+'-'+str(chunk);result=r['chunks'][key];name='native-'+key
            child,data,err,ok=command(name,[output,str(placement),str(chunk)],'native',strict=False)
            result.update(status='failed',command=name,exit=child['exit'],raw=child.get('captures',{}).get('stdout'))
            if not child.get('reaped') or child.get('cleanup_errors'):
                raise ValueError('unsafe to proceed after incomplete native cleanup')
            readrow,observed,readerr,readok=command('read-'+key,[tools['python'],'-I','-S','-B',reader,
                private/(name+'.stdout'),'--exit-status',str(child['exit']),'--placement',str(placement),'--chunk',str(chunk),
                '--pid',str(child['pid']),'--cpu',str(args.cpu)],'native',strict=False)
            result['reader_command']=readrow['name']
            try:
                if ok and not err and readok and not readerr:
                    item=json.loads(observed,object_pairs_hook=unique)
                    need(item['profile']=='helper-tf-native-v1' and item['status']=='observed_unqualified' and
                         item['placement']==placement and item['chunk']==chunk and
                         [item[x] for x in ('cases','lanes','full_frames','successful_pairs','memory_fault_pairs',
                         'pending_x87_fault_pairs','original_tf_refusals','descriptor_controls')]==
                         [22,44,88,22 if chunk==0 else 10,0 if chunk==0 else 9,0 if chunk==0 else 3,47,469] and
                         item['raw_bytes']==len(data)==8491872 and item['raw_sha256']==hashlib.sha256(data).hexdigest() and
                         item['instruction_execution_at_original_pc'] is True and
                         all(item[x] is False for x in ('runtime_owner_credit','production_sigfpe_capture_credit',
                             'qualification_credit','performance_credit')),'full fixed helper reader/result/capture join')
                    h=__import__('struct').unpack_from('<64Q',data)
                    need(h[28]==inspected['reload_address'] and h[29]==inspected['scratch_end_address'] and
                         h[34]==inspected['handler_address'],'actual inspected bootstrap/handler raw address joins')
                    result.update(status='observed_unqualified',result=item)
            except Exception as e:result['error']=repr(e)
            save(receipt,r)
        need(all(x['status']=='observed_unqualified' for x in r['chunks'].values()),'all four original-bound helper chunks completed exactly')
        r['result']=dict(status='observed_unqualified',pairs=88,lanes=176,full_frames=352,
            successful_pairs=64,memory_fault_pairs=18,pending_x87_fault_pairs=6,
            descriptor_controls=1876,original_tf_refusals=188,old_footprint_cases=38,
            runtime_owner_credit=False,production_sigfpe_capture_credit=False,qualification_credit=False,performance_credit=False)
        r['status']='observed_unqualified'
    except Exception as e:r['error']=repr(e)
    finally:
        try:closure();r['inputs_unchanged']=True
        except Exception as e:r['final_errors'].append(repr(e));r['status']='failed'
        try:r['source_unchanged']=source()==r.get('source')
        except Exception as e:r['final_errors'].append(repr(e));r['source_unchanged']=False
        r['cleanup_complete']=all(x.get('reaped') is True and not x.get('cleanup_errors') and
            all(d['closed'] for d in x.get('descriptors',[])) for x in r['commands'])
        if not r['source_unchanged'] or not r['cleanup_complete']:r['status']='failed'
        save(receipt,r)
    print(json.dumps({k:r[k] for k in ('status','error','source_unchanged','inputs_unchanged','cleanup_complete')}),flush=True)
    return 0 if r['status']=='observed_unqualified' else 1

if __name__=='__main__':raise SystemExit(main())
