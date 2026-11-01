"""One bounded standalone policy oracle; no runtime-owner or equivalence credit."""
import sys
sys.dont_write_bytecode=True
import argparse,hashlib,json,os,shlex,shutil,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV,need,save
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand

SOURCES=('tf_nx_page_boundary.h','tf_chain.h','tf_owner.h','step_owner.h','decoder.h',
        'tf_continuation.h','tf_entry_route.h','lifecycle_loader.h',
        'tests/tf_nx_page_boundary/oracle.c','tests/tf_nx_page_boundary/build.sh')
BUILD=[30,512<<20,16<<20,60]
NATIVE=[5,512<<20,16<<20,15]
EXPECTED=b'LI2_TF_NX_PAGE_BOUNDARY cases=57 geometry=32 declined=15 malformed=10\n'

def fact(path):
    p=Path(path);b=p.read_bytes()
    return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=format(p.stat().st_mode&0o777,'04o'))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cpu',type=int,required=True);p.add_argument('--expect-revision',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();out=a.output.absolute()
    need(not sys.flags.optimize and a.cpu>=0 and sorted(os.sched_getaffinity(0))==[a.cpu],
         'assertions and exact externally reserved CPU')
    need(out.parent==ROOT/'target/evaluation/inprocess' and not out.exists(),'fresh direct output child')
    out.mkdir();receipt=out/'receipt.json'
    r=dict(schema=1,profile='tf-nx-page-boundary-oracle-v1',status='failed',cpu=a.cpu,
        revision=a.expect_revision,source=source(),hardware=hardware(a.cpu),commands=[],inputs={},aliases={},artifacts={},
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,error=None,final_errors=[],
        runtime_owner_credit=False,equivalence_credit=False,qualification_credit=False,performance_credit=False)
    def pin(path):
        alias=Path(path).absolute();q=alias.resolve(strict=True);v=fact(q)
        need(str(q)not in r['inputs']or r['inputs'][str(q)]==v,'stable whole input')
        need(str(alias)not in r['aliases']or r['aliases'][str(alias)]==str(q),'stable input alias')
        r['inputs'][str(q)]=v;r['aliases'][str(alias)]=str(q);return q
    def artifact(path):
        q=Path(path).resolve(strict=True);need(q.is_relative_to(out),'owned artifact')
        v=fact(q);need(str(q)not in r['artifacts']or r['artifacts'][str(q)]==v,'stable whole artifact')
        r['artifacts'][str(q)]=v;return q
    def closure():
        need(all(fact(k)==v for k,v in r['inputs'].items()),'whole inputs unchanged')
        need(all(str(Path(k).resolve(strict=True))==v for k,v in r['aliases'].items()),'literal aliases unchanged')
        need(all(fact(k)==v for k,v in r['artifacts'].items()),'whole artifacts unchanged')
        need(sorted(os.sched_getaffinity(0))==[a.cpu],'same reserved CPU')
    def command(name,argv,native=False):
        closure();need(not any(v['name']==name for v in r['commands']),'one fixed command, no retry')
        row=dict(name=name,argv=list(map(str,argv)),bounds=NATIVE if native else BUILD,
                 environment=dict(ENV),capture_limit=16<<20,expected_exit=0)
        r['commands'].append(row);save(receipt,r)
        try:stdout,stderr=invoke(row,out,a.cpu)
        finally:
            for v in row.get('captures',{}).values():artifact(out/v['file'])
            save(receipt,r)
        need(row['exit']==0,'successful bounded '+name)
        return stdout,stderr
    try:
        need(r['source']['revision']==a.expect_revision and r['source']['tracked_clean'] is True and
             r['source']['head_sources_match'] is True,'exact clean installed revision')
        pin(__file__);selected=ROOT/'tools/page-entry/selected';origins={}
        for name in SOURCES:
            path=selected/name
            need(path.is_file() and not path.is_symlink(),'regular installed oracle source')
            origin=pin(path);origins[name]=dict(path=str(origin),**fact(origin))
        r['selected_sources']=origins
        cc=pin(shutil.which('cc',path=ENV['PATH']));r['compiler']=dict(path=str(cc),**fact(cc))
        for name in ('cc1','collect2','as','ld'):
            stdout,stderr=command('tool-'+name,[cc,'-print-prog-name='+name]);value=stdout.decode().strip()
            need(value and not stderr,'one compiler-selected tool')
            pin(value if Path(value).is_absolute() else shutil.which(value,path=ENV['PATH']))
        for module in tuple(sys.modules.values()):
            q=getattr(module,'__file__',None)
            if q and Path(q).is_file():pin(q)
        fixture=selected/'tests/tf_nx_page_boundary'
        rows=recipe(fixture/'build.sh','"$cc_bin"');need(len(rows)==1,'one source-owned pure oracle recipe')
        argv=expand(rows[0],{'$cc_bin':cc,'$selected_dir':selected,'$fixture_dir':fixture,'$output':out})
        unit=str(fixture/'oracle.c');binary=out/'tf-nx-page-boundary-oracle'
        need([x for x in argv if x.endswith(('.c','.S'))]==[unit]and argv[-2:]==['-o',str(binary)]and
             [x for x in argv if x.startswith('-D')]==['-DLI2_TF_NX_PAGE_BOUNDARY=1'],
             'exact one-TU source, macro and output')
        flags=[x for x in argv[1:-2]if x!=unit and not x.startswith('-Wl,')]
        stdout,stderr=command('headers',[cc,*flags,'-M','-MT','li2_boundary',unit])
        lines=stdout.decode().replace('\\\n',' ').splitlines()
        need(not stderr and len(lines)==1 and lines[0].startswith('li2_boundary: '),'one complete actual-M rule')
        deps=shlex.split(lines[0].split(':',1)[1]);need(deps[0]==unit,'actual source heads dependency rule')
        need(all(Path(v).is_absolute()for v in deps),'absolute complete header paths')
        r['headers']={v:dict(path=str(pin(v)),**fact(v))for v in deps}
        need({str(selected/v)for v in SOURCES if v.endswith('.h')}<=set(deps),'all expected actual typed headers')
        stdout,stderr=command('build',argv);need(stdout==stderr==b'','strict source-owned build diagnostics')
        artifact(binary);b=binary.read_bytes();need(b[:7]==b'\x7fELF\2\1\1'and struct.unpack_from('<HH',b,16)==(2,62),'static x86-64 ELF')
        offset=struct.unpack_from('<Q',b,32)[0];size,count=struct.unpack_from('<HH',b,54)
        need(size==56 and 0<count<=32 and offset+size*count<=len(b),'bounded whole program headers')
        ph=[struct.unpack_from('<IIQQQQQQ',b,offset+size*i)for i in range(count)]
        need(not any(v[0]in(2,3,7)for v in ph)and all(v[1]&7!=7 for v in ph if v[0]==1),
             'no interpreter, dynamic dependencies, TLS or writable executable LOAD')
        r['binary']=dict(path=str(binary),**fact(binary))
        stdout,stderr=command('oracle',[binary],native=True)
        need(stdout==EXPECTED and stderr==b'','exact57 policy observations without diagnostics')
        need([v['name']for v in r['commands']]==['tool-cc1','tool-collect2','tool-as','tool-ld','headers','build','oracle'],
             'all seven fixed bounded commands')
        r['result']=dict(cases=57,geometry=32,declined=15,malformed=10);r['status']='policy_observed'
    except Exception as e:r['error']=repr(e)
    finally:
        try:closure();r['inputs_unchanged']=True
        except Exception as e:r['final_errors'].append(repr(e))
        try:r['source_unchanged']=source()==r['source']
        except Exception as e:r['final_errors'].append(repr(e))
        r['cleanup_complete']=all(v.get('reaped')is True and not v.get('cleanup_errors')and
            all(x.get('closed')is True for x in v.get('descriptors',[]))for v in r['commands'])
        if not(r['inputs_unchanged']and r['source_unchanged']and r['cleanup_complete'])or r['final_errors']:r['status']='failed'
        save(receipt,r)
    return 0 if r['status']=='policy_observed'else 1

if __name__=='__main__':raise SystemExit(main())
