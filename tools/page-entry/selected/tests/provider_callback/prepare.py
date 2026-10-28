#!/usr/bin/env python3
"""Generate only a callback probe from the exact retained provider fixture."""
import argparse,hashlib,json
from pathlib import Path

def generate(donor,output):
    donor=Path(donor);output=Path(output);output.mkdir(parents=True,exist_ok=False)
    here=Path(__file__).resolve().parent
    source=(donor/'probe.c').read_text();before=source
    assert hashlib.sha256(before.encode()).hexdigest()=='f2bc12cd53d74014c0ca46fc818f78b553b8166a14ae3a07cbb0b653b373fabd',"exact predecessor probe"
    operations=[]
    def replace(a,b):
        nonlocal source
        assert source.count(a)==1,a
        operations.append({'before':a,'after':b});source=source.replace(a,b)
    replace('static void handler(int sig,siginfo_t *si,void *opaque) {',
            '#include "callback.inc"\nstatic void handler(int sig,siginfo_t *si,void *opaque) {')
    replace('    if(in_handler)nested(sig,si,uc);',
            '    if(in_handler && control==50)callback_nested(sig,si,uc);\n    if(in_handler)nested(sig,si,uc);')
    replace('li2_selected_complete_scripted(uc,&request,control==32?0:&script,&completion)',
            'callback_complete(uc,&request,control==32?0:&script,&completion)')
    replace('reg<16 && control<=48 && layout<=1 && prefix<=6',
            'reg<16 && control<=54 && control!=52 && layout<=1 && prefix<=6')
    replace('    singleton();require(!fixture_xstate_prepare(),4,1);',
            '    require(mechanism==2,70,3);\n    callback_controls();\n    singleton();require(!fixture_xstate_prepare(),4,1);')
    replace('    for(size_t i=0;i<STACK_BYTES;i++)',
            '    const char *callback_df=getenv("LI2_FIXTURE_CALLBACK_DF");\n    if(callback_df){require(fixture_equal(callback_df,"1",2),70,4);fixture_input[16]|=UINT64_C(0x400);}\n    for(size_t i=0;i<STACK_BYTES;i++)')
    replace('mechanism==2 && kind!=4 && !control',
            'mechanism==2 && kind!=4 && (!control || control==53)')
    replace('    require(!munmap(program,3*PAGE)',
            '    callback_record(1);\n    require(!munmap(program,3*PAGE)')
    back=source
    for row in reversed(operations):
        assert back.count(row['after'])==1;back=back.replace(row['after'],row['before'])
    assert back==before
    (output/'probe.c').write_text(source)
    # The generated probe is compiled with the donor's fixture header/ASM and
    # complete state helpers; no copy or modification of those helpers.
    (output/'callback.inc').write_bytes((here/'callback.inc').read_bytes())
    (output/'operations.json').write_text(json.dumps({'donor_sha256':hashlib.sha256(before.encode()).hexdigest(),'operations':operations},separators=(',',':'))+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--donor',required=True);p.add_argument('--output',required=True)
    a=p.parse_args();generate(a.donor,a.output)
