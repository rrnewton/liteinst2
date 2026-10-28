#!/usr/bin/env python3
"""Only exact authenticated support/chain adapters; no target execution."""
import hashlib,json,sys
from pathlib import Path
BASE_GENERIC = 'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910'
BASE_CHAIN = '9b3869630f23d6fb2b492a4d968fefa1bf13c0302379d8807a957ab5bb8d4c77'
GENERATED_GENERIC = '3f21a0ed42e34c459d3a510471dd1056f9282bbf2897b0dd583997ec7517cdb0'
GENERATED_CHAIN = '1f3272f9bf6a7e268b50a98ad9b9d86d0205e8619f7b856f0b65371ca1363f34'
GENERIC_OPERATIONS = [(b'static int dump(void) {\n    result.header_bytes=sizeof(result);result.sample_bytes=sizeof(struct sample);\n    return write_all(3,&result,sizeof(result)) && write_all(3,samples,sizeof(samples)) &&\n           write_all(3,&negative_sample,sizeof(negative_sample)) && write_all(3,&refused_last,sizeof(refused_last));\n}', b'static int dump(void) { return chain_dump(); }'), (b'long raw(long n,long a,long b,long c,long d,long e,long f) {', b'static long fixture_kernel_raw(long n,long a,long b,long c,long d,long e,long f) {'), (b'int fd=sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};', b'int fd=chain_sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};')]
CHAIN_OPERATIONS = [('#include <errno.h>', '#include <errno.h>\n#include "vector.inc"\nstatic void short_inputs(void);\nstatic void short_effects(void);'), ('#include "cases.h"', '#include "short_cases.h"'), ('return write_all(3,&li2_chain_record,sizeof li2_chain_record)&&write_all(3,&samples[0],sizeof samples[0])&&chain_control_dump();', 'return write_all(3,&li2_chain_record,sizeof li2_chain_record)&&write_all(3,&samples[0],sizeof samples[0])&&chain_control_dump()&&write_all(3,&vpb_observations,sizeof vpb_observations);'), ('chain_control_inputs();fixture_target=li2_chain_record.pc;', 'chain_control_inputs();short_inputs();fixture_target=li2_chain_record.pc;'), ('#include "controls.inc"', '#include "tests/trace_chain/controls.inc"\n#include "connected_extra.inc"'), ('chain_parse_environment(stack);li2_chain_record.case_id=case_id;li2_chain_record.mode=mode;', 'chain_parse_environment(stack);need(!mode&&case_id>=12&&case_id<14,1300);li2_chain_record.case_id=case_id;li2_chain_record.mode=mode;'), ('setup(stack);size_t complete=0,failed=0;uint32_t rc=0;', 'setup(stack);vpb_layout();vpb_seed();vpb_observations.group=case_id-9;size_t complete=0,failed=0;uint32_t rc=0;'), ('compare_program();need(li2_chain_record.completed_lanes==3', 'compare_program();short_effects();need(li2_chain_record.completed_lanes==3'), ('sizeof(li2_chain_record)+sizeof(samples[0])+sizeof(ctl)<16*1024*1024', 'sizeof(li2_chain_record)+sizeof(samples[0])+sizeof(ctl)+sizeof(vpb_observations)<16*1024*1024')]

def main():
    selected=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
    receipts=[]
    for name,source,expected,operations,after in (
        ('chain_support.inc',selected/'tests/generic/fixture.c',BASE_GENERIC,GENERIC_OPERATIONS,GENERATED_GENERIC),
        ('connected_body.inc',selected/'tests/trace_chain/fixture.c',BASE_CHAIN,CHAIN_OPERATIONS,GENERATED_CHAIN)):
        before=source.read_bytes();value=before
        if hashlib.sha256(value).hexdigest()!=expected:raise ValueError('exact source '+str(source))
        for old,new in operations:
            if isinstance(old,str):old,new=old.encode(),new.encode()
            if value.count(old)!=1:raise ValueError('unique exact adapter '+name)
            value=value.replace(old,new)
        if hashlib.sha256(value).hexdigest()!=after:raise ValueError('exact generated '+name)
        with (out/name).open('xb') as stream:stream.write(value)
        if source.read_bytes()!=before or (out/name).read_bytes()!=value:raise ValueError('source/generated closure')
        receipts.append(dict(name=name,bytes=len(value),sha256=after))
    print(json.dumps(receipts,sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
