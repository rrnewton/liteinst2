#!/usr/bin/env python3
"""Exact instrumentation-only views; all real guards and branches survive inverse."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
SOURCES = [{'source': 'tests/generic/fixture.c', 'target': 'repeat_lease_support.inc', 'before_sha256': 'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910', 'after_sha256': '071e1a4ca63b1c62763d9ca6c111794bb47f65add3a508ae1a388e68a391ac56', 'before_bytes': 34870, 'after_bytes': 34624, 'edits': [('static int dump(void) {\n    result.header_bytes=sizeof(result);result.sample_bytes=sizeof(struct sample);\n    return write_all(3,&result,sizeof(result)) && write_all(3,samples,sizeof(samples)) &&\n           write_all(3,&negative_sample,sizeof(negative_sample)) && write_all(3,&refused_last,sizeof(refused_last));\n}', 'static int dump(void) { return rl_dump(); }'), ('long raw(long n,long a,long b,long c,long d,long e,long f) {', 'static long fixture_kernel_raw(long n,long a,long b,long c,long d,long e,long f) {'), ('int fd=sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};', 'int fd=rl_sealed_elf();const struct li2_lifecycle_hooks hooks={raw,lifecycle_fail,protected_range};')]}, {'source': 'step_owner.c', 'target': 'step_owner.c', 'before_sha256': '6b3aebbf6cf39712c238ffaf8e29bd334cc950c68381a8b4b465e9ac40b9124d', 'after_sha256': 'b0a8e979629a205ff12637bb3d661a3dd3df9690278afba8d8e8f8ecc05d2193', 'before_bytes': 14644, 'after_bytes': 14726, 'edits': [('#include "step_owner.h"', '#include "step_owner.h"\nextern void rl_revoke_observe(struct li2_step_owner *);'), ('    o->phase=LI2_STEP_REVOKING;', '    o->phase=LI2_STEP_REVOKING;\n    rl_revoke_observe(o);')]}, {'source': 'repeat_lease.inc', 'target': 'repeat_lease.inc', 'before_sha256': 'ba25605c8c653acaf276b7fbc43e6bbfea1d529a26413d9a6d05901d48433799', 'after_sha256': '425f2cbfd999f1c233f52b3da52deee89dfe4674e512ea35b37d5f7f1fbe60f1', 'before_bytes': 22044, 'after_bytes': 22206, 'edits': [('#include "repeat_custody.h"', '#include "repeat_custody.h"\nextern void rl_guard_observe(struct li2_repeat_lease_owner *,const ucontext_t *);\nextern int rl_release_observe(const struct li2_fetch_ref *);'), ('static void repeat_lease_write(struct li2_repeat_lease_owner *o,const ucontext_t *uc) {', 'static void repeat_lease_write(struct li2_repeat_lease_owner *o,const ucontext_t *uc) {\n    rl_guard_observe(o,uc);'), ('o->release_result=li2_lifecycle_fetch_release(&o->borrow);', 'o->release_result=rl_release_observe(&o->borrow);')]}, {'source': 'repeat_custody.inc', 'target': 'repeat_custody.inc', 'before_sha256': '06ee770614e50be9dafe530bd002a3087d5daee5d45037bcdb28dc21d0b92bd5', 'after_sha256': 'fa0db7d4e05c34a2d2140d17caae2280d54a03ba215038dd11b6b87190c928b0', 'before_bytes': 25870, 'after_bytes': 25956, 'edits': [('#include "register_run_publish.h"', '#include "register_run_publish.h"\nextern void rl_seed_observe(struct li2_repeat_lease_owner *);'), ('    if((e=rep_phase(LI2_REP_CUSTODY_BOUND,LI2_REP_CUSTODY_SEEDING)))return e;', '    if((e=rep_phase(LI2_REP_CUSTODY_BOUND,LI2_REP_CUSTODY_SEEDING)))return e;\n    rl_seed_observe(o);')]}, {'source': 'lifecycle_loader.c', 'target': 'lifecycle_loader.c', 'before_sha256': 'c8cf9246878ceb1c51c8ebeded3716706b4b47dc7396b9e255122a2ea574a8be', 'after_sha256': 'c8cf9246878ceb1c51c8ebeded3716706b4b47dc7396b9e255122a2ea574a8be', 'before_bytes': 44237, 'after_bytes': 44237, 'edits': []}]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('selected',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();observed=[]
    for row in SOURCES:
        source=a.selected/row['source'];before=source.read_bytes()
        if len(before)!=row['before_bytes'] or hashlib.sha256(before).hexdigest()!=row['before_sha256']:
            raise ValueError('exact current source for instrumentation: '+row['source'])
        after=before
        for old,new in row['edits']:
            old,new=old.encode(),new.encode()
            if after.count(old)!=1:raise ValueError('exact unique instrumentation span')
            after=after.replace(old,new)
        if len(after)!=row['after_bytes'] or hashlib.sha256(after).hexdigest()!=row['after_sha256']:
            raise ValueError('whole generated source identity')
        target=a.output/row['target']
        with target.open('xb')as f:f.write(after)
        if source.read_bytes()!=before or target.read_bytes()!=after:raise ValueError('source and adapter closure')
        observed.append({k:row[k]for k in ('source','target','before_sha256','after_sha256','before_bytes','after_bytes')})
    print(json.dumps(observed,sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
