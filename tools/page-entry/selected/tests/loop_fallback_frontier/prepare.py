#!/usr/bin/env python3
"""Extract the actual deterministic history helper; retain the whole old oracle."""
from pathlib import Path
import sys

assert len(sys.argv)==3
selected=Path(sys.argv[1]).resolve();output=Path(sys.argv[2])
assert not output.exists()
source=(selected/'persistent_loop_owner.inc').read_text()
start=source.index('static int plr_fallback_destination(')
brace=source.index('{',start);depth=1;end=brace+1
while depth:
    depth+=(source[end]=='{')-(source[end]=='}');end+=1
body=source[start:end]+'\n'
# The historical head-only loop rejects every boundary token before choosing a
# destination. Derive that exact old decision from the real helper, rather
# than writing a second implementation of the new frontier semantics.
a=body.index('    /* Ordinary unsupported fallthrough frontier: exact source identity. */')
b=body.index('    /* Existing generated-head and capacity-link destinations stay exact. */')
prior=(body[:a]+body[b:]).replace('plr_fallback_destination','prior_fallback_destination',1)
prior=prior.replace('    const struct li2_span_decoded *d=&g->original[head];\n','',1)
assert 'if(k>=g->heads)return 0;' in prior and 'g->exit_pc[x]' not in prior
original=(selected/'tests/loop_fused_far/oracle.c').read_text()
assert original.count('int main(void) {')==1
text=original.replace('int main(void) {','int original_lpf_main(void) {',1)
text+=body+prior+'#include "tests/loop_fallback_frontier/oracle.c"\n'
output.write_text(text)
