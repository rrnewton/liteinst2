#!/usr/bin/env python3
"""Run the whole old oracle, then exact source-extracted effects selection.

No alternate selector or admission predicate is implemented here. The original
script builds its unchanged default-profile fixture. Only the additional
selector and pair-advisory bodies are preprocessed for the effects profile;
their owner/permit observations remain the original descriptive test fixture.
"""
from pathlib import Path
import runpy
import sys

assert len(sys.argv)==3
selected=Path(sys.argv[1]).resolve();output=Path(sys.argv[2])
assert not output.exists()
old=selected/'tests/persistent_subentry/prepare.py'
namespace=runpy.run_path(str(old),run_name='__main__')
text=output.read_text()
marker='#include "tests/persistent_subentry/oracle.c"\n'
assert text.count(marker)==1
text=text.replace(marker,'#define main original_subentry_main\n'+marker+'#undef main\n')
body=namespace['body'];structure=namespace['structure']
source=(selected/'persistent_group_source.inc').read_text()
subsource=(selected/'persistent_subentry_source.inc').read_text()
selector=(selected/'persistent_subentry.inc').read_text()
text+="""
/* Exact effects selector/advisories, over the same complete old owner fixture.
   The original component above remains preprocessed in its original profile. */
#define LI2_PERSISTENT_LOOP_RUNTIME 1
#define LI2_PERSISTENT_LOOP_EFFECTS 1
#define li2_pg_source_pair_advisory effects_forward_advisory
#define li2_pgs_source_pair_advisory effects_pair_advisory
#define pe_sub_choice effects_sub_choice
#define pe_sub_choose effects_sub_choose
"""
text+=body(source,'static unsigned pgs_loop_owned_class(')
text+=body(source,'int li2_pg_source_pair_advisory(')
text+=body(subsource,'int li2_pgs_source_pair_advisory(')
text+=structure(selector,'pe_sub_choice')+body(selector,'static int pe_sub_choose(')
text+="""
#undef pe_sub_choose
#undef pe_sub_choice
#undef li2_pgs_source_pair_advisory
#undef li2_pg_source_pair_advisory
#undef LI2_PERSISTENT_LOOP_EFFECTS
#undef LI2_PERSISTENT_LOOP_RUNTIME
#include "tests/persistent_subentry_effects/oracle.c"
"""
output.write_text(text)
