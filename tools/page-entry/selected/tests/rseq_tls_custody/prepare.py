#!/usr/bin/env python3
"""Actual loader/maps and whole rseq owner; supplied component boundaries only."""
from pathlib import Path
import hashlib,json,sys

assert len(sys.argv)==3
selected=Path(sys.argv[1]).resolve(strict=True);out=Path(sys.argv[2])
assert out.is_dir() and not any(out.iterdir())
donor=selected/'tests/maps_current_custody/oracle.c'
text=donor.read_text();loader=(selected/'lifecycle_loader.c').read_text()
needle='#include "maps_phase.inc"\n';assert loader.count(needle)==1
# Select the real resident TLS maps branch without fabricating a resident
# lifecycle or importing unrelated persistent/native owners into this fixture.
loader=loader.replace(needle,'#define LI2_RESIDENT_SOURCE_LEASE 1\n'
    '#include "rseq_guard.h"\n'+needle+'#undef LI2_RESIDENT_SOURCE_LEASE\n',1)
assert loader.replace('#define LI2_RESIDENT_SOURCE_LEASE 1\n#include "rseq_guard.h"\n'+needle+
    '#undef LI2_RESIDENT_SOURCE_LEASE\n',needle,1)==(selected/'lifecycle_loader.c').read_text()

def function(name):
    import re
    found=list(re.finditer(r'^(?:static )?(?:_Noreturn )?(?:long|void|int) '+name+r'\([^;]*?\) \{',text,re.M))
    assert len(found)==1,name
    start=found[0].start();at=text.index('{',start);depth=1;end=at+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]+'\n'

names=('kernel','tracked','need','fatal','li2_decoder_abort','equal','protected_none',
       'authenticate','owner_failure','decoded','setup')
pieces={n:function(n)for n in names}
setup=pieces['setup']
old='    li2_maps_view_stack(anchor);need(!li2_maps_view_enable(),941);\n'
assert setup.count(old)==1
setup=setup.replace(old,'#ifdef LI2_MAPS_MAINTAINED\n'+old+'#else\n    (void)anchor;\n#endif\n',1)
old='    observe(SETUP,0);need(!custody_owner_live(&owner_key,&borrow,1),948);'
assert setup.count(old)==1
setup=setup.replace(old,'    need(!custody_owner_live(&owner_key,&borrow,1),948);',1)
pieces['setup']=setup
for name,data in {'loader.inc':loader,'support.inc':''.join(pieces.values()),
                  'rseq.c':'#define LI2_RESIDENT_SOURCE_LEASE 1\n#include "rseq_guard.c"\n'}.items():
    (out/name).write_text(data)
facts={str(p):dict(bytes=len(p.read_bytes()),sha256=hashlib.sha256(p.read_bytes()).hexdigest())
       for p in (donor,selected/'lifecycle_loader.c',selected/'rseq_guard.c',selected/'rseq_guard.h',
                 selected/'maps_phase.inc',selected/'maps_view.inc')}
(out/'source.json').write_text(json.dumps(dict(inputs=facts,whole_rseq_owner=True,
    exact_donor_helpers=list(names[:-1]),setup_delta='maintained-only stack enable; separate new observation',
    loader_delta='resident selector only around actual maps include',component_only=True),sort_keys=True)+'\n')
