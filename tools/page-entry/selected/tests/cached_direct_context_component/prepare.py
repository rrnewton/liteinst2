#!/usr/bin/env python3
"""Extract production types/lookup verbatim; no compiler or candidate import."""
from pathlib import Path
import hashlib
import sys

assert len(sys.argv) == 4
selected = Path(sys.argv[1]).resolve(strict=True)
fixture = Path(sys.argv[2]).resolve(strict=True)
output = Path(sys.argv[3])
assert output.is_dir()
for name, size, sha in (
    ('machine.S', 6550, 'cbebaf8c474c35afab10c7cc7af66914c562e86cdc12f8f681eeb192f0a353b5'),
    ('app.ld', 2125, '76b2b9dde34c951c985745e5fef5b256cc4e313c3202b250044e933215b88b6e')):
    value = (fixture/name).read_bytes()
    assert len(value) == size and hashlib.sha256(value).hexdigest() == sha


def body(source, signature):
    assert source.count(signature) == 1, signature
    start = source.index(signature); opening = source.index('{', start)
    depth = 1; end = opening+1
    while depth:
        depth += (source[end] == '{')-(source[end] == '}'); end += 1
    return source[start:end]+'\n'


controller = (selected/'persistent_group_controller.inc').read_text()
subentry = (selected/'persistent_subentry_source.inc').read_text()
literal = '#define PE_PROOF_BYTES ((sizeof(struct pe_payload)+PAGE-1U)&~(PAGE-1U))'
assert controller.splitlines().count(literal) == 1
text = ('/* Actual production declarations and whole legal-head lookup. */\n'
        '#include "persistent_group_runtime.h"\n#define PAGE 4096U\n')
for name in ('pe_header', 'pe_payload'):
    text += body(controller, 'struct '+name+' {').rstrip()+';\n'
text += literal+'\n'+body(subentry, 'int li2_pgs_head_lookup(')
with (output/'actual.inc').open('x') as stream: stream.write(text)
# These macro values select the actual types. They are not an archive/runtime
# binding: this component has no controller, source query, seal, entry or RAW TU.
config = '#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
for name, value in (
    ('LI2_PG_BINDING_VERSION', 1), ('LI2_PG_GROUP_BINDING_VERSION', 4),
    ('LI2_PG_LOOP_RO_BINDING_VERSION', 1), ('LI2_PG_LOOP_RESIDENT_RX_BINDING_VERSION', 1),
    ('LI2_PG_LOOP_CACHE8_BINDING_VERSION', 1), ('LI2_PG_LOOP_GROUP_DESCRIPTOR_BINDING_VERSION', 1),
    ('LI2_PG_LOOP_TRANSLATION_ARENA_BINDING_VERSION', 1), ('LI2_PG_LOOP_CACHED_DIRECT_CONTEXT_BINDING_VERSION', 1)):
    config += '#define '+name+' '+str(value)+'\n'
config += '#endif\n'
with (output/'persistent_group_config.h').open('x') as stream: stream.write(config)
