"""Test-only observer call boundary; production sources have no injection hook."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
assert len(sys.argv) == 3
source, output = map(Path, sys.argv[1:])
output.mkdir(exist_ok=False)
owner = (source/'step_owner.c').read_bytes()
assert owner.count(b'#include "tf_owner.inc"') == 1
text = (source/'tf_owner.inc').read_bytes()
before = b'__attribute__((noinline)) int li2_tf_observe_shstk('
after = b'__attribute__((noinline)) int li2_tf_actual_observe_shstk('
assert text.count(before) == 1 and after not in text
changed = text.replace(before, after)
assert changed.replace(after, before) == text
for name, data in [('step_owner.c', owner), ('tf_owner.inc', changed)]:
    with (output/name).open('xb') as stream:
        stream.write(data)
