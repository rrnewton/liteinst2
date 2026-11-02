#!/usr/bin/env python3
"""Use the actual local adapter and unchanged identity predicate, not copies."""
from pathlib import Path
import sys

assert len(sys.argv) == 3
selected = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2])
assert not output.exists()


def function(path, name):
    text = path.read_text()
    token = 'static int '+name+'('
    assert text.count(token) == 1
    start = text.index(token)
    brace = text.index('{', start)
    depth, end = 1, brace+1
    while depth:
        depth += (text[end] == '{')-(text[end] == '}')
        end += 1
    return text[start:end]+'\n'


text = ('#define main original_current_custody_main\n'
        '#include "tests/maps_current_custody/oracle.c"\n#undef main\n'
        '#include "rseq_current_data.h"\n')
text += function(selected/'rseq_native_pair.inc', 'np_rseq_data')
text += function(selected/'rseq_guard.c', 'same_data')
text += '#include "tests/rseq_pair_current/oracle.c"\n'
output.write_text(text)
