"""Extract actual old/new predicates; preserve the complete old216 fixture."""
import re
import sys
from pathlib import Path

selected = Path(sys.argv[1]).resolve(strict=True)
output = Path(sys.argv[2])

def enabled(text):
    result, stack = [], []
    for line in text.splitlines(keepends=True):
        directive = line.strip()
        if directive.startswith(('#if ', '#ifdef ', '#ifndef ')):
            chosen = directive in ('#ifdef LI2_PERSISTENT_CROSS_PAIR',
                                   '#ifdef LI2_PERSISTENT_DIRECT_FRONTIER')
            stack.append([chosen, True])
            if chosen:
                continue
        elif directive == '#else' and stack and stack[-1][0]:
            stack[-1][1] = not stack[-1][1]
            continue
        elif directive == '#endif':
            chosen = stack.pop()[0]
            if chosen:
                continue
        if all(not chosen or active for chosen, active in stack):
            result.append(line)
    assert not stack
    return ''.join(result)

def function(text, name):
    pattern = r'^(?:static )?(?:int|void|struct li2_tf_chain_slot \*)\s*' + re.escape(name) + r'\('
    found = list(re.finditer(pattern, text, re.M))
    assert len(found) == 1, name
    match = found[0]
    brace = text.index('{', match.end())
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end]

chain = (selected/'tf_chain.inc').read_text()
span = enabled((selected/'tf_span_transfer.inc').read_text())
start = span.index('struct li2_tf_span_transfer {')
end = span.index('static int span_error(', start)
parts = [span[start:end]]
for name in ('chain_registered_ok', 'chain_slot', 'chain_need', 'chain_count',
             'chain_observe', 'chain_frame_equal', 'chain_trace_closed', 'chain_closed', 'chain_release'):
    parts.append(function(chain, name))
for name in ('span_error', 'span_page_equal', 'span_frame_equal', 'span_origin',
             'li2_tf_chain_span_cross_page_eligible', 'li2_tf_chain_span_direct_eligible',
             'span_close', 'li2_tf_chain_span_close', 'li2_tf_chain_span_close_cross_page',
             'li2_tf_chain_span_close_direct', 'span_fresh', 'li2_tf_chain_span_consume'):
    parts.append(function(span, name))
assert function(span, 'span_close').count('if(pc<page || pc-page>LI2_STEP_PAGE-15)return LI2_ST_ORIGIN;') == 1
old = (selected/'tests/cross_page_handoff/oracle.c').read_text()
assert old.count('/* ACTUAL_SOURCE */') == 1 and old.count('int main(void)') == 1
extra = (Path(__file__).resolve().parent/'oracle.c').read_text()
with output.open('x') as stream:
    stream.write('#define LI2_PERSISTENT_DIRECT_FRONTIER 1\n#define main inherited_cross_page_main\n')
    stream.write(old.replace('/* ACTUAL_SOURCE */', '\n\n'.join(parts)))
    stream.write('\n#undef main\n')
    stream.write(extra)
