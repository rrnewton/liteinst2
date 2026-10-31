"""Actual eligibility/close/ticket predicates; external observations are scripted."""
import sys
from pathlib import Path

selected = Path(sys.argv[1]).resolve(strict=True)
output = Path(sys.argv[2])
chain = (selected / 'tf_chain.inc').read_text()
span = (selected / 'tf_span_transfer.inc').read_text()

def cross_enabled(text):
    # Resolve only this exact feature; preserve all other compiler conditionals.
    stack = []
    result = []
    for line in text.splitlines(keepends=True):
        directive = line.strip()
        if directive.startswith(('#if ', '#ifdef ', '#ifndef ')):
            selected = directive == '#ifdef LI2_PERSISTENT_CROSS_PAIR'
            stack.append([selected, True])
            if selected:
                continue
        elif directive == '#else' and stack and stack[-1][0]:
            stack[-1][1] = not stack[-1][1]
            continue
        elif directive == '#endif':
            selected = stack.pop()[0]
            if selected:
                continue
        if all(not selected or enabled for selected, enabled in stack):
            result.append(line)
    assert not stack
    return ''.join(result)

def function(text, name):
    # The selected names each have one definition, and no string/comment braces.
    import re
    match = re.search(r'^(?:static )?(?:int|void|struct li2_tf_chain_slot \*)\s*' +
                      re.escape(name) + r'\(', text, re.M)
    assert match, name
    start = match.start()
    brace = text.index('{', match.end())
    depth, end = 1, brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

span = cross_enabled(span)
start = span.index('struct li2_tf_span_transfer {')
end = span.index('static int span_error(', start)
parts = [span[start:end]]
for name in ('chain_registered_ok', 'chain_slot', 'chain_need', 'chain_count',
             'chain_observe', 'chain_frame_equal', 'chain_trace_closed',
             'chain_closed', 'chain_release'):
    parts.append(function(chain, name))
for name in ('span_error', 'span_page_equal', 'span_frame_equal', 'span_origin',
             'li2_tf_chain_span_cross_page_eligible', 'span_close',
             'li2_tf_chain_span_close', 'li2_tf_chain_span_close_cross_page',
             'span_fresh', 'li2_tf_chain_span_consume'):
    parts.append(function(span, name))
assert parts[-5].count('if(pc<page || pc-page>LI2_STEP_PAGE-15)return LI2_ST_ORIGIN;') == 1
oracle = (Path(__file__).resolve().parent / 'oracle.c').read_text()
assert oracle.count('/* ACTUAL_SOURCE */') == 1
with output.open('x') as stream:
    stream.write(oracle.replace('/* ACTUAL_SOURCE */', '\n\n'.join(parts)))
