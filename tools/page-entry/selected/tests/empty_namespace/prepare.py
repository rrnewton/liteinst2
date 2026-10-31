"""Extract actual source predicates and callers; only environment/kernel transport is scripted."""
import sys
from pathlib import Path

selected=Path(sys.argv[1]).resolve(strict=True)
output=Path(sys.argv[2])
life=(selected/'lifecycle_loader.c').read_text()
runtime=(selected/'runtime_loader.c').read_text()

def function(text,name):
    pos=text.index(name+'(')
    begin=text.rfind('\n',0,pos)+1
    brace=text.index('{',pos); depth=1; end=brace+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[begin:end]

start=life.index('/* Empty dependency namespace:')
end=life.index('/* End empty dependency source proof. */',start)+len('/* End empty dependency source proof. */')
parts=[life[start:end],function(runtime,'parse_fds'),function(life,'li2_lifecycle_initialize'),function(life,'li2_lifecycle_initialize_empty')]
oracle=(Path(__file__).resolve().parent/'oracle.c').read_text()
assert oracle.count('/* ACTUAL_SOURCE */')==1
with output.open('x')as stream:stream.write(oracle.replace('/* ACTUAL_SOURCE */','\n\n'.join(parts)))
