"""Copy actual committed product inputs and apply only test observation adapters."""
import json
from pathlib import Path
from page_selected import fact, need
from page_selected_rseq_compare import decode

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'tools/page-entry/selected/tests/rseq_application'
CATALOG = ROOT/'evaluation/inprocess/page_selected_rseq_inputs.json'


def validate(pin):
    manifest = decode(pin(CATALOG).read_bytes())
    for row in manifest['inputs']:
        need(fact(pin(ROOT/row['path'])) == {k: row[k] for k in ('bytes', 'sha256')},
             'exact committed rseq input '+row['path'])
    return manifest


def prepare(out, pin):
    manifest = validate(pin)
    out = Path(out).resolve()
    need(out.is_relative_to(ROOT/'target') and not out.exists(), 'unique private fixture source copy')
    out.mkdir(parents=True)
    for row in manifest['runtime_sources']:
        p = pin(ROOT/row['path'])
        need(fact(p) == {k: row[k] for k in ('bytes', 'sha256')}, 'current unobserved source before test copy')
        q = out/row['path']; q.parent.mkdir(parents=True, exist_ok=True); q.write_bytes(p.read_bytes())
    for operation in decode(pin(FIXTURE/'ADAPTERS.json').read_bytes()):
        p = out/operation['path']; b = p.read_bytes()
        before, after = operation['before'].encode(), operation['after'].encode()
        need(b.count(before) == operation['count'], 'exact test-only observation adapter')
        p.write_bytes(b.replace(before, after))
    selected = out/'tools/page-entry/selected'
    for name in ('observe.h', 'observe.c'):
        (selected/name).write_bytes(pin(FIXTURE/name).read_bytes())
    rows = [dict(path=str(out/r['path']), **fact(out/r['path'])) for r in manifest['runtime_sources']]
    rows += [dict(path=str(selected/n), **fact(selected/n)) for n in ('observe.h', 'observe.c')]
    (out/'COMPOSITION.json').write_text(json.dumps(dict(catalog=fact(CATALOG), sources=rows), sort_keys=True, indent=2)+'\n')
    return selected
