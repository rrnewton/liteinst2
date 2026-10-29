"""Custody-only observation view; all product mutations have exact inverses."""
from pathlib import Path
import importlib.util
from page_selected import fact, need

STORAGE = ('static struct lso_record lso_record;',
           '#include "page_custody_record.h"\nstatic struct cso_stream cso_stream;\n#define lso_record cso_stream.base')
ADAPTERS = (
    ('runtime_loader.c', '#include "tf_lease_observe.inc"', '#include "page_custody_observe.inc"'),
    ('runtime_loader.c', '    li2_tf_chain_handler_end(&selected_chain);',
     '    cso_handler_end(&selected_chain,sig,si,ptr);'),
    ('fetch_rx_transfer.inc', '#include "tf_same_page.h"',
     '#include "tf_same_page.h"\nextern void cso_fetch_phase(unsigned,const struct li2_fetch_ref *,const struct li2_fetch_rx_view *);'),
    ('fetch_rx_transfer.inc', '    fetch=rx_candidate;',
     '    fetch=rx_candidate;\n    cso_fetch_phase(2,ref,&rx_view);'),
    ('fetch_page_custody.inc', 'int li2_lifecycle_fetch_rx_stage_custody(',
     'static int cso_real_rx_stage_custody('),
    ('fetch_page_custody.inc', 'int li2_lifecycle_fetch_rx_commit_custody(',
     'static int cso_real_rx_commit_custody('),
    ('fetch_page_custody.inc', '        fetch=rx_candidate;*out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};',
     '        fetch=rx_candidate;\n        cso_fetch_phase(2,ref,&rx_view);\n        *out=(struct li2_fetch_ref){&fetch,fetch.progress.sequence};'),
)
OUTER = '''
/* Return-side observation: both cold and retained paths have completed. */
extern void cso_fetch_returned(unsigned,int,const struct li2_fetch_ref *,
    const struct li2_fetch_ref *,const struct li2_custody_owner *,
    const struct li2_fetch_rx_view *,const struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_stage_custody(const struct li2_fetch_ref *ref,uintptr_t pc,
        const struct li2_custody_owner *key,const struct li2_fetch_rx_view **out) {
 struct li2_fetch_ref before={0};if(ref)before=*ref;
 int result=cso_real_rx_stage_custody(ref,pc,key,out);
 cso_fetch_returned(1,result,ref,&before,key,out?*out:0,0);
 if(!result)cso_fetch_phase(1,ref,*out);
 return result;
}
int li2_lifecycle_fetch_rx_commit_custody(const struct li2_fetch_ref *ref,
        const struct li2_fetch_rx_view *view,const struct li2_custody_owner *key,struct li2_fetch_ref *out) {
 struct li2_fetch_ref before={0};if(ref)before=*ref;
 int result=cso_real_rx_commit_custody(ref,view,key,out);
 cso_fetch_returned(2,result,ref,&before,key,view,result?0:out);
 return result;
}
'''
FILES = ('runtime_loader.c', 'selected_controller.inc', 'native_controller.inc',
         'selected_chain.inc', 'lifecycle_loader.c', 'fetch_loader.inc',
         'fetch_rx_transfer.inc', 'fetch_page_custody.inc')


def original(root, pin):
    path = pin(Path(root) / 'tools/page-entry/selected/tests/tf_same_page/prepare.py')
    spec = importlib.util.spec_from_file_location('cso_original_prepare', path)
    module = importlib.util.module_from_spec(spec)
    # Loading authenticated source directly never writes a fixture-tree .pyc,
    # including when a caller has not disabled the interpreter cache globally.
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module


def config(*, stack=False, fault_event=0, overlap=False):
    need(type(stack) is bool and type(overlap) is bool and type(fault_event) is int
         and fault_event in (0, 1) and not (stack and overlap)
         and not ((stack or overlap) and fault_event), 'fixed custody observer selector')
    return ('/* Fixed source selection; never a runtime argument. */\n'
            f'#define CSO_STACK {int(stack)}\n#define CSO_FAULT_EVENT {fault_event}\n'
            f'#define CSO_OVERLAP {int(overlap)}\n').encode()


def compose(name, before, old):
    data = before
    # Exactly the eight original non-fetch adapters. New outer wrappers replace
    # the three original inner-hook adapters, not the original runtime policy.
    inherited = old.ADAPTERS[:8]
    need(len(old.ADAPTERS) == 11 and all(row[0] == 'fetch_rx_transfer.inc'
         for row in old.ADAPTERS[8:]), 'exact original observer adapter partition')
    operations = [row[1:] for row in inherited + ADAPTERS if row[0] == name]
    if name == 'tf_lease_observe.inc':
        operations = [STORAGE]
    for source, replacement in operations:
        a, b = source.encode(), replacement.encode()
        need(data.count(a) == 1 and b not in data, 'unique custody observer seam ' + name)
        data = data.replace(a, b)
    suffix = (old.FETCH_WRAPPER if name == 'native_controller.inc' else
              old.PROTECTION if name == 'lifecycle_loader.c' else
              OUTER if name == 'fetch_page_custody.inc' else '').encode()
    data += suffix
    inverse = data[:-len(suffix)] if suffix else data
    for source, replacement in reversed(operations):
        a, b = source.encode(), replacement.encode()
        need(inverse.count(b) == 1, 'unique custody inverse ' + name)
        inverse = inverse.replace(b, a)
    need(inverse == before, 'complete original product recovered ' + name)
    return data


def prepare(root, out, pin, *, stack=False, fault_event=0, overlap=False):
    root, out = Path(root), Path(out)
    selected = root / 'tools/page-entry/selected'
    leaf = selected / 'tests/page_custody'
    selected_config = config(stack=stack, fault_event=fault_event, overlap=overlap)
    old = original(root, pin)
    need(not out.exists(), 'unique custody observation source view')
    out.mkdir(parents=True)
    facts = []

    def emit(name, before_path, data):
        dest = out / name
        dest.write_bytes(data)
        pin(dest)
        facts.append(dict(name=name, before=fact(before_path), after=fact(dest)))

    for name in FILES:
        path = pin(selected / name)
        emit(name, path, compose(name, path.read_bytes(), old))
    path = pin(selected / 'tests/tf_same_page/observe.inc')
    emit('tf_lease_observe.inc', path, compose('tf_lease_observe.inc', path.read_bytes(), old))
    path = pin(selected / 'tests/tf_same_page/record.h')
    before = path.read_bytes()
    a, b = b'#include "../rseq_native/record.h"', b'#include "tf_lease_old_record.h"'
    need(before.count(a) == 1 and b not in before, 'exact original frame include')
    data = before.replace(a, b)
    need(data.replace(b, a) == before, 'complete frame include inverse')
    emit('tf_lease_record.h', path, data)
    for source, dest in ((selected / 'tests/rseq_native/record.h', 'tf_lease_old_record.h'),
                         (selected / 'tf_same_page.h', 'tf_lease_types.h'),
                         (leaf / 'record.h', 'page_custody_record.h'),
                         (leaf / 'observe.inc', 'page_custody_observe.inc')):
        path = pin(source)
        emit(dest, path, path.read_bytes())
    path = out / 'page_custody_config.h'
    path.write_bytes(selected_config)
    pin(path)
    facts.append(dict(name=path.name, before=None, after=fact(path)))
    return facts
