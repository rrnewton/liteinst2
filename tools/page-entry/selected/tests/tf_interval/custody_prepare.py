"""Fixed custody interval observer; exact inverse of every production edit."""
import importlib.util
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from page_selected import fact, need

FILES = ('runtime_loader.c', 'selected_controller.inc', 'native_controller.inc',
         'selected_chain.inc', 'lifecycle_loader.c', 'fetch_loader.inc',
         'fetch_rx_transfer.inc', 'fetch_page_custody.inc')
GENERATED = (*FILES, 'tf_interval_observe.inc', 'tf_interval_record.h',
             'tf_interval_old_record.h', 'tf_interval_custody_record.h',
             'tf_interval_custody_observe.inc')
ADAPTERS = (
 ('runtime_loader.c', '    li2_tf_chain_handler_end(&selected_chain);',
  '    tci_handler_end(&selected_chain,sig,si,ptr);'),
 ('fetch_page_custody.inc', 'int li2_lifecycle_fetch_rx_stage_custody(',
  'static int tci_real_stage_custody('),
 ('fetch_page_custody.inc', 'int li2_lifecycle_fetch_rx_commit_custody(',
  'static int tci_real_commit_custody('),
 ('tf_interval_observe.inc', 'struct tfi_owner {',
  '#include "tf_interval_custody_record.h"\nstruct tfi_owner {'),
 ('tf_interval_observe.inc',
  ' unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];',
  ' unsigned char terminal_source[RN_SOURCE_BYTES],terminal_data[RN_DATA_BYTES],terminal_page[4096];\n struct tci_record custody;'),
 ('tf_interval_observe.inc', 'static void tfi_counts(uint64_t h[16]) {',
  '#include "tf_interval_custody_observe.inc"\nstatic void tfi_counts(uint64_t h[16]) {'),
 ('tf_interval_observe.inc', ' tfi_counts(r->counts_before);tfi_compact',
  ' tci_entry(tfi_count);\n tfi_counts(r->counts_before);tfi_compact'),
 ('tf_interval_observe.inc', ' ++tfi_count;tfi_trace_active=0;return result;',
  ' tci_returned(tfi_count);\n ++tfi_count;tfi_trace_active=0;return result;'),
 ('tf_interval_observe.inc', ' size_t at=0;\n while(at<sizeof tfi_record)',
  ' tci_terminal();\n size_t at=0;\n while(at<sizeof tfi_record)'),
)
OUTER = '''
extern void tci_fetch_returned(unsigned,int,const struct li2_fetch_ref *,
 const struct li2_custody_owner *,const struct li2_fetch_rx_view *,const struct li2_fetch_ref *);
int li2_lifecycle_fetch_rx_stage_custody(const struct li2_fetch_ref *ref,uintptr_t pc,
 const struct li2_custody_owner *key,const struct li2_fetch_rx_view **out) {
 struct li2_fetch_ref before={0};if(ref)before=*ref;
 int result=tci_real_stage_custody(ref,pc,key,out);
 tci_fetch_returned(1,result,&before,key,out?*out:0,0);return result;
}
int li2_lifecycle_fetch_rx_commit_custody(const struct li2_fetch_ref *ref,
 const struct li2_fetch_rx_view *view,const struct li2_custody_owner *key,struct li2_fetch_ref *out) {
 struct li2_fetch_ref before={0};if(ref)before=*ref;
 int result=tci_real_commit_custody(ref,view,key,out);
 tci_fetch_returned(2,result,&before,key,view,result?0:out);return result;
}
'''

def original(root, pin):
    path = pin(Path(root) / 'tools/page-entry/selected/tests/tf_interval/prepare.py')
    spec = importlib.util.spec_from_file_location('tci_original_prepare', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(path.read_bytes(), str(path), 'exec', dont_inherit=True), module.__dict__)
    return module

def compose(name, before, old):
    data = before
    operations = [(a, b) for path, a, b in old.ADAPTERS + ADAPTERS if path == name]
    for a, b in operations:
        need(data.count(a.encode()) == 1 and b.encode() not in data, 'one exact custody interval seam ' + name)
        data = data.replace(a.encode(), b.encode())
    suffix = (old.FETCH_WRAPPER if name == 'native_controller.inc' else
              old.PROTECTION if name == 'lifecycle_loader.c' else
              OUTER if name == 'fetch_page_custody.inc' else '').encode()
    data += suffix
    inverse = data[:-len(suffix)] if suffix else data
    for a, b in reversed(operations):
        need(inverse.count(b.encode()) == 1, 'one exact custody interval inverse')
        inverse = inverse.replace(b.encode(), a.encode())
    need(inverse == before, 'whole production/observer source recovered')
    return data

def prepare(root, out, pin):
    root, out = Path(root), Path(out)
    selected = root / 'tools/page-entry/selected'
    leaf = selected / 'tests/tf_interval'; old = original(root, pin)
    need(not out.exists(), 'fresh custody interval view'); out.mkdir()
    facts = []
    def emit(name, source, data):
        path = out / name; path.write_bytes(data); pin(path)
        facts.append(dict(name=name, before=fact(source), after=fact(path)))
    for name in FILES:
        path = pin(selected / name)
        emit(name, path, compose(name, path.read_bytes(), old))
    path = pin(leaf / 'observe.inc')
    emit('tf_interval_observe.inc', path, compose('tf_interval_observe.inc', path.read_bytes(), old))
    path = pin(leaf / 'record.h'); before = path.read_bytes()
    a, b = b'#include "../rseq_native/record.h"', b'#include "tf_interval_old_record.h"'
    need(before.count(a) == 1 and b not in before, 'one original frame include')
    data = before.replace(a, b); need(data.replace(b, a) == before, 'whole frame header inverse')
    emit('tf_interval_record.h', path, data)
    for path, name in ((selected / 'tests/rseq_native/record.h', 'tf_interval_old_record.h'),
                       (leaf / 'custody_record.h', 'tf_interval_custody_record.h'),
                       (leaf / 'custody_observe.inc', 'tf_interval_custody_observe.inc')):
        path = pin(path); emit(name, path, path.read_bytes())
    need(tuple(row['name'] for row in facts) == GENERATED, 'all thirteen generated sources')
    return facts
