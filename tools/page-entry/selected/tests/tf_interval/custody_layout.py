"""Original file-only DWARF extractor plus the fixed custody extension."""
from pathlib import Path
path = Path(__file__).with_name('layout.py')
source = path.read_text()
old = "types={n:shape(n)for n in names};s=gdb.lookup_static_symbol(record)"
new = """if record=='tfi_record':
 names+=['tci_record','tci_row','tci_meta','li2_page_custody_stats','li2_maps_stats','li2_step_session','li2_page_custody_receipt']
types={n:shape(n)for n in names};s=gdb.lookup_static_symbol(record)"""
if source.count(old) != 1 or new in source:
    raise ValueError('one exact original DWARF extension seam')
adapted = source.replace(old, new)
if adapted.replace(new, old) != source:
    raise ValueError('complete original DWARF source inverse')
exec(compile(adapted, str(path), 'exec', dont_inherit=True))
