"""File-only GDB observations of actual current-custody storage; no inferior."""
import gdb
import json


NAMES = ('maps_current', 'mct_physical_receipt', 'mct_physical_id',
         'rx_current', 'rx_current_busy', 'cc', 'cc_candidate', 'cc_serial', 'cc_stats')


def need(value, message):
    if not value:
        raise ValueError(message)


def extent(name):
    symbol = gdb.lookup_static_symbol(name)
    need(symbol is not None and symbol.is_variable and symbol.symtab is not None,
         'actual static variable and declaring compilation unit: ' + name)
    t = symbol.type.strip_typedefs()
    size, alignment = int(t.sizeof), int(t.alignof)
    need(0 < size <= 1 << 20 and 0 < alignment <= 4096 and not alignment & (alignment - 1),
         'complete actual storage extent and alignment')
    address = int(symbol.value().address)
    need(address > 0 and address % alignment == 0, 'actual aligned symbol address')
    fields = {}
    if t.code == gdb.TYPE_CODE_STRUCT:
        for f in t.fields():
            need(f.name and f.name not in fields and not f.bitsize and f.bitpos % 8 == 0,
                 'every direct field is a unique whole-byte field')
            offset, width = int(f.bitpos) // 8, int(f.type.sizeof)
            need(0 <= offset < size and 0 < width <= size - offset, 'complete member inside object')
            fields[f.name] = dict(offset=offset, bytes=width, type=str(f.type.strip_typedefs()))
    else:
        need(t.code == gdb.TYPE_CODE_INT, 'only actual integer or structure state')
    return dict(address=address, bytes=size, alignment=alignment, type=str(t),
                source=symbol.symtab.fullname(), fields=fields)


need(gdb.selected_inferior().pid == 0, 'metadata observation never starts an inferior')
print(json.dumps(dict(version=1, symbols={name: extent(name) for name in NAMES}),
                 sort_keys=True, separators=(',', ':')))
