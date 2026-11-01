"""Independent schema15 image/configuration and actual compiled storage joins."""
import re
import shutil
import struct
from maps_view import need, fact, H, SELECTED, ENV
from persistent_epoch_build import dynamic_original_image
from page_selected import elf


def capture_config(builder, image, output, pin, binary, run):
    image = pin(binary(image))
    original = dynamic_original_image(image)
    data, h, segments = elf(image)
    need(h[1:4] == (2, 62, 1) and h[8:10] == (64, 56) and
         h[11] == 64 and 0 < h[12] <= 256, 'exact lifecycle ET_EXEC observation image')
    def take(offset, size):
        need(type(offset) is int and type(size) is int and 0 <= offset <= len(data) and
             0 <= size <= len(data)-offset, 'complete bounded observation ELF bytes')
        return data[offset:offset+size]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one complete actual fixture symbol table')
    table = tables[0]
    need(table[9] == 24 and table[5] % 24 == 0 and table[6] < len(sections),
         'complete symbol table extent')
    strings = sections[table[6]]
    need(strings[1] == 3, 'actual symbol string table')
    names = take(strings[4], strings[5])
    # Independently literal schema15 fixture grammar; observation only.
    a = bytes.fromhex('4883e9014883f9020f84f2feffff4885c975ed66894f084983ea0175faff2500000000')
    b = bytes.fromhex('4c890f4983e9014c89c9e9f1000000')
    page = (0x4000000, 0x700000000000)
    expected = {'lc_a_template': (a, 1), 'lc_b_template': (b, 1),
        'lc_entry': (struct.pack('<2I', 512, 256), 4),
        'lc_source_page': (struct.pack('<2Q', *page), 8),
        'lc_steps': (struct.pack('<2I', 50, 42), 4),
        'lc_a_back': (struct.pack('<2I', 3, 2), 4),
        'lc_a_to_b': (struct.pack('<2I', 3, 2), 4),
        'lc_predecessor_offset': (struct.pack('<i', -5), 4)}
    for name, value in (('base',512), ('b',256), ('cancel',19), ('c',23), ('stub',29)):
        expected['lc_'+name+'_offset'] = (struct.pack('<I', value), 4)
    wanted = set(expected) | {'region_app_capture_high'}
    found = {}
    for at in range(table[4], table[4]+table[5], 24):
        n, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete actual symbol name')
        name = names[n:names.index(b'\0', n)].decode()
        if name not in wanted:
            continue
        need(0 < section < len(sections) and name not in found,
             'unique complete actual paired selector symbol')
        found[name] = (address, size, info & 15)
    need(set(found) == wanted and len(a)==35 and len(b)==15, 'all exact lifecycle selectors and full templates')
    for name in expected.keys() | {'region_app_capture_high'}:
        address, size, kind = found[name]
        function = name == 'region_app_capture_high'
        flags = 5 if function else 4
        need(kind == (2 if function else 1) and size > 0 and
             4096 <= address < address+size < 1 << 47,
             'actual readonly object or executable function extent')
        if not function:
            body, alignment = expected[name]
            need(size == len(body) and address % alignment == 0, 'exact table size/alignment')
        owners = [p for p in segments if p[0] == 1 and p[1] == flags and p[5] <= p[6] and
                  p[3] <= address and address-p[3]+size <= p[5]]
        need(len(owners) == 1 and all(p == owners[0] for p in segments if p[0] == 1 and
             p[3] < address+size and address < p[3]+p[6]), 'one nonoverlapping whole load owner')
        p = owners[0]
        if not function:
            need(take(p[2]+address-p[3], size) == body, 'whole paired selector bytes '+name)
    need(all(page_at%4096==0 and 4096<=page_at and page_at+3*4096<1<<47 for page_at in page)
         and 512+23<=4096-15 and 512+43<8192, 'unchanged whole-pair cold-root geometry')
    high = found['region_app_capture_high'][0]
    values = (('unsigned char','plc_a_template',a), ('unsigned char','plc_b_template',b),
              ('uint64_t','plc_source_pages',page))
    header = ('#ifndef LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE_CONFIG_H\n'
              '#define LI2_PERSISTENT_LOOP_LIFECYCLE_CAPTURE_CONFIG_H\n'
              '#define LI2_PLC_CAPTURE_VERSION 15\n#define LI2_PLC_APP_PROTOCOL 1\n'
              '#define LI2_PLC_HIGH_RVA 0x%xULL\n' % high)
    for typ, name, row in values:
        cells = ', '.join('0x%xULL' % n if typ == 'uint64_t' else str(n) for n in row)
        header += 'static const %s %s[%d]={%s};\n' % (typ, name, len(row), cells)
    header = (header+'#endif\n').encode()
    script = pin(SELECTED/'persistent_loop_lifecycle_capture_binding.py')
    _, out, err = run('loop-capture-binding', [builder.tools['python'], '-B', script, image, output],
                     env=builder.environment)
    need(out == err == b'', 'separate observation binder diagnostics empty')
    destination = pin(binary(output/'persistent_loop_lifecycle_capture_config.h'))
    need(destination.read_bytes() == header, 'whole independently derived schema15 selector header')
    return dict(version=15, protocol=1, original=original, symbols=found,
                source_pages=list(page), entries=[512,256], predecessor_offset=-5,
                templates={name:dict(bytes=len(value),sha256=H(value)) for name,value in (('A',a),('B',b))},
                lifecycle_lifetimes=5, full_cohort_credit=False,
                script=dict(path=str(script), **fact(script)),
                header=dict(path=str(destination), **fact(destination)))



def capture_extents(builder, bridge, symbols, pin, run, state):
    """Exact full source-derived sizes; actual DWARF/ELF must agree before use."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    names = ('wire', 'encoded', 'certificate', 'epoch', 'next', 'stage', 'slots', 'epoch_info',
             'domain_checkpoint', 'memory', 'selection', 'loop', 'counts', 'cancellation')
    expressions = ('sizeof(pdo_wire)', 'sizeof(pdo_encoded)', 'sizeof(struct pdo_certificate)',
        'sizeof(struct pdo_epoch)', 'sizeof(struct pdo_next)', 'sizeof(struct pdo_stage)',
        'sizeof(struct pdo_slots)', 'sizeof(struct pdo_epoch_info)',
        'sizeof(struct pdo_domain_checkpoint)', 'sizeof(struct li2_pdo_memory)',
        'sizeof(struct plc_selection)', 'sizeof(struct plr_state)',
        'sizeof(struct pdo_counts)', 'sizeof(struct pbo_cancel)')
    expression = ('printf "LI2_PLC_EXTENTS '+' '.join(['%llu']*len(expressions))+'\\n", '+
                  ', '.join('(unsigned long long)('+v+')' for v in expressions))
    _, out, err = run('persistent-loop-capture-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(b'LI2_PLC_EXTENTS '+b' '.join([rb'([0-9]+)']*len(expressions))+b'\n', out)
    need(not err and match is not None, 'one complete actual schema15 DWARF extent row')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (13739904, 4194304, 434240, 1842176, 267968, 384808, 71432, 15176,
                   11792, 9032, 224, 260544, 360, 1393408),
         'exact complete raw schema15 and unchanged encoded cap')
    _, _, segments = elf(bridge)
    storage = {}
    for name, extent in (('pdo_wire', sizes[0]), ('pdo_encoded', sizes[1])):
        rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
             int(rows[0][0], 16) > 0 and int(rows[0][1], 16) == extent,
             'actual full capture symbol equals DWARF extent')
        address = int(rows[0][0], 16)
        need(sum(p[0] == 1 and p[1] == 6 and p[3] <= address < address+extent <= p[3]+p[6]
                 for p in segments) == 1, 'whole buffer belongs to protected RW/NX PT_LOAD')
        storage[name] = dict(address=address, bytes=extent)
    a, b = storage.values()
    need(a['address']+a['bytes'] <= b['address'] or b['address']+b['bytes'] <= a['address'],
         'full raw and encoded storage disjoint')
    state['capture_extents'] = dict(zip(names, sizes))
    state['capture_extents'].update(footer=64, header=64, record_limit=4194304,
        stream_strictly_below=4194304, codec_version=1, schema_version=15, storage=storage,
        representation='five actual lifecycle offers, mixed owners, replacement and genuine cancellation with whole state',
        full_cohort_credit=False)
