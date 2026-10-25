"""Additive exact reservation/guard audit; no architectural normalization."""
import csv
from state_ledger_schema import OWNERSHIP_HEADER, exact_rows


def audit_ownership(path, item, bias, phase, mapped, actual_pages):
    sparse = item['body_ownership']['kind'] == 'sparse-exec'
    if sparse:
        assert (item['min_vaddr'], item['max_vaddr'], item['source_page'], item['image_pc']) == (0x400000, 0x405000, 0x401000, 0x10000)
        relative = [(0x3ff000, 0x406000), (0xf000, 0x12000)]
        assert item['body_ownership'] == dict(kind='sparse-exec', roots=[list(row) for row in relative], root_count=2, owned_bytes=40960)
    else:
        assert (item['min_vaddr'], item['max_vaddr'], item['source_page'], item['image_pc']) == (0, 0x6000, 0x1000, 0x5000)
        relative = [(-4096, 0x7000)]
        assert item['body_ownership'] == dict(kind='compact', roots=[list(row) for row in relative], root_count=1, owned_bytes=32768)
    rows = exact_rows(path.read_text(), OWNERSHIP_HEADER)
    assert len(rows) == len(relative)
    roots = []
    total = 0
    for index, (row, (lo, hi)) in enumerate(zip(rows, relative)):
        assert set(row) == {'index','start','end','interior_start','interior_end','kind','rewritten'}
        start, end = bias + lo, bias + hi
        assert 0 < start < end <= (1 << 47) and start % 4096 == end % 4096 == 0
        assert row == dict(index=str(index),start=str(start),end=str(end),interior_start=str(start+4096),interior_end=str(end-4096),kind=item['body_ownership']['kind'],rewritten=str(phase=='rewritten').lower())
        assert 0 < end-start <= 1048576
        total += end-start
        assert total <= 1048576
        assert all(end <= a or z <= start for a,z in roots)
        assert not start <= bias + 0x20fedc000 < end
        roots.append((start,end))
        for address in range(start,end,4096):
            if address in actual_pages:
                assert start+4096 <= address and address+4096 <= end-4096
                continue  # Existing audit authenticates full bytes/file/offset/permissions.
            # Every guard and every inactive interior page is wholly anonymous
            # and inaccessible. Adjacent VMAs may merge; roots need not be VMAs.
            cursor = address
            for low,high,fields in mapped:
                if low < address+4096 and address < high:
                    assert low <= cursor < high
                    assert len(fields)==5 and fields[1:5] == ['---p','00000000','00:00','0']
                    cursor = min(high,address+4096)
            assert cursor == address+4096
    assert all(sum(start+4096 <= a and a+4096 <= end-4096 for start,end in roots)==1 for a in actual_pages)
    assert total == item['body_ownership']['owned_bytes']
    return roots
