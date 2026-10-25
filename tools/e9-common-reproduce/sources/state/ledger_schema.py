"""Exact ordered TSV schemas for the three fixed capture ledgers."""
import csv
import io

CASES_HEADER = ('fixture', 'bias_index', 'bias', 'source', 'image', 'restored_head', 'terminal')
PAGES_HEADER = ('address', 'bytes', 'sha256')
OWNERSHIP_HEADER = ('index', 'start', 'end', 'interior_start', 'interior_end', 'kind', 'rewritten')


def exact_rows(text, header):
    """Reject duplicate/reordered/unknown headers and missing/extra row cells."""
    assert isinstance(text, str)
    assert isinstance(header, tuple) and header and len(set(header)) == len(header)
    reader = csv.reader(io.StringIO(text, newline=''), delimiter='\t', strict=True)
    assert next(reader, None) == list(header), 'exact ordered ledger header required'
    rows = []
    for cells in reader:
        assert len(cells) == len(header), 'exact ledger row width required'
        assert all(cell != '' for cell in cells), 'missing ledger value'
        rows.append(dict(zip(header, cells)))
    return rows
