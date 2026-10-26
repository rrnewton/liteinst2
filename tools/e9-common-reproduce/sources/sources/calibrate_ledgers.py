"""Additive three-schema/21-malformation controls; no processes or mappings."""
import csv
from state_ledger_schema import CASES_HEADER, PAGES_HEADER, OWNERSHIP_HEADER, exact_rows


def calibrate():
    accepted, refused = [], []
    schemas = (
        ('cases', CASES_HEADER, ('fixture', '0', '1879048192', '1879052391', '1879113728', '1879113728', '1879054336')),
        ('pages', PAGES_HEADER, ('1879113728', '4096', '1' * 64)),
        ('ownership', OWNERSHIP_HEADER, ('1', '1879109632', '1879121920', '1879113728', '1879117824', 'sparse-exec', 'true')),
    )
    def encoded(header, cells):
        return '\t'.join(header) + '\n' + '\t'.join(cells) + '\n'
    for schema, header, cells in schemas:
        assert exact_rows(encoded(header, cells), header) == [dict(zip(header, cells))]
        accepted.append(schema + '-exact-ordered-schema')
        mutations = (
            ('duplicate-leading-header-conflicting-value', (header[0],) + header, ('conflicting-first-value',) + cells),
            ('duplicate-trailing-header', header + (header[0],), cells + (cells[0],)),
            ('reordered-header', (header[1], header[0]) + header[2:], (cells[1], cells[0]) + cells[2:]),
            ('missing-header', header[:-1], cells[:-1]),
            ('extra-header', header + ('unexpected',), cells + ('extra',)),
            ('missing-row-cell', header, cells[:-1]),
            ('extra-row-cell', header, cells + ('extra',)),
        )
        assert len(mutations) == 7
        for label, changed_header, changed_cells in mutations:
            try:
                exact_rows(encoded(changed_header, changed_cells), header)
            except (AssertionError, csv.Error):
                refused.append(schema + '-' + label)
            else:
                raise AssertionError('required malformed-ledger refusal accepted: ' + schema + '-' + label)
    assert len(accepted) == len(set(accepted)) == 3
    assert len(refused) == len(set(refused)) == 21
    return dict(accepted=accepted, refused=refused, acceptances=3, refusals=21,
                mappings=0, application_executions=0)
