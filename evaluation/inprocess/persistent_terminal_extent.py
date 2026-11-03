"""Original terminal NX extent predicate, shared without changing its default."""
from linked_frontier_census import need


def nx_extent(d):
    """Original NX lifecycle, kept exact for every existing caller."""
    need((d['opened_pages'],d['closed_pages'],d['recovery_complete'])==
         ((17*d['domain_members'],17*d['domain_members'],1)if d['phase']==13 else(0,0,0)), 'exact executed versus unentered terminal extent')
