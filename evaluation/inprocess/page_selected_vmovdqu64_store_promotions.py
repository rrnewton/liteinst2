"""Mandatory retained Code1847 rows; supplied tuples have no native credit."""
import hashlib,struct
from page_selected import need
LITERAL='62e1fe487f0f'
def promotions(data,indices=(16,)):
    need(type(indices)is tuple and indices in ((16,),(16,5)),'explicit complete original-table contract')
    count=len(indices);extent=64+288*count
    need(len(data)==extent,'complete mandatory promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d445156324c,1,extent,count,count,0,0,0),
         'every original row attempted and completed exactly once')
    for slot,index in enumerate(indices):
        at=64+288*slot
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),'exact original index and successful typed observations')
        need(data[at+40:at+56]==bytes.fromhex(LITERAL)+bytes(10),'complete literal bytes and zero unused capacity')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,1847,6,1,6),
             'mandatory Code1847 fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'exact supplied GPR/FS/GS tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0x1234070,0x12340b0,1,2,1847,6),
             'mandatory exact-Code full64-byte RANGE footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=count,
                supplied_range_queries=count,scope='Supplied exact retained bytes; native coverage is separate.')
