"""Mandatory exact old-row promotions; supplied inputs are not actual-before frames."""
import hashlib,struct
from page_selected import need
PROMOTED=((0, '62f1fe486f0f'), (1, '6271fe486f0f'), (2, '6261fe486f0f'), (3, '62c1fe486f0f'), (4, '62e1fe486f0e'), (5, '62e1fe486f17'), (6, '62e1fe486fcf'))

def promotions(data):
    need(len(data)==2080,'complete seven-promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d343656324c,1,2080,7,7,0,0,0),
         'all seven original rows attempted and completed')
    for i,(index,hexadecimal)in enumerate(PROMOTED):
        at=64+288*i;b=bytes.fromhex(hexadecimal)
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),
             'exact old row and successful typed/query observations')
        need(data[at+40:at+56]==b+bytes(10),'exact retained bytes and unused capacity')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,1605,6,1,6),
             'mandatory Code1605 positive fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'declared supplied GPR/FS/GS tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0,0,1,1,1605,6),
             'mandatory exact-Code NONE footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=7,
                supplied_none_queries=7,scope='Supplied exact old-byte controls; native coverage is separate.')
