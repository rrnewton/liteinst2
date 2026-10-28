"""Mandatory exact old-row promotions; supplied inputs are not actual-before frames."""
import hashlib,struct
from page_selected import need
PROMOTED=((33,'62f17540740f'),(34,'62f17540743f'),(39,'62f175487407'),
          (40,'62f17d407407'),(41,'62f16d407407'))

def promotions(data):
    need(len(data)==1504,'complete five-promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d435056324c,1,1504,5,5,0,0,0),
         'all five original rows attempted and completed')
    for i,(index,hexadecimal)in enumerate(PROMOTED):
        at=64+288*i;b=bytes.fromhex(hexadecimal)
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),
             'exact old row and successful typed/query observations')
        need(data[at+40:at+56]==b+bytes(10),'exact retained bytes and unused capacity')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,1720,6,1,6),
             'mandatory Code1720 positive fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'declared supplied GPR/FS/GS tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0,0,1,1,1720,6),
             'mandatory exact-Code NONE footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=5,
                supplied_none_queries=5,scope='Supplied exact old-byte controls; native coverage is separate.')
