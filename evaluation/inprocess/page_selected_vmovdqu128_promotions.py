"""Strict supplied typed promotions; actual native state is checked separately."""
import hashlib,struct
from page_selected import need

PROMOTED=(
    (66,'c5fa6f0e'),(67,'c5fa6f3e'),(68,'c57a6f06'),
    (69,'c5fa6f07'),(70,'c5fa6f00'),(71,'c5fa6f03'),
    (72,'c5fa6fc6'),(79,'c5fa6f4600'),(80,'c5fa6f0426'),
    (81,'c4e17a6f06'),(82,'c4e1fa6f06'),(83,'c4c17a6f06'),
)

def promotions(data):
    need(len(data)==3520,'complete supplied-promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d383231564c,1,3520,12,12,0,0,0),
         'all twelve promotions attempted and completed, no missing control')
    for i,(index,hexadecimal)in enumerate(PROMOTED):
        at=64+288*i;b=bytes.fromhex(hexadecimal);n=len(b)
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),
             'exact retained old row, successful typed and footprint observations')
        need(data[at+40:at+56]==b+bytes(16-n),'exact old bytes and zero unused capacity')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1000+n,1,1,1598,n,1,6),
             'mandatory positive fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'declared supplied tuple, not an actual-before frame')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1000+n,0,0,1,1,1598,n),
             'mandatory exact-Code NONE footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                typed_promotions=12,supplied_none_queries=12,
                scope='Supplied exact old-byte controls; native coverage is separate.')
