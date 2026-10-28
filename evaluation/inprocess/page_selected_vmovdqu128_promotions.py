"""Strict supplied typed promotions; actual native state is checked separately."""
import hashlib,struct
from page_selected import need

LOAD_PROMOTED=(
    (66,'c5fa6f0e'),(67,'c5fa6f3e'),(68,'c57a6f06'),
    (69,'c5fa6f07'),(70,'c5fa6f00'),(71,'c5fa6f03'),
    (72,'c5fa6fc6'),(79,'c5fa6f4600'),(80,'c5fa6f0426'),
    (81,'c4e17a6f06'),(82,'c4e1fa6f06'),(83,'c4c17a6f06'),
)
PROMOTED=LOAD_PROMOTED[:7]+((73,'c5fa7f06'),)+LOAD_PROMOTED[7:]

def promotions(data):
    need(len(data)==3808,'complete supplied-promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d383231564c,1,3808,13,13,0,0,0),
         'all thirteen promotions attempted and completed, no missing control')
    for i,(index,hexadecimal)in enumerate(PROMOTED):
        at=64+288*i;b=bytes.fromhex(hexadecimal);n=len(b)
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),
             'exact retained old row, successful typed and footprint observations')
        need(data[at+40:at+56]==b+bytes(16-n),'exact old bytes and zero unused capacity')
        if index==73:
            need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1000+n,1,1,1840,n,1,6),
                 'mandatory exact store positive fallthrough SIMD classification')
        else:
            need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1000+n,1,1,1598,n,1,6),
                 'mandatory positive fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'declared supplied tuple, not an actual-before frame')
        if index==73:
            supplied_rsi=struct.unpack_from('<18Q',data,at+96)[6]
            need(struct.unpack_from('<4Q4I',data,at+240)==
                 (0x1000,0x1000+n,supplied_rsi,supplied_rsi+16,1,2,1840,n),
                 'mandatory exact-Code RANGE16 from actual supplied RSI')
        else:
            need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1000+n,0,0,1,1,1598,n),
                 'mandatory exact-Code NONE footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                typed_promotions=13,supplied_none_queries=12,supplied_range_queries=1,
                scope='Supplied exact old-byte controls; native coverage is separate.')
