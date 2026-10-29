"""One mandatory old Code1838 row; supplied inputs are not native before frames."""
import hashlib,struct
from page_selected import need
PROMOTED=(10,'62e1fd487f0f')
def promotions(data):
    need(len(data)==352,'complete single-promotion trailer')
    need(struct.unpack_from('<8Q',data)==(0x31504d415156324c,1,352,1,1,0,0,0),
         'the exact original row was attempted and completed once')
    at=64
    need(struct.unpack_from('<5Q',data,at)==(10,1,0,0,1),'exact old index and successful typed/query observations')
    need(data[at+40:at+56]==bytes.fromhex(PROMOTED[1])+bytes(10),'complete original bytes and zero unused capacity')
    need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,1838,6,1,6),
         'mandatory Code1838 fallthrough SIMD classification')
    need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
         'exact supplied GPR/FS/GS tuple')
    need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0x1234070,0x12340b0,1,2,1838,6),
         'mandatory exact-Code RANGE64 footprint')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=1,
                supplied_range_queries=1,scope='Supplied exact old bytes; full native coverage is separate.')
