"""Strict eleven-mode scalar-DAG hardware record; no execution or runtime-owner credit."""
import json
import struct

PAGE, FP, DATA, STACK = 4096, 65536, 8192, 131072
TF, RF, MASK64 = 0x100, 0x10000, (1 << 64) - 1
REGS = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
OFFSETS = (0, 3, 6, 12, 15, 17, 21, 24, 26, 28, 33, 35, 43, 46, 48, 54, 59, 62, 69, 71)
LENGTHS = (3, 3, 6, 3, 2, 4, 3, 2, 2, 5, 2, 8, 3, 2, 6, 5, 3, 7, 2, 6)
GEN = (0, 3, 6, 12, 15, 21, 25, 28, 30, 36, 41, 43, 51, 54, 56, 62, 67, 70, 77, 79)
EXITS = (0x73e, 0x670, 0xa14, 0x818, 0x63f)
FAULT_HEADS = (5, 9, 11, 15, 17, 17)
TRACES = (3, 9, 11, 20, 20, 5, 9, 11, 15, 17, 17)
CODES = (282, 274, 1868, 274, 173, 2090, 260, 115, 173, 286, 96, 2090, 260, 115, 1868, 286, 282, 285, 273, 1868)
JCC = (2, 4, 8, 14, 19)
TAKEN = (0x73e, 0x60e, 0x670, 0xa14, 0x818)
LITERAL = bytes.fromhex('4889c84885d20f84400100004885c9740b0fb6410583e0033c0374624c8b7c245831db410fb6871c03000083e0033c020f84ec0300004c8b5424504d89fd418bbfe403000085ff0f84d90100008b05bbd40200')
SOURCE_PAGE = bytes.fromhex(
    '7818488b7c2428488d04ff488d0447488d3deadf0200488344c7600148894c2408488b7c2430ff155cda0200488b442450488b4c240848895808488908e99bfb'
    'ffff4d29ec4c89e048c1e0054c01c0eb120f1f80000000004901d44801f04d39e576df488378080075ee4489304889780848894810488958180fb6831c030000'
    '83e0033c020f8577ffffff80bb1f030000000f856afffffff68424d0000000080f845903000080bb20030000000f854ffffffff60546da0200040f85d0030000'
    'c6832003000001e936ffffff0f1f40004d29eee9cdfdffff4d29ece9dffeffff488b54241831c00fb63a4885ff0f84a20000000fb6420184c00f84b902000048'
    'c1e7044801c7488b4424180fb6400284c00f84a102000048c1e7044801c7488b4424180fb6400384c00f848902000048c1e7044801c7488b4424180fb6400484'
    'c00f847102000048c1e7044801f8488b7c24180fb64f05488d570584c9742148c1e0044883c2014801c14889c848c1e81825f00000004831c80fb60a84c975df'
    '25ffffff0f31d24889c748f7f6488d049500000000488b54245848893ae923f9ffff4d85ed0f856902000048894c2418be1f000000bf20000000ff15c0d80200'
    '48894424204885c00f84a902000048894550488b4c241848ba114208218410420841bd1f000000488b058ad8020048c745581f000000488945684c89f048f7e2'
    '4c89f04829d048d1e84c8d240248ba4758ee6984e59e4649c1ec044c89e048c1e0054c29e04d89f44929c44c89f048f7ea4889d04c89f248c1fa3f48c1f80348'
    '29d0488d14c5000000004829c2488d04904c89f24829c24883c201e940fdffff4589f04c8b7c2438488bac24c00000004c8b742440e9c8fcffff498d7d01e88d'
    '150000bf200000004889c54889c6ff15ecd702004989c74885c00f84d7010000488d45fe488b542420488b4c243848894424184c89e848c1e0054889d74801d0'
    '4d85ed4989c4747e0f1f8400000000004c8b47084d85c07464448b2f31d24c8b57184c8b5f104c89e84d89e948f7f54c89e84889d631d248f77424184883c201'
    '4989d549c1e5054889f048c1e0054c01f8eb140f1f4400004801d64c01e84839f50f8689000000488378080075ea4489084c8940084c8958104c8950184883c7'
    '204939fc758a488b7c242848894c24384989ed488d04ff488d0447488d3d9edc02004c8d24c7488b7c242041ff542468488b0501d7020031d249896c24584d89'
    '7c2450488b4c243849894424684c89f048f7f54c897c24204c89f04989d431d248f77424184883c201e9f2fbffff66904829eee94fffffff4889f831d248f7f6'
    '488d049500000000e9c8fdffff4589f04c8b7c24384c8b7424404889c1488bac24c0000000e9a6f7ffff488b4510488b7c2450488b5d18488907e909fbfffff6'
    '05fad6020004754dc6831f03000001e9eefbfffff605e6d60200080f85fbfbffff488d0d28360200ba3c010000488d35731a0200488d3d25460200e8c01e0100'
    '488bac24c0000000448b8424e0000000e989f5ffff488b5330488b730831c048894c2408488d3d1d460200e8c0360000488b4c2408eb91488b7c2430ff1506d6'
    '0200488d3d2a1a020031c0e8003a0000488b5330488b730831c048894c2408488d3de2450200e885360000488b4c2408e90bfcffff66662e0f1f840000000000'
    'f30f1efa41574156415541544989fc554889d5534881ec98000000488974241048894c24184c8944240844894c2438410fb6142484d20f84340200004c89e1bb'
    '051500000f1f40004889d84883c10148c1e0054801c34801d30fb61184d275e889db488305eee4020001b8ffffffff48837c240800488944244048c744245000'
    '00000048c744245800000000740ef68424d0000000020f85700c00004883bc24d800000000488b4424184c8b080f856d0200004d85c90f84be01000048c74424'
    '2000000000488b4424204c8b6c24184c8d7c24504c8d742440eb140f1f4400004d8b4d084983c50831c04d85c9743aff7424108b7c24404d89f84c89f2488b4d'
    '00574c89e7ffb424e80000008bb424e8000000564889deff74242850e80ff3ffff4883c43085c074b7488b4d00488b5424504889c84885d20f84400100004885'
    'c9740b0fb6410583e0033c0374624c8b7c245831db410fb6871c03000083e0033c020f84ec0300004c8b5424504d89fd418bbfe403000085ff0f84d90100008b'
    '05bbd40200a9040800000f85e00100004c8955004881c4980000004c89e85b5d415c415d415e415fc30f1f8000000000837c2438010f847a04000048c7442470'
    '00000000488b44241848c7442478000000004c8b084d85c90f84500400004c8b542418837c2438044c8d442470488b5424200f944424284d89c54d89d7eb4c90'
    '6a004d89e84889de4c89e750ffb424e80000008b8424e800000050ff742428524c89f2e808f2ffff4883c43085c00f85cb0300004d8b4f084983c7084d85c90f'
    '84ba030000488b4d0031d20fb6410483e00f3c01750c807c242800b804000000759eb801000000eb970f1f8000000000bb05150000e9e8fdffff488b45004885'
    'c0740f0fb64004c0e8043c020f8481000000f605a8d30200017578488b4424104885c00f84a6040000488b700848837c2408000fb6060f84b5050000488b7c24'
    '08488d15f42702004c8d05331702004c8b0f4d85c94c0f44ca84c00f849d0400004c8d6c24704c89e1488d152e17020031c04c89efe87694ffff31ff488d1534'
    '1702004c89eee8356affff4c89efe8ed98ffff4531d24531ede972feffff6690498b01488b304839b424d80000000f8488fdffff488b8c24d800000031d26690'
    '4883c20148390cd075f64889542420e971fdffff0f1f400041c787e403000001000000e917feffff0f1f840000000000a8040f84ad000000498b4d0885db4d8b'
    '45304c8d0d84160200488d05871602004c0f44c88039007518488b0580d20200488b08488d05311202004885c9480f44c8488b442410488b7008488b5030803e'
    '007518488b0556d20200488b30488d05071202004885f6480f44f04c895424184883ec0831c04154488d3d09430200e87c320000595e488b4424084c8b542418'
    '4885c00f840d040000488b30488d3d3816020031c0e8063300008b0520d202004c8b542418f6c4080f8462fdffff488b05e3d40200488b1504d7020048c74424'
    '600000000048c7442468000000004885c00f840d0200004839d00f84040200004d85d20f8417040000410fb64204836424380383e00f3c060f841a06000031d2'
    '8b74243889f183c9083c0a0f45ce894c243885d20f8401030000488b7424104c8b4d00498b5208498b8558030000488b8e580300004929c94c8954240841b810'
    '000000488d35aa150200488d3d5f42020052ba100000006a105031c06a10e88d330000488b8424800000004531c04883c42031d24c8b5424084885c074104c8b'
    '4008488b442468488b9058030000b910000000be10000000488d3d3315020031c04c89542408e8453300004c8b5424088b7424384c89e2488d3d2715020031c0'
    '4c89542408e8263300004c8b542408e93cfcffff4c397c24100f8409fcfffff68424d0000000010f84fbfbffff4180bf1f030000000f85edfbffff8b8424d000'
    '000083e00889442420740e4180bf20030000000f85cffbffff488b442410488bb0d80300004989f54889742428488b80d00300004989c648894424284d85f60f'
    '8474020000498b0631d24885c0751ce9650200000f1f40008d42014889c2498b04c64885c00f844e0200004939c775e84c8b6c24584c8b542450e971fbffff48'
    '837c2470007427488b7424104839742478741b488b450048897424584989f74889442450bb01000000e927fbffff4c8b7c2458ebef488b4424104989ca483944'
    '24580f844503000048894c245048894424584c8b7c2410bb010000004d89fde90cfbffff48395424100f84f1fdffff410fb60c2484c90f84470400004c89e6b8'
    '051500000f1f40004889c24883c60148c1e2054801d04801c80fb60e84c975e889c6b8ffffffff488d5424484c89542428488b4d004889442448488b4424104c'
    '8b3dcad4020048c705bfd4020000000000508b7c24404c8b88a0030000574c89e76a006a00ff7424286a004c8d84249000000048895424504889742448e82eed'
    'ffff4883c4304c8b542428488b7424184c39542460488b5424200f84750200004c893d69d402004d85d20f8489010000410fb64204836424380383e00f3c060f'
    '84e6050000ba01000000e931fdffff4c8d056623020048837c2408004d89c1741d488b4424084c8d05951202004c8b08488d05452302004d85c94c0f44c8488b'
    '059bce0200488b30488d054c0e02004885f6480f44f0e946fbffff488b1576d102004885d20f94c048395424100f94c208d0750b837c2438030f8ed1f9ffff48'
    '8b7c24104c8b4d00498b5208498b8558030000488b8f580300004929c94c8954240841b810000000488d357e120200488d3d3a3f020052ba100000006a105031'
    'c06a10e8683000004883c4204c8b542408e91afdffff31c0488d3d9c2202004c89542418e8f72e00008b0511ce02004c8b542418e9ecfbffff4d85ed0f849300'
    '0000458b45004585c00f8489000000418d50ff498d4508498d54d510eb094883c0084839c274714c393875f2e97ffdffff4c8d05442202004d89c1e959faffff'
    '4885c00f94c248394424100f94c008c2750b837c2438030f8ef3f8ffff488b4424104c8b4d0031d2488b885803000031c04929c9e924ffffff488b4424104c8b'
    '4d0031d2488b885803000031c04929c9e9e3fbffff4531c0498b878004000048894424288b8424d000000083e004894424300f856f020000448944243c488d3d'
    'c4db0200ff15c6cc0200448b44243c4d89fa488b442410488d3d22d20200488b5030488d04d2488d0442488b04c74c39d00f84b90000004885c0750deb146690'
    '4c39d00f84a7000000488b40184885c075ee488d3d6fdb0200ff1569cc02008b54243085d20f84c4f6ffff64c704251c00000001000000488b442410488b8098'
    '0300004889442418e9a2f6ffff4989d2e9bdfcffff4c396c24680f8580fdffff488b442410f6801e0300000874094d85d20f853f0400004c893dd2d102004d85'
    'd20f85a2faffff488b154acf02004885d20f94c048395424100f94c208d00f84aefeffffe9b4feffff0f1f80000000004885c00f8459ffffff488b442428493b'
    '82800400000f8547ffffff4180ba1f03000000754f448b4c24204585c9740a4180ba2003000000753b488b4424100fb6801c0300008844241883e0033c020f84'
    '89000000f605f5cb0200040f85bd030000837c2420000f85bc01000041c6821f03000001488d3d5dda0200ff1557cb02008b4424304c8b6c24584c8b54245085'
    'c00f84e9f6ffff64c704251c00000001000000e9d8f6ffff4c8b4d00498b5208c744243804000000488b7c2410498b8558030000488b8f580300004929c9e91a'
    'fdffffbe05150000e9d5fbffff488b4424108b80e00300004439c00f8694010000488b7424104489c2488b86d80300004c8954d008488b86d8030000418d5001'
    '8910f60537cb0200400f8455ffffff488b442410488b48084c8b40308039007513488b05f8ca0200488b084885c90f8453040000498b7208498b5230803e0075'
)
OBS_BYTES, WIRE_BYTES, FIRST_OBS = 272288, 607936, 63360


def need(ok, why):
    if not ok:
        raise ValueError(why)


def q(data, at=0, n=1):
    return struct.unpack_from('<' + 'Q' * n, data, at)


def u(data, at=0, n=1):
    return struct.unpack_from('<' + 'I' * n, data, at)


def json_row(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            need(key not in out, 'duplicate_key')
            out[key] = value
        return out
    need(type(data) is bytes and len(data) <= 2048, 'stdout_bound')
    row = json.loads(data, object_pairs_hook=unique)
    need(type(row) is dict and all(type(x) is int for x in row.values()), 'integer_row')
    need(json.dumps(row, separators=(',', ':')).encode() + b'\n' == data, 'canonical_row')
    return row


def live(data):
    need(len(data) == 152 and data[148:] == b'\0' * 4, 'live_extent')
    return q(data, 0, 16), q(data, 128)[0], data[136:148]


def frame(data, h):
    need(len(data) == 65792, 'frame_extent')
    g = q(data, 0, 23)
    mask, address, count, initialized = q(data, 184, 4)
    need(mask == h[13] and initialized == count and 580 <= count <= FP, 'frame_header')
    need(address % 16 == 0 and h[12] + 4096 <= address <= h[12] + 4096 + 524288 - count, 'frame_storage')
    need(data[216:256] == b'\0' * 40, 'frame_padding')
    fp = data[256:]
    need(fp[count:] == b'\0' * (FP - count), 'frame_unused')
    need(u(fp, 464)[0] == 0x46505853 and u(fp, 468)[0] == count and u(fp, 480)[0] == count - 4 and u(fp, count - 4)[0] == 0x46505845 and q(fp, 520)[0] == 0, 'kernel_standard_fp')
    return g, fp, count, mask


def seed_fp(fp, layout, xsave_bytes):
    need(len(fp) == FP and struct.unpack_from('<HH', fp) == (0x37f, 0x3000) and fp[4] == 0xc0 and u(fp, 24)[0] == 0x1f80, 'seed_x87_mxcsr')
    bv, comp = q(fp, 512, 2)
    need(bv & 0xe7 == 0xe7 and comp == 0, 'seed_xstate')
    for reg in range(32):
        for word in range(8):
            if reg >= 16:
                feature, off = 7, (reg - 16) * 64 + word * 8
            elif word >= 4:
                feature, off = 6, reg * 32 + (word - 4) * 8
            elif word >= 2:
                feature, off = 2, reg * 16 + (word - 2) * 8
            else:
                feature, off = 0, 160 + reg * 16 + word * 8
            if feature:
                present, base, size = layout[feature]
                need(present == 1 and off + 8 <= size, 'seed_component')
                off += base
            need(off + 8 <= xsave_bytes and q(fp, off)[0] == 0x3141592653589793 + reg * 8 + word + 1, 'seed_vector')
    masks = (0x0123456789abcdef, 0xfedcba9876543210, 0xaaaaaaaa55555555, 0x0f0ff0f0a5a55a5a, 0x1111222233334444, 0x8877665544332211, 0xffff00000000ffff, 0x5a5a5a5aa5a5a5a5)
    need(layout[5][0] == 1 and layout[5][2] >= 64 and q(fp, layout[5][1], 8) == masks, 'seed_opmask')


def fixture(h):
    mode = h[3]
    seed = [0x3141592600000000 + i * 0x102030405 for i in range(16)]
    seed[1] = 0 if mode == 2 else h[11] + (DATA - 6 if mode == 1 else 123)
    seed[2], seed[4] = int(mode != 0), h[10] + PAGE + STACK - 504
    stack_fault = h[10] + 2 * PAGE if mode in (6, 8) else 0
    if mode == 6:
        seed[4] = stack_fault - 0x58
    if mode == 8:
        seed[4] = stack_fault + PAGE - 0x58
    r15 = h[11] + DATA - 4 - 0x3e4
    if mode == 2:
        r15 = h[11] + DATA - 1 - 0x31c
    if mode == 7:
        r15 = h[11] + DATA - 0x31c
    if mode == 9:
        r15 = h[11] + DATA - 0x3e4
    if mode == 10:
        r15 = h[11] + DATA - 2 - 0x3e4
    if mode == 0:
        seed[1] = h[11] + DATA
    if mode == 5:
        seed[1] = h[11] + DATA - 5
    data = bytearray(1 + (i * 17) % 255 for i in range(DATA))
    if mode not in (0, 2, 5):
        data[DATA - 1 if mode == 1 else 128] = 3 if mode == 1 else 1
    if mode not in (0, 1, 5, 6, 7):
        data[r15 + 0x31c - h[11]] = 2 if mode == 2 else 1
    if mode in (3, 4):
        struct.pack_into('<I', data, r15 + 0x3e4 - h[11], 0 if mode == 3 else 0x80000001)
    stack = bytes((i * 29 + 7) & 255 for i in range(160))
    operands = struct.pack('<QQ', 0x8877665544332211, r15)
    fault = stack_fault if mode == 6 else stack_fault + PAGE - 8 if mode == 8 else h[11] + DATA
    need(h[31:35] == (stack_fault, seed[4] + 0x50, seed[4] + 0x58, fault if mode >= 5 else 0), 'actual_operand_fault_geometry')
    need(seed[4] % 16 == 8 and h[10] + PAGE <= seed[4] - 128 and seed[4] + 0x60 <= h[10] + PAGE + STACK, 'full_stack_geometry')
    return tuple(seed), bytes(data), stack, operands


def descriptor(page, off, length, code, kind, operand_spec=(), memory=None, flags=(0, 0, 0, 0, 0), target=0, refusal=0):
    """Fixed specimen's independent 304-byte ABI image, not a decoder."""
    row = bytearray(304)
    pc, step = page[0] + off, int(kind in ('mov',) and memory is None)
    struct.pack_into('<QQ10I', row, 0, pc, pc + length, 1, 0, code, 0, 16, 0, step, 15, length, 0)
    row[56:72] = page[1][off:off + 15] + b'\0'
    struct.pack_into('<I', row, 232, 1)
    if refusal:
        struct.pack_into('<I', row, 240, refusal)
        return bytes(row)
    flow, condition = (1, 4) if kind == 'jcc' else (2, 16) if kind == 'jmp' else (0, 16)
    struct.pack_into('<Q', row, 72, target)
    registers = []
    for i, (form, reg, width, access, immediate, encoding) in enumerate(operand_spec):
        struct.pack_into('<Q6I', row, 80 + 32 * i, immediate, form, reg, width, access, encoding, 0)
        if form == 1 and access:
            if width == 32 and access == 3:
                registers += [(reg, 32, 1, 0), (reg, 64, 2, 0)]
            else:
                registers += [(reg, 64 if width == 32 and access == 2 else width, access, 0)]
        elif form == 2:
            registers += [(memory[1], 64, 1, 0)]
    need(len(registers) <= 3, 'fixed_register_extent')
    for i, value in enumerate(registers):
        struct.pack_into('<4I', row, 144 + 16 * i, *value)
    if memory:
        struct.pack_into('<Q8I', row, 192, *memory, 0)
    read = write = 0
    for reg, _, access, _ in registers:
        if access & 1:
            read |= 1 << reg
        if access & 2:
            write |= 1 << reg
    struct.pack_into('<18I', row, 232, 1, 1, 0, flow, condition, len(operand_spec), len(registers), int(memory is not None), *flags, read, write, 0, 0, 0)
    return bytes(row)


def exact_plan(h, source, image):
    reg = lambda r, w, a: (1, r, w, a, 0, 0)
    imm = lambda value, w: (3, 0, w, 1, value, 8)
    mem = lambda w: (2, 0, w, 1, 0, 0)
    # Fixed hardware semantics, independent of the candidate's type output.
    logic = (0, 0xc4, 0, 0x801, 0x10)
    cmpflags = (0, 0x8d5, 0, 0, 0)
    spec = {
        0: ('mov', (reg(0, 64, 2), reg(1, 64, 1)), None, (0,) * 5),
        1: ('test', (reg(2, 64, 1), reg(2, 64, 1)), None, logic),
        3: ('test', (reg(1, 64, 1), reg(1, 64, 1)), None, logic),
        5: ('load', (reg(0, 32, 2), mem(8)), (5, 1, 16, 1, 1, 64, 1, 1), (0,) * 5),
        6: ('and', (reg(0, 32, 3), imm(3, 32)), None, logic),
        7: ('cmp', (reg(0, 8, 1), imm(3, 8)), None, cmpflags),
        9: ('load', (reg(15, 64, 2), mem(64)), (0x58, 4, 16, 1, 8, 64, 2, 1), (0,) * 5),
        10: ('xor', (reg(3, 32, 2), reg(3, 32, 0)), None, (0, 0, 0x44, 0x881, 0x10)),
        11: ('load', (reg(0, 32, 2), mem(8)), (0x31c, 15, 16, 1, 1, 64, 1, 1), (0,) * 5),
        12: ('and', (reg(0, 32, 3), imm(3, 32)), None, logic),
        13: ('cmp', (reg(0, 8, 1), imm(2, 8)), None, cmpflags),
        15: ('load', (reg(10, 64, 2), mem(64)), (0x50, 4, 16, 1, 8, 64, 2, 1), (0,) * 5),
        16: ('mov', (reg(13, 64, 2), reg(15, 64, 1)), None, (0,) * 5),
        17: ('load', (reg(7, 32, 2), mem(32)), (0x3e4, 15, 16, 1, 4, 64, 1, 1), (0,) * 5),
        18: ('test', (reg(7, 32, 1), reg(7, 32, 1)), None, logic),
    }
    p = bytearray(53024)
    struct.pack_into('<12I4Q', p, 0, 1, 1, 20, 5, 5, 21, 20, 1, 77, 90, 42, 0, h[8], h[8] + 0x5f2, h[9], h[8] + 0x63f)
    p[80:4176], p[4176:8272] = source, image
    block = 0
    for i in range(20):
        if i in (3, 5, 9, 15):
            block += 1
        if i in JCC:
            target_offset = TAKEN[JCC.index(i)]
            target_head = 9 if i == 4 else 64 + (0 if i == 2 else 1 if i == 8 else 2 if i == 14 else 3)
            successors = (target_head, i + 1 if i != 19 else 68)
            n, kind = 6, 'jcc'
            original_target = h[8] + target_offset
            generated_target = h[9] + GEN[9] if i == 4 else original_target
            op = lambda target, encoding: ((4, 0, 64, 1, target, encoding),)
            d = descriptor((h[8], source), 0x5f2 + OFFSETS[i], LENGTHS[i], CODES[i], kind, op(original_target, 8 if LENGTHS[i] == 2 else 32), flags=(0x40, 0, 0, 0, 0), target=original_target)
            e = descriptor((h[9], image), GEN[i], 6, 1868, kind, op(generated_target, 32), flags=(0x40, 0, 0, 0, 0), target=generated_target)
        else:
            kind, operands, memory, flags = spec[i]
            n, successors = LENGTHS[i], (i + 1, 0)
            d = descriptor((h[8], source), 0x5f2 + OFFSETS[i], LENGTHS[i], CODES[i], kind, operands, memory, flags)
            e = descriptor((h[9], image), GEN[i], n, CODES[i], kind, operands, memory, flags)
        p[8272 + 304 * i:8272 + 304 * (i + 1)] = d
        p[28032 + 304 * i:28032 + 304 * (i + 1)] = e
        struct.pack_into('<8I', p, 47792 + 32 * i, 0x5f2 + OFFSETS[i], LENGTHS[i], GEN[i], n, 2 if i in JCC else 1, *successors, block)
        struct.pack_into('<8I2Q', p, 49904 + 48 * i, 1, 1, i, 2 if i in JCC else 1, 0x5f2 + OFFSETS[i], LENGTHS[i], GEN[i], n, h[8] + 0x5f2 + OFFSETS[i], h[9] + GEN[i])
    boundary = descriptor((h[8], source), 0x63f, 6, 285, 'load', refusal=5)
    p[27728:28032] = boundary
    p[28032 + 20 * 304:28032 + 21 * 304] = descriptor((h[9], image), 85, 5, 696, 'jmp', ((4, 0, 64, 1, h[8] + 0x63f, 32),), target=h[8] + 0x63f)
    struct.pack_into('<5Q', p, 49840, *(h[8] + x for x in EXITS))
    struct.pack_into('<8I2Q', p, 49904 + 20 * 48, 1, 1, 19, 3, 0x63f, 0, 85, 5, h[8] + 0x63f, h[9] + 85)
    return bytes(p)


def generated(h):
    output = bytearray()
    for i, (offset, length) in enumerate(zip(OFFSETS, LENGTHS)):
        if i in JCC:
            target = h[9] + GEN[9] if i == 4 else h[8] + TAKEN[JCC.index(i)]
            output += b'\x0f\x84' + struct.pack('<i', target - (h[9] + GEN[i] + 6))
        else:
            output += LITERAL[offset:offset + length]
    output += b'\xe9' + struct.pack('<i', h[8] + 0x63f - (h[9] + 90))
    need(len(output) == 90, 'complete_emission')
    return bytes(output) + b'\xcc' * (PAGE - 90)


def path_and_result(h, seed, data, operands):
    """Expected retired heads and defined GPRs only; AF is actual native equality."""
    mode = h[3]
    path = list(range(20))
    if mode == 0:
        path = [0, 1, 2]
    elif mode == 1:
        path = list(range(9))
    elif mode == 2:
        path = [0, 1, 2, 3, 4, 9, 10, 11, 12, 13, 14]
    elif mode >= 5:
        path = path[:FAULT_HEADS[mode - 5]]
    result = list(seed)
    for i in path:
        if i == 0:
            result[0] = result[1]
        elif i == 5:
            result[0] = data[result[1] + 5 - h[11]]
        elif i in (6, 12):
            result[0] &= 3
        elif i == 9:
            result[15] = q(operands, 8)[0]
        elif i == 10:
            result[3] = 0
        elif i == 11:
            result[0] = data[result[15] + 0x31c - h[11]]
        elif i == 15:
            result[10] = q(operands)[0]
        elif i == 16:
            result[13] = result[15]
        elif i == 17:
            result[7] = u(data, result[15] + 0x3e4 - h[11])[0]
    pcs = [h[8] + 0x5f2 + OFFSETS[i] for i in path[1:]]
    pcs.append(h[35])
    need(len(path) == TRACES[mode], 'fixed_path_count')
    return tuple(pcs), tuple(result)


def observation(data, h, seed, layout, memory, stack, operands, which):
    need(len(data) == OBS_BYTES, 'observation_extent')
    before, after = live(data[:152]), live(data[152:304])
    xbefore, xafter = data[304:65840], data[65840:131376]
    entry, ending = frame(data[131376:197168], h), frame(data[197168:262960], h)
    entry_si, exit_si = data[262960:263088], data[263088:263216]
    got_stack, got_memory, got_operands = data[263216:263376], data[263376:271568], data[271568:271584]
    trace, meta = q(data, 271584, 64), q(data, 272096, 24)
    mode, fault = h[3], h[3] >= 5
    head = FAULT_HEADS[mode - 5] if fault else (2, 8, 14, 19, 19)[mode]
    raw_pc = h[9] + GEN[head] if which and fault else h[35]
    expected_meta = (which, 2 if which and not fault else 1, 0 if which else TRACES[mode], 2 if fault else 1, raw_pc, h[35])
    need(meta[:6] == expected_meta and meta[8:] == (1, 1, h[34], head, 0x5f2 + OFFSETS[head] if fault else EXITS[mode], GEN[head] if fault else MASK64, h[13], int(mode in (6, 8)), TRACES[mode], 1, 1, meta[6], meta[7], h[13], 0, 0), 'complete_event_metadata')
    path, result = path_and_result(h, seed, memory, operands)
    need(trace == ((0,) * 64 if which else path + (0,) * (64 - len(path))), 'actual_complete_trace_path')
    need(before[0] == seed and before[1] == h[23] and before[2] == after[2] and after[0] == result, 'complete_seed_and_defined_gprs')
    need(xbefore == xafter and entry[1:] == ending[1:], 'complete_fp_and_mask')
    for fp in (xbefore, xafter, entry[1], ending[1]):
        seed_fp(fp, layout, h[7])
    need(got_stack == stack and got_memory == memory and got_operands == operands, 'every_stack_data_operand_byte')
    need(tuple(entry[0][r] for r in REGS) == seed and entry[0][16] == h[8] + 0x5f2 and entry[0][17] == h[23] | RF and entry[0][19:] == (21, 14, h[13], h[8] + 0x5f2), 'authentic_original_nx_entry')
    need(u(entry_si, 0, 3) == (11, 0, 2) and q(entry_si, 16)[0] == h[8] + 0x5f2, 'entry_siginfo')
    need(tuple(ending[0][r] for r in REGS) == after[0] and ending[0][16] == raw_pc and ending[0][21] == h[13], 'actual_ending_state')
    flags = after[1] | (RF if which or fault else TF) | (TF if fault and not which else 0)
    need(ending[0][17] == flags and not after[1] & (TF | RF), 'full_flags_including_af')
    cs, ss, ds, es, fs, gs = struct.unpack('<6H', before[2])
    need(entry[0][18] == ending[0][18] == cs | gs << 16 | fs << 32 | ss << 48, 'actual_live_signal_selectors')
    if fault:
        need(ending[0][19:21] == (4, 14) and ending[0][22] == h[34] and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == h[34], 'genuine_read_fault')
    elif which:
        need(ending[0][19:21] == (21, 14) and ending[0][22] == h[35] and u(exit_si, 0, 3) == (11, 0, 2) and q(exit_si, 16)[0] == h[35], 'genuine_original_nx_exit')
    else:
        need(ending[0][19:21] == (0, 1) and ending[0][22] == h[8] + 0x5f2 and u(exit_si, 0, 3) == (5, 0, 2), 'actual_reference_trace')
    return before, after, xbefore, xafter, entry, ending, meta, got_stack, got_memory, got_operands


def check(record, stdout, stderr, exit_status, mode):
    need(type(mode) is int and 0 <= mode <= 10 and type(exit_status) is int and exit_status == (125 if mode >= 5 else 0), 'actual_required_exit')
    need(type(record) is bytes and len(record) == WIRE_BYTES and stderr == b'', 'whole_closed_capture')
    h = q(record, 0, 48)
    need(h[:6] == (0x314745524332494c, 1, 48, mode, 0, 1) and h[14:20] == (53024, 65792, FP, DATA, 160, 2), 'complete_header')
    need(h[6] & 0xe7 == 0xe7 and 576 <= h[7] <= FP and h[8] + PAGE == h[9] and all(x > 0 and x % PAGE == 0 for x in h[8:13]), 'actual_mapping_layout')
    ranges = ((h[8], 2 * PAGE), (h[10], STACK + 2 * PAGE), (h[11], DATA + PAGE), (h[12], 524288 + 2 * PAGE))
    need(all(a + n <= b or b + m <= a for i, (a, n) in enumerate(ranges) for b, m in ranges[i + 1:]), 'disjoint_owned_ranges')
    need(h[13] == MASK64 & ~sum(1 << (sig - 1) for sig in (11, 5, 31, 9, 19)), 'exact_application_mask')
    need(h[20:26] == (4, 21, 69, 0x202 if mode % 2 else 0xad7, TRACES[mode], int(mode >= 5)), 'fixed_native_population')
    need(h[26] > 0 and h[28] > 0 and h[26] != h[28] and h[27] == h[29] and h[30] == 15, 'actual_distinct_sealed_files')
    need(h[36:] == (OBS_BYTES, 48, 20, 5, 5, 90, 77, 21, 69, 0, 0, 0), 'fixed_abi_census')
    expected_pc = h[8] + (EXITS[mode] if mode < 5 else 0x5f2 + OFFSETS[FAULT_HEADS[mode - 5]])
    need(h[35] == expected_pc, 'fixed_terminal_pc')
    seed, data, stack, operands = fixture(h)
    need(q(record, 384, 16) == seed, 'exact_initial_registers')
    layout = tuple(q(record, 512 + i * 24, 3) for i in range(64))
    for feature, (present, offset, size) in enumerate(layout):
        if feature < 2 or not (h[6] >> feature & 1):
            need((present, offset, size) == (0, 0, 0), 'unused_cpuid_row')
        else:
            need(present == 1 and offset >= 576 and size > 0 and offset + size <= h[7], 'actual_cpuid_component')
    stats = record[2048:2096]
    need(stats == record[2096:2144] and u(stats, 0, 4) == (1, 2, 0, 0) and q(stats, 16)[0] == 2 << 20 and 0 < q(stats, 24)[0] <= 2 << 20, 'complete_postseal_allocator_equality')
    source, image, p = record[2144:6240], record[6240:10336], record[10336:FIRST_OBS]
    need(source == SOURCE_PAGE and source[0x5f2:0x5f2 + len(LITERAL)] == LITERAL, 'whole_source_snapshot')
    need(image == generated(h), 'whole_emitted_image')
    need(p == exact_plan(h, source, image), 'complete_actual_plan_and_every_descriptor')
    n = observation(record[FIRST_OBS:FIRST_OBS + OBS_BYTES], h, seed, layout, data, stack, operands, 0)
    g = observation(record[FIRST_OBS + OBS_BYTES:], h, seed, layout, data, stack, operands, 1)
    need(n[:4] == g[:4] and n[4][0] == g[4][0] and n[4][1:] == g[4][1:] and n[5][1:] == g[5][1:] and n[6][6:8] == g[6][6:8] and n[7:] == g[7:], 'full_native_generated_state')
    expected = list(n[5][0])
    expected[17] &= ~TF
    if mode >= 5:
        expected[16] = h[9] + GEN[FAULT_HEADS[mode - 5]]
    else:
        expected[17] |= RF; expected[19] = 21; expected[20] = 14; expected[22] = h[35]
    need(tuple(expected) == g[5][0], 'all_23_actual_gregs_with_exact_event_association')
    result = dict(schema=1, mode=mode, qualified_comparison=1, completed_path=int(mode < 5), required_read_failure=int(mode >= 5), cleanup=1, reference_trace=TRACES[mode], generated_trace=0, exit_kind=2 if mode >= 5 else 1, authority_controls=4, head_checks=21, interior_misses=69, postseal_equal=1)
    need(json_row(stdout) == result, 'exact_numeric_summary')
    return result


def controls(record, stdout, stderr, exit_status, mode):
    """Call only after the actual record passed check(); no fabricated baseline."""
    a, b = FIRST_OBS, FIRST_OBS + OBS_BYTES
    locations = [('version', 8), ('error', 32), ('cleanup', 40), ('mode', 24), ('abi', 112), ('seed', 384), ('cpuid_unused', 512), ('allocator_before', 2080), ('allocator_after', 2128), ('source_tail', 6239), ('image_tail', 10335), ('plan_source', 10336 + 80), ('plan_effect', 10336 + 8272 + 264), ('plan_unused', 10336 + 8272 + 63 * 304), ('plan_map', 10336 + 49904 + 32), ('reference_before', a), ('reference_after', a + 152), ('reference_af', a + 280), ('reference_selectors', a + 288), ('before_fp_tail', a + 65839), ('after_fp_tail', a + 131375), ('entry_fp_tail', a + 197167), ('exit_fp_tail', a + 262959), ('entry_si', a + 262960), ('stack_tail', a + 263375), ('data_tail', a + 271567), ('operand_tail', a + 271583), ('trace_path', a + 271584), ('actual_fs', a + 272096 + 48), ('generated_gpr', b + 152), ('generated_af', b + 280), ('generated_fp_tail', b + 131375), ('generated_stack', b + 263375), ('generated_operand', b + 271583), ('generated_trace', b + 272096 + 16), ('generated_nx', b + 272096 + 8), ('restored_stack', b + 272096 + 120), ('before_fs', b + 272096 + 152), ('before_mask', b + 272096 + 168)]
    trials = []
    for name, offset in locations:
        value = bytearray(record); value[offset] ^= 0x10 if name.endswith('_af') else 1
        trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    # Coherent aliases leave all old cross-lane/live/frame equalities intact.
    for name, offsets in [('coherent_live_cs', (a + 136, a + 288, b + 136, b + 288)), ('coherent_signal_cs', (a + 131376 + 18 * 8, a + 197168 + 18 * 8, b + 131376 + 18 * 8, b + 197168 + 18 * 8))]:
        value = bytearray(record)
        for at in offsets:
            value[at] ^= 1
        trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    trials += [('truncated', (record[:-1], stdout, stderr, exit_status, mode)), ('appended', (record + b'\0', stdout, stderr, exit_status, mode)), ('extra_stdout', (record, stdout + b'\n', stderr, exit_status, mode)), ('stderr', (record, stdout, b'x', exit_status, mode)), ('wrong_exit', (record, stdout, stderr, 0 if exit_status else 125, mode))]
    if mode >= 5:
        for name, at in [('fault_cr2', b + 197168 + 22 * 8), ('fault_pc', b + 197168 + 16 * 8), ('fault_tf', b + 197168 + 17 * 8 + 1)]:
            value = bytearray(record); value[at] ^= 1
            trials.append((name, (bytes(value), stdout, stderr, exit_status, mode)))
    row = json.loads(stdout); row['qualified_comparison'] = True
    trials.append(('bool_output', (record, json.dumps(row, separators=(',', ':')).encode() + b'\n', stderr, exit_status, mode)))
    need(len(trials) == 47 + 3 * int(mode >= 5) and len({name for name, _ in trials}) == len(trials), 'fixed_unique_reader_controls')
    for name, arguments in trials:
        try:
            check(*arguments)
        except ValueError:
            continue
        raise ValueError('accepted supplied mutation ' + name)
    return [name for name, _ in trials]


if __name__ == '__main__':
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('record', 'stdout', 'stderr'):
        parser.add_argument(name, type=Path)
    parser.add_argument('exit_status', type=int); parser.add_argument('mode', type=int)
    args = parser.parse_args()
    print(json.dumps(check(args.record.read_bytes(), args.stdout.read_bytes(), args.stderr.read_bytes(), args.exit_status, args.mode), separators=(',', ':')))
