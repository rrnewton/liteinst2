"""Exact reviewed native frame/context helpers, shared by the RET observation only."""
import hashlib
import struct
PAGE, FP, STACK, FRAME = 4096, 65536, 16384, 67072
REG = (13, 14, 12, 11, 15, 10, 9, 8, 0, 1, 2, 3, 4, 5, 6, 7)
MASK64 = (1 << 64)-1
STATUS, TF, RF = 0x8D5, 0x100, 0x10000

def need(value, message):
    if not value:
        raise ValueError(message)



def words(raw, count, offset=0):
    return struct.unpack_from('<'+'Q'*count, raw, offset)



def digest(raw):
    return hashlib.sha256(raw).hexdigest()



def flags(value):
    return 0x202 | sum(1 << bit for i, bit in enumerate((0, 2, 4, 6, 7, 11)) if value & (1 << i))



def frame(raw, header, phase):
    need(len(raw) == FRAME, 'whole frame')
    h, greg = words(raw, 16), words(raw, 23, 128)
    mask, info, context, fp = raw[312:440], raw[440:568], raw[568:1536], raw[1536:]
    need(h[11] == header[16] and h[12] == phase, 'actual CPU and event order')
    need(header[24] <= h[10] < header[24]+header[25] and
         header[24] <= h[6] <= header[24]+header[25]-h[7], 'actual alternate-stack geometry')
    need(512 <= h[7] <= FP and not any(fp[h[7]:]), 'whole FP extent and zero unused tail')
    magic = struct.unpack_from('<I', fp, 464)[0]
    if magic == 0x46505853:
        need(struct.unpack_from('<I', fp, 468)[0] == h[7] and h[7] >= 576 and
             struct.unpack_from('<I', fp, h[7]-4)[0] == 0x46505845 and
             struct.unpack_from('<I', fp, 480)[0] <= h[7]-4, 'actual xstate framing')
    else:
        need(h[7] == 512, 'legacy FP framing')
    need(words(context, 23, 40) == greg and words(context, 1, 224)[0] == h[6] and
         context[296:424] == mask and words(context, 2) == h[4:6], 'whole ucontext joins')
    # Linux x86-64 delivers an eight-byte kernel sigset. The remaining
    # 120 bytes copied through glibc's larger uc_sigmask alias the adjacent
    # event siginfo; retain and authenticate every byte of that raw span.
    need(mask == bytes(mask[:8])+bytes(info[:120]) and context[304:432] == info,
         'whole raw mask span and complete embedded siginfo match their independent captures')
    sig, error, code = struct.unpack_from('<iii', info)
    need((sig, error & MASK64, code & MASK64) == (h[0], h[2], h[1]) and
         words(info, 1, 16)[0] == h[3], 'whole siginfo joins')
    need((greg[20], greg[19], greg[22]) == h[13:16], 'raw trap/error/CR2 joins')
    return h, greg, fp



def normalized_context(raw, greg, info):
    context = bytearray(raw[568:1536])
    context[40:224] = struct.pack('<23Q', *greg)
    context[224:232] = bytes(8)  # actual FP pointer is independently joined to its full captured storage
    # frame() first authenticates all128 embedded bytes against this separate
    # siginfo capture; pair() changes only its exact architectural endpoint.
    context[304:432] = info
    return bytes(context)
