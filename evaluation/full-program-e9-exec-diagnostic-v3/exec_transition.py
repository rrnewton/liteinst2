"""One kernel-specific exec return distinction; no launch or debugger dependency."""
import hashlib
import struct

KERNEL_BUILD_ID = "fa15f90afce5930f146e2138d2ba10eb95e3e5ad"
PROFILE = "linux-fa15f90-native-elf-execveat-322-to-59-v1"


def kernel_identity(notes):
    if not 0 < len(notes) <= 65536:
        raise RuntimeError("kernel notes extent")
    offset = 0
    build_ids = []
    while offset < len(notes):
        if len(notes) - offset < 12:
            raise RuntimeError("truncated kernel note header")
        namesz, descsz, kind = struct.unpack_from("<III", notes, offset)
        name_start = offset + 12
        name_end = name_start + namesz
        desc_start = (name_end + 3) & ~3
        desc_end = desc_start + descsz
        end = (desc_end + 3) & ~3
        if name_end > len(notes) or end > len(notes):
            raise RuntimeError("truncated kernel note")
        if kind == 3 and notes[name_start:name_end] == b"GNU\0":
            build_ids.append(notes[desc_start:desc_end].hex())
        offset = end
    if build_ids != [KERNEL_BUILD_ID]:
        raise RuntimeError("unproved running kernel build ID")
    return dict(profile=PROFILE, build_id=KERNEL_BUILD_ID, notes_bytes=len(notes),
                notes_sha256=hashlib.sha256(notes).hexdigest())


def running_kernel_identity():
    with open("/sys/kernel/notes", "rb") as f:
        first = f.read(65537)
    with open("/sys/kernel/notes", "rb") as f:
        second = f.read(65537)
    if first != second:
        raise RuntimeError("running kernel notes changed")
    return kernel_identity(first)


def exec_return_kind(*, entered, pending, number, orig_rax, signed_rax,
                     exec_seen, kernel_build_id, pending_frame, frame):
    if number != orig_rax:
        raise RuntimeError("syscall detail/register identity")
    if not entered or pending not in (59, 322):
        raise RuntimeError("syscall return without matching authenticated request")
    if number == pending:
        return "EXACT_PENDING_RETURN"
    # Proved only for this running kernel's native ELF personality transition.
    # The pending frame retains the authenticated request's RIP and argument GPRs.
    if (pending == 322 and number == 59 and not exec_seen
            and kernel_build_id == KERNEL_BUILD_ID and -4095 <= signed_rax < 0
            and isinstance(pending_frame, tuple) and len(pending_frame) == 6
            and all(type(x) is int and 0 <= x < 1 << 64 for x in pending_frame)
            and frame == pending_frame):
        return "CANONICALIZED_POSTCOMMIT_EXEC_ERROR"
    raise RuntimeError("syscall return without matching authenticated request")
