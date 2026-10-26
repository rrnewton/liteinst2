"""Additional pure record-join controls; no loading, tracing or child launch."""
import sys
if sys.flags.optimize:
    raise SystemExit('optimized Python is forbidden')
import copy
import json
from backing_records import backing_records
from calibrate_identity import calibrate

ROLES = ('main', 'interpreter', 'libgcc')
IMAGES = {role: dict(resolved='/fixture/' + role, device=48, inode=77 + index,
                     size=4096 + index, sha256=str(index + 1) * 64)
          for index, role in enumerate(ROLES)}


def record(role, descriptor):
    image = IMAGES[role]
    info = f"pos:\t0\nflags:\t02100000\nmnt_id:\t123\nino:\t{image['inode']}\n"
    mount = '123 12 0:42 /sub /fixture rw - btrfs /dev/mock rw'
    return (f"consumer_backing role={role} fd={descriptor} stat_dev=48 inode={image['inode']} bytes={image['size']} "
            f"mount_major=0 mount_minor=42 mount_id=123 path={image['resolved']} "
            f"fdinfo_hex={info.encode().hex()} mountinfo_hex={mount.encode().hex()} "
            f"fd_path_hex={image['resolved'].encode().hex()} whole_file_bytes_exact=true")


BASE = [record(role, index + 3) for index, role in enumerate(ROLES)] * 3


def checked(lines, images=IMAGES, cohorts=3):
    result = backing_records('\n'.join(lines) + '\n', images, cohorts)
    assert result == {role: (0, 42, image['inode']) for role, image in images.items()}


def main():
    old = calibrate()
    assert (old['positive'], old['negative']) == (2, 17)
    checked(BASE)
    checked(BASE[:6], cohorts=2)
    cases = []
    def replace(name, before, after, index=0):
        lines = BASE.copy()
        assert before in lines[index]
        lines[index] = lines[index].replace(before, after, 1)
        cases.append((name, lines))
    replace('wrong_record_stat_device', 'stat_dev=48', 'stat_dev=49')
    replace('wrong_record_inode', 'inode=77', 'inode=78')
    replace('wrong_record_size', 'bytes=4096', 'bytes=4095')
    replace('wrong_record_path', 'path=/fixture/main ', 'path=/fixture/other ')
    replace('wrong_record_mount_device', 'mount_minor=42', 'mount_minor=43')
    replace('wrong_record_mount_id', 'mount_id=123', 'mount_id=124')
    replace('false_full_file_check', 'whole_file_bytes_exact=true', 'whole_file_bytes_exact=false')
    replace('nonhex_fdinfo', 'fdinfo_hex=', 'fdinfo_hex=z')
    replace('wrong_fd_path_bytes', '/fixture/main'.encode().hex(), '/fixture/other'.encode().hex())
    replace('unknown_role', 'role=main', 'role=other')
    replace('unreadable_access_mode', '3032313030303030', '3032313030303031')
    replace('nonzero_fd_position', '706f733a09300a', '706f733a09310a')
    replace('retained_descriptor_changed', 'fd=3', 'fd=9', index=3)
    replace('duplicate_retained_descriptor', 'fd=4', 'fd=3', index=1)
    cases.append(('missing_required_record', BASE[:-1]))
    cases.append(('duplicate_required_record', BASE + [BASE[0]]))
    reordered = BASE.copy();reordered[0], reordered[1] = reordered[1], reordered[0]
    cases.append(('reordered_roles', reordered))
    cases.append(('unsupported_extra_field', [BASE[0] + ' ignored=true'] + BASE[1:]))
    assert len(cases) == 18 and len({name for name, _ in cases}) == 18
    for name, lines in cases:
        try:
            checked(lines)
        except (AssertionError, ValueError, UnicodeDecodeError):
            pass
        else:
            raise AssertionError('required backing-record refusal accepted: ' + name)
    print(json.dumps(dict(legacy=old, added_positive=2, added_negative=18,
                         names=[name for name, _ in cases], total_positive=4,
                         total_negative=35, native_executed=False), sort_keys=True))


if __name__ == '__main__':
    main()
