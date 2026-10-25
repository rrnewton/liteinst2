"""Join captured retained-fd proofs to independently frozen file identities."""
import sys
if sys.flags.optimize:
    raise SystemExit('optimized Python is forbidden')
import re
from mapping_identity import backing_identity

FIELDS = re.compile(r'^consumer_backing role=(main|interpreter|libgcc) fd=([0-9]+) stat_dev=([0-9]+) inode=([0-9]+) bytes=([0-9]+) mount_major=([0-9]+) mount_minor=([0-9]+) mount_id=([0-9]+) path=(\S+) fdinfo_hex=([0-9a-f]+) mountinfo_hex=([0-9a-f]+) fd_path_hex=([0-9a-f]+) whole_file_bytes_exact=true$')


def backing_records(text, images, cohorts):
    assert cohorts in (2, 3)
    assert set(images) == {'main', 'interpreter', 'libgcc'}
    lines = [line for line in text.splitlines() if line.startswith('consumer_backing')]
    assert len(lines) == 3 * cohorts
    result, first, descriptors = {}, {}, set()
    for index, line in enumerate(lines):
        match = FIELDS.fullmatch(line)
        assert match, 'complete native backing record grammar'
        role, fd, dev, ino, size, major, minor, mount_id, path, fd_hex, mount_hex, path_hex = match.groups()
        assert role == ('main', 'interpreter', 'libgcc')[index % 3]
        image = images[role]
        assert path == image['resolved']
        assert (int(dev), int(ino), int(size)) == (image['device'], image['inode'], image['size'])
        fdinfo, mountinfo, fd_path = (bytes.fromhex(value).decode('utf-8') for value in (fd_hex, mount_hex, path_hex))
        # This digest is the caller's independently frozen/currently rehashed
        # whole-file identity, NOT a digest claimed to be measured by the child.
        # The frozen native producer independently compares every retained-fd
        # byte with its held original bytes, including the libgcc frozen copy.
        record = dict(fd=fd, stat_dev=dev, stat_ino=ino, stat_size=size, sha256=image['sha256'])
        owner = backing_identity(record, fdinfo, mountinfo, fd_path, path,
                                 image['device'], image['inode'], image['size'], image['sha256'])
        assert owner == (int(major), int(minor), image['inode'])
        fields = dict(line.split(':', 1) for line in fdinfo.splitlines())
        assert int(fields['mnt_id']) == int(mount_id)
        assert int(fields['pos']) == 0 and int(fields['flags'], 8) & 3 == 0
        if index < 3:
            assert int(fd) not in descriptors
            descriptors.add(int(fd))
            first[role] = line
            result[role] = owner
        else:
            assert line == first[role], 'retained descriptor identity changed between checks'
    return result
