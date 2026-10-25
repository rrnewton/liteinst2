"""Authenticate distinct fd-stat and mapped-superblock identity domains."""
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python disables mapping identity checks")

def backing_identity(record, fdinfo, mountinfo, fd_path, expected_path,
                     stat_dev, stat_ino, stat_size, digest):
    assert record.keys() == {'fd','stat_dev','stat_ino','stat_size','sha256'}
    assert int(record['fd']) >= 0
    assert (int(record['stat_dev']),int(record['stat_ino']),int(record['stat_size']),record['sha256']) == (stat_dev,stat_ino,stat_size,digest)
    assert fd_path == expected_path
    rows = [line.split(':',1) for line in fdinfo.splitlines()]
    assert all(len(row)==2 for row in rows)
    parsed = {key:value.strip() for key,value in rows}
    assert len(parsed)==len(rows) and {'mnt_id','ino','pos','flags'} <= parsed.keys()
    assert int(parsed['ino']) == stat_ino and int(parsed['pos']) >= 0
    int(parsed['flags'],8)
    mount_id = int(parsed['mnt_id']); assert mount_id > 0
    lines = mountinfo.splitlines(); assert len(lines)==1
    fields = lines[0].split()
    assert fields.count('-')==1
    separator = fields.index('-')
    assert separator >= 6 and len(fields)==separator+4
    assert int(fields[0])==mount_id and int(fields[1]) > 0
    device = fields[2].split(':'); assert len(device)==2
    major,minor = (int(value) for value in device)
    assert major >= 0 and minor >= 0
    # Linux emits escaped mount paths. This finite fixture has no escapes;
    # accepting arbitrary path encodings would need a separately tested parser.
    root,mountpoint=fields[3:5]
    assert root.startswith('/') and mountpoint.startswith('/')
    assert '\\' not in root and '\\' not in mountpoint
    assert expected_path==mountpoint or expected_path.startswith(mountpoint.rstrip('/')+'/')
    assert all(fields[index] for index in (5,separator+1,separator+2,separator+3))
    return (major,minor,stat_ino)

def require_mapping_identity(backing, major, minor, inode):
    assert (major,minor,inode)==backing
