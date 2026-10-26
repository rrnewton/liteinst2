//! Shared bounded read for test-only owned-process inventories.

use std::io::{self, Read};

/// Reads at most 4,097 bytes, distinguishing disappearance before any byte.
///
/// Only raw ENOENT or ESRCH before the first byte means the process vanished.
/// Every error after a partial read and every other error is returned intact.
/// A full 4,097-byte result is preserved for the caller's existing size refusal.
pub(super) fn read_bounded_stat(mut reader: impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = vec![0; 4097];
    let mut used = 0;
    while used < bytes.len() {
        match reader.read(&mut bytes[used..]) {
            Ok(0) => {
                bytes.truncate(used);
                return Ok(Some(bytes));
            }
            Ok(count) => used += count,
            Err(error)
                if used == 0
                    && matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(Some(bytes))
}
