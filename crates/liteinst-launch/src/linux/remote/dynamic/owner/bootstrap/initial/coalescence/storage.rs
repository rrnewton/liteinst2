//! Exact-layout payloads. The caller installs each returned owner before the
//! next fallible operation; no initialized value is ever abandoned on error.
use super::*;

pub(super) fn vector<T>(count: usize) -> Result<Vec<T>, LaunchError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if size_of::<T>() == 0 {
        return Err(invalid());
    }
    let layout = std::alloc::Layout::array::<T>(count).map_err(|_| invalid())?;
    if layout.size() > isize::MAX as usize {
        return Err(invalid());
    }
    let pointer = unsafe { std::alloc::alloc(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(LaunchError::Invalid(
            "initial coalescence allocation failed",
        ));
    }
    // SAFETY: the global allocator supplied precisely this nonzero layout and
    // alignment. Length zero exposes no uninitialized T. Vec now solely owns
    // this allocation and will deallocate with the same layout.
    Ok(unsafe { Vec::from_raw_parts(pointer, 0, count) })
}

pub(super) fn string(count: usize) -> Result<String, LaunchError> {
    let bytes = vector(count)?;
    // SAFETY: the vector is empty, hence valid UTF-8. Filling is through String.
    Ok(unsafe { String::from_utf8_unchecked(bytes) })
}

pub(super) fn mapping_bytes(row: &MemoryMapping) -> Result<usize, LaunchError> {
    add(
        row.permissions.capacity(),
        row.pathname.as_ref().map_or(0, String::capacity),
    )
}

pub(super) fn mappings_bytes(rows: &Vec<MemoryMapping>) -> Result<usize, LaunchError> {
    let mut bytes = mul(rows.capacity(), size_of::<MemoryMapping>())?;
    for row in rows {
        bytes = add(bytes, mapping_bytes(row)?)?;
    }
    Ok(bytes)
}

pub(super) fn add(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_add(b).ok_or_else(invalid)
}
pub(super) fn mul(a: usize, b: usize) -> Result<usize, LaunchError> {
    a.checked_mul(b).ok_or_else(invalid)
}
