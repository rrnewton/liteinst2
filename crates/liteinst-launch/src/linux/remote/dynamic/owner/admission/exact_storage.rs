//! Safe owning containers with exact prepaid capacities. Allocation only: this
//! boundary performs no native observation, task operation or permission change.
use std::alloc::{Layout, alloc_zeroed};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AllocationError {
    Capacity,
    Allocation,
}

pub(super) fn empty_bytes(capacity: usize) -> Result<Vec<u8>, AllocationError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(capacity).map_err(|_| AllocationError::Capacity)?;
    // SAFETY: the checked nonzero layout uses the global allocator and u8's
    // alignment. The returned owning Vec will deallocate the identical layout.
    let pointer = unsafe { alloc_zeroed(layout) };
    if pointer.is_null() {
        return Err(AllocationError::Allocation);
    }
    // SAFETY: a unique valid allocation of exactly capacity bytes, len zero,
    // and matching allocator/alignment. Spare capacity is never exposed as len.
    Ok(unsafe { Vec::from_raw_parts(pointer, 0, capacity) })
}

pub(super) fn one<T>(value: T) -> Result<Box<[T]>, AllocationError> {
    let layout = Layout::array::<T>(1).map_err(|_| AllocationError::Capacity)?;
    if layout.size() == 0 {
        return Err(AllocationError::Capacity);
    }
    // SAFETY: checked nonzero one-element layout, aligned for T. Allocation
    // failure leaves value locally owned and drops it normally on return.
    let pointer = unsafe { alloc_zeroed(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(AllocationError::Allocation);
    }
    // SAFETY: initialize the sole element before exposing the owning slice.
    // No fallible operation or user code intervenes between write and transfer.
    // Box<[T]> drops one initialized T and frees this exact global layout.
    unsafe {
        pointer.write(value);
        Ok(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pointer, 1,
        )))
    }
}
