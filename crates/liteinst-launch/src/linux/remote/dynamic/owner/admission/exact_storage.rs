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

/// Exact empty owning slots. Successful return owns every initialized None; a
/// slot grants no fact or native authority. The caller installs it before any
/// later fallible allocation and accounts this exact payload once.
pub(super) fn empty_slots<T>(count: usize) -> Result<Box<[Option<Box<T>>]>, AllocationError> {
    if count == 0 {
        return Ok(Box::new([]));
    }
    let layout = Layout::array::<Option<Box<T>>>(count).map_err(|_| AllocationError::Capacity)?;
    // SAFETY: nonzero checked global layout, aligned for Option<Box<T>>.
    // Null is handled before any owner is published. No T is constructed.
    let pointer = unsafe { alloc_zeroed(layout) }.cast::<Option<Box<T>>>();
    if pointer.is_null() {
        return Err(AllocationError::Allocation);
    }
    // SAFETY: initialize each element explicitly instead of relying on zero
    // representation. None initialization cannot invoke user code or panic.
    // The returned slice has exactly count elements and deallocates the same
    // Layout; each later Some owns precisely its original Box<T>.
    unsafe {
        for index in 0..count {
            pointer.add(index).write(None);
        }
        Ok(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pointer, count,
        )))
    }
}

/// One exact value owner. Stack-profile callers pass only empty fixed headers;
/// on allocation failure value is still locally owned and is dropped normally.
pub(super) fn value<T>(value: T) -> Result<Box<T>, AllocationError> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        // A ZST has no allocation; Box uses its aligned dangling ZST owner.
        return Ok(Box::new(value));
    }
    // SAFETY: checked nonzero global allocation with T's exact alignment.
    let pointer = unsafe { alloc_zeroed(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(AllocationError::Allocation);
    }
    // SAFETY: one initialized T, uniquely owned, with identical Box drop
    // layout. No fallible work or user callback intervenes before transfer.
    unsafe {
        pointer.write(value);
        Ok(Box::from_raw(pointer))
    }
}

/// Exact uninitialized element storage. The caller installs this empty owner
/// before any later check/hook. No T exists until the caller moves it in.
pub(super) fn empty_vec<T>(capacity: usize) -> Result<Vec<T>, AllocationError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| AllocationError::Capacity)?;
    if layout.size() == 0 {
        return Err(AllocationError::Capacity);
    }
    // SAFETY: checked nonzero global layout, aligned for T. No T is initialized.
    let pointer = unsafe { alloc_zeroed(layout) }.cast::<T>();
    if pointer.is_null() {
        return Err(AllocationError::Allocation);
    }
    // SAFETY: unique exact capacity with length zero; Vec deallocates the same
    // layout. No fallible work/callback separates allocation and ownership.
    Ok(unsafe { Vec::from_raw_parts(pointer, 0, capacity) })
}
