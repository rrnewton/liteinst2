//! Private borrowed process-text adapter; not an owning executable allocation.
use super::{Mapping, NativeOracle, PAGE, STACK_BYTES};
use std::mem::ManuallyDrop;
use std::ops::Deref;

pub struct ProcessTextOracle {
    inner: ManuallyDrop<NativeOracle>,
}

impl ProcessTextOracle {
    /// # Safety
    /// `page` is the aligned, full readable/executable assembly fixture page,
    /// kept mapped for this process's lifetime. No other caller can execute or
    /// mutate it during a publication lease. The adapter never owns/unmaps it.
    pub unsafe fn new(page: u64) -> Self {
        assert_eq!(page % PAGE as u64, 0);
        let code = Mapping {
            address: page as usize as *mut u8,
            len: PAGE,
        };
        // Build owning allocations before assembling the borrowed code guard.
        // ManuallyDrop prevents the process text alias from ever reaching munmap.
        let code = ManuallyDrop::new(code);
        let data = Mapping::new(PAGE);
        data.initialize(
            0,
            &(0..PAGE).map(|i| (i * 37 + 11) as u8).collect::<Vec<_>>(),
        );
        let stack = Mapping::new(STACK_BYTES + PAGE);
        stack.initialize(0, &vec![0x5a; STACK_BYTES + PAGE]);
        assert_eq!(
            unsafe { libc::mprotect(stack.writable().cast(), PAGE, libc::PROT_NONE) },
            0
        );
        let initial_rsp = stack.address() + STACK_BYTES as u64 - 8;
        let return_pc = page + (PAGE / 2) as u64;
        stack.initialize(
            (initial_rsp - stack.address()) as usize,
            &return_pc.to_ne_bytes(),
        );
        let original_code = code.bytes().to_vec();
        Self {
            inner: ManuallyDrop::new(NativeOracle {
                code: ManuallyDrop::into_inner(code),
                data,
                stack,
                initial_rsp,
                return_pc,
                original_code,
                seeded_arithmetic_flags: false,
            }),
        }
    }
}

impl Deref for ProcessTextOracle {
    type Target = NativeOracle;
    fn deref(&self) -> &NativeOracle {
        &self.inner
    }
}

impl Drop for ProcessTextOracle {
    fn drop(&mut self) {
        // All trace children are reaped before drop. Free only the owned fields;
        // the code Mapping is a borrowed process-lifetime assembly page.
        unsafe {
            std::ptr::drop_in_place(&mut self.inner.data);
            std::ptr::drop_in_place(&mut self.inner.stack);
            std::ptr::drop_in_place(&mut self.inner.original_code);
        }
    }
}
