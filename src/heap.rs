#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(any(feature = "std", feature = "alloc", feature = "force-alloc")))]
compile_error!(
    "This module requires heap. Enable one of: `std`, `alloc`, or `std with force-alloc` features."
);

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
extern crate alloc;

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
use linked_list_allocator::LockedHeap;

use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
const RUST_HEAP_SIZE: usize = 256 * 1024;

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
#[no_mangle]
#[used]
#[link_section = ".bss.rust_heap"]
static mut RUST_HEAP: [u8; RUST_HEAP_SIZE] = [0; RUST_HEAP_SIZE];

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the allocator (Rust only)
#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
pub fn init_heap() {
    if HEAP_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        unsafe {
            ALLOCATOR
                .lock()
                .init(RUST_HEAP.as_ptr() as *mut u8, RUST_HEAP_SIZE);
        }
    }
}

/// Return (size, used, free) for Rust
#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
pub fn heap_stats() -> (usize, usize, usize) {
    unsafe {
        let alloc = ALLOCATOR.lock();
        (alloc.size(), alloc.used(), alloc.free())
    }
}

#[repr(C)]
pub struct HeapStats {
    pub size: usize,
    pub used: usize,
    pub free: usize,
}

/// Expose stats for C
#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
#[no_mangle]
pub extern "C" fn rust_heap_stats() -> HeapStats {
    let (size, used, free) = heap_stats();
    HeapStats { size, used, free }
}

/// Expose pointer to ALLOCATOR for C
#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
#[no_mangle]
pub extern "C" fn rust_allocator_ptr() -> *mut LockedHeap {
    unsafe { &ALLOCATOR as *const LockedHeap as *mut LockedHeap }
}
