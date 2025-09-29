// Updated allocator code
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
extern crate alloc;

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
use linked_list_allocator::LockedHeap;

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

// We can only call this function one time
#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
pub fn init_heap() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(RUST_HEAP.as_ptr() as *mut u8, RUST_HEAP_SIZE);
    }
}

#[cfg(any(feature = "alloc", all(feature = "std", feature = "force-alloc")))]
pub fn heap_stats() -> (usize, usize, usize) {
    unsafe {
        let alloc = ALLOCATOR.lock();
        (alloc.size(), alloc.used(), alloc.free())
    }
}
