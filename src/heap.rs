#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use linked_list_allocator::LockedHeap;

#[cfg(all(feature = "alloc", not(feature = "std")))]
const RUST_HEAP_SIZE: usize = 256 * 1024; // 256 KB

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[link_section = ".bss.rust_heap"]
static mut RUST_HEAP: [u8; RUST_HEAP_SIZE] = [0; RUST_HEAP_SIZE];

#[cfg(all(feature = "alloc", not(feature = "std")))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(all(feature = "alloc", not(feature = "std")))]
pub fn init_heap() {
    unsafe {
        ALLOCATOR
            .lock()
            .init(RUST_HEAP.as_ptr() as *mut u8, RUST_HEAP_SIZE);
    }
}
