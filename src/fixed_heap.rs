#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
use crate::allocator::HeapStats;
#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
extern crate alloc;
#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
use linked_list_allocator::LockedHeap;
#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
const FIXED_HEAP_SIZE: usize = 256 * 1024;

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
#[no_mangle]
#[used]
#[link_section = ".bss.fixed_heap"]
static mut FIXED_HEAP: [u8; FIXED_HEAP_SIZE] = [0; FIXED_HEAP_SIZE];

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
pub fn init_heap() {
    if HEAP_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        unsafe {
            ALLOCATOR
                .lock()
                .init(FIXED_HEAP.as_ptr() as *mut u8, FIXED_HEAP_SIZE);
        }
    }
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
pub fn heap_stats() -> (usize, usize, usize) {
    unsafe {
        let alloc = ALLOCATOR.lock();
        (alloc.size(), alloc.used(), alloc.free())
    }
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
#[no_mangle]
pub extern "C" fn rust_heap_stats() -> HeapStats {
    let (size, used, free) = heap_stats();
    HeapStats { size, used, free }
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "fixed-heap"))]
#[no_mangle]
pub extern "C" fn rust_allocator_ptr() -> *mut LockedHeap {
    unsafe { &ALLOCATOR as *const LockedHeap as *mut LockedHeap }
}

