#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
use core::alloc::{GlobalAlloc, Layout};
#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
use crate::allocator::HeapStats;

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn aligned_alloc(alignment: usize, size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
struct ThreadXCAllocator;

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
unsafe impl GlobalAlloc for ThreadXCAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > core::mem::size_of::<usize>() {
            aligned_alloc(layout.align(), layout.size())
        } else {
            malloc(layout.size())
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr);
    }
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
#[global_allocator]
static ALLOCATOR: ThreadXCAllocator = ThreadXCAllocator;

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
pub fn init_heap() {
    #[cfg(feature = "std")]
    {
        println!("[ac-heap] heap initialized (GlobalAlloc = ThreadXCAllocator)");
    }
    HEAP_INITIALIZED.store(true, Ordering::Relaxed);
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
pub fn heap_stats() -> (usize, usize, usize) {
    (0, 0, 0)
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
#[no_mangle]
pub extern "C" fn rust_heap_stats() -> HeapStats {
    let (size, used, free) = heap_stats();
    HeapStats { size, used, free }
}

#[cfg(all(any(feature = "alloc", feature = "force-alloc"), feature = "ac-heap"))]
#[no_mangle]
pub extern "C" fn rust_allocator_ptr() -> *mut ThreadXCAllocator {
    unsafe { &ALLOCATOR as *const ThreadXCAllocator as *mut ThreadXCAllocator }
}
