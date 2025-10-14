#[cfg(any(feature = "alloc", feature = "force-alloc"))]
#[repr(C)]
pub struct HeapStats {
    pub size: usize,
    pub used: usize,
    pub free: usize,
}
