pub struct MemoryRegion {
    pub base_address: usize,
    pub region_size: usize,
    pub is_readable: bool,
    pub is_committed: bool,
}
