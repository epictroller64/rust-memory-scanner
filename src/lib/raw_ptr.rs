// newtype for HANDLE pointer

use std::ffi::c_void;

#[derive(Copy, Clone)]
pub struct ProcessHandle(pub *mut c_void);

// Tell the compiler: "I guarantee this is safe"
unsafe impl Send for ProcessHandle {}
unsafe impl Sync for ProcessHandle {}
