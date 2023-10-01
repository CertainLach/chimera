use std::arch::asm;
use std::os::raw::c_void;
use std::{process, ptr};

use tracing::{error, info};

#[repr(C)]
struct JitCodeEntry {
    next: *mut JitCodeEntry,
    prev: *mut JitCodeEntry,
    symfile_addr: *const c_void,
    symfile_size: u64,
}

#[repr(C)]
pub struct JitDescriptor {
    version: u32,
    action_flag: u32,
    relevant_entry: *const JitCodeEntry,
    first_entry: *const JitCodeEntry,
}

#[no_mangle]
#[inline(never)]
extern "C" fn __jit_debug_register_code() {}

#[no_mangle]
pub static mut __jit_debug_descriptor: JitDescriptor = JitDescriptor {
    version: 1,
    action_flag: 0,
    relevant_entry: ptr::null(),
    first_entry: ptr::null(),
};

pub fn register_jit_code(code_ptr: *const c_void, code_size: u64) {
    if std::env::var("SKIP_JIT").is_ok() {
        return;
    }
    let entry = Box::into_raw(Box::new(JitCodeEntry {
        next: ptr::null_mut(),
        prev: ptr::null_mut(),
        symfile_addr: code_ptr,
        symfile_size: code_size,
    }));

    info!("registering jitted code at {code_ptr:?}");
    unsafe {
        if __jit_debug_descriptor.first_entry.is_null() {
            __jit_debug_descriptor.first_entry = entry;
        } else {
            let mut current = __jit_debug_descriptor.first_entry.cast_mut();

            while !(*current).next.is_null() {
                current = (*current).next;
            }

            (*current).next = entry;

            (*entry).prev = current;
        }

        // Update descriptor
        __jit_debug_descriptor.relevant_entry = entry;
        __jit_debug_descriptor.action_flag = 1;

        asm!("nop");

        // Inform debugger
        __jit_debug_register_code();
    }
    info!("debugger informed");
}
