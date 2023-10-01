use std::ffi::{c_char, c_void, CStr};
use std::ptr::null;

use tracing::info;

use crate::fuckup_cc;

pub fn override_import(_module: &str, name: &str) -> Option<usize> {
    Some(match name {
        "malloc" => fuckup_cc(libc::malloc as unsafe extern "C" fn(_) -> _),
        "memset" => fuckup_cc(libc::memset as unsafe extern "C" fn(_, _, _) -> _),
        "memcpy" => fuckup_cc(libc::memcpy as unsafe extern "C" fn(_, _, _) -> _),
        "getenv" => fuckup_cc(libc::getenv as unsafe extern "C" fn(_) -> _),
        "GetModuleHandleW" => {
            extern "win64" fn find_module(name: *const ()) -> *const c_void {
                dbg!(name);
                null()
            }
            find_module as usize
        }
        "GetModuleHandleA" => {
            extern "win64" fn find_module(name: *const c_char) -> *const c_void {
                let name = unsafe { CStr::from_ptr(name) };
                dbg!(name);
                null()
            }
            find_module as usize
        }
        "GetProcAddress" => {
            extern "win64" fn find_proc(handle: *const (), name: *const c_char) -> *const c_void {
                let name = unsafe { CStr::from_ptr(name) };
                dbg!(handle, name);
                null()
            }
            find_proc as usize
        }
        "GetSystemTimeAsFileTime" => {
            extern "win64" fn time(_out: *mut ()) {
                info!("queried time")
            }
            time as usize
        }
        "GetCurrentThreadId" => {
            extern "win64" fn thread() -> u32 {
                info!("queried thread id");
                42
            }
            thread as usize
        }
        "GetCurrentProcessId" => {
            extern "win64" fn process() -> u32 {
                info!("queried process id");
                42
            }
            process as usize
        }
        "QueryPerformanceCounter" => {
            extern "win64" fn perfcnt(out: &mut u64) {
                info!("queried perf cnt");
                *out = 42;
            }
            perfcnt as usize
        }
        "_initialize_onexit_table" => {
            extern "win64" fn dummy() {}
            dummy as usize
        }
        _ => return None,
    })
}
