use std::ffi::{c_char, c_void, CStr};
use std::ptr::null;
use std::sync::Mutex;
use tracing::{info, warn};

use crate::wininternals::get_tib;

pub fn override_import(_module: &str, name: &str) -> Option<usize> {
    Some(match name {
        "malloc" => {
            extern "win64" fn my_malloc(size: usize) -> *mut c_void {
                dbg!(size);
                unsafe { libc::malloc(size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_malloc as usize
        }
        "calloc" => {
            extern "win64" fn my_malloc(nobj: usize, size: usize) -> *mut c_void {
                dbg!(nobj, size);
                unsafe { libc::calloc(nobj, size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_malloc as usize
        }
        "free" => {
            extern "win64" fn my_free(size: *mut c_void) {
                dbg!(size);
                unsafe { libc::free(size) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_free as usize
        }
        "memset" => {
            extern "win64" fn my_memset(dst: *mut c_void, c: i32, n: usize) -> *mut c_void {
                dbg!(dst, c, n);
                unsafe { libc::memset(dst, c, n) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_memset as usize
            // fuckup_cc("memset", libc::memset as unsafe extern "C" fn(_, _, _) -> _)
        }
        "memcpy" => {
            extern "win64" fn my_memcpy(
                dst: *mut c_void,
                c: *const c_void,
                n: usize,
            ) -> *mut c_void {
                unsafe { libc::memcpy(dst, c, n) }
            }
            // fuckup_cc("malloc", libc::malloc as unsafe extern "C" fn(_) -> _)
            my_memcpy as usize
            // fuckup_cc("memcpy", libc::memcpy as unsafe extern "C" fn(_, _, _) -> _)
        }
        // "getenv" => fuckup_cc("getenv", libc::getenv as unsafe extern "C" fn(_) -> _),
        // "GetModuleHandleW" => {
        //     extern "win64" fn find_module(name: *const ()) -> *const c_void {
        //         dbg!(name);
        //         null()
        //     }
        //     find_module as usize
        // }
        // "GetModuleHandleA" => {
        //     extern "win64" fn find_module(name: *const c_char) -> *const c_void {
        //         let name = unsafe { CStr::from_ptr(name) };
        //         dbg!(name);
        //         null()
        //     }
        //     find_module as usize
        // }
        // "GetProcAddress" => {
        //     extern "win64" fn find_proc(handle: *const (), name: *const c_char) -> *const c_void {
        //         let name = unsafe { CStr::from_ptr(name) };
        //         dbg!(handle, name);
        //         null()
        //     }
        //     find_proc as usize
        // }
        "InitializeCriticalSectionAndSpinCount" => {
            extern "win64" fn icsasc(cs: *mut (), _sc: u32) -> bool {
                warn!("todo: threads");
                // *cs = unsafe {Mutex::new(());};
                true
            }
            icsasc as usize
        }
        "DeleteCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "EnterCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "LeaveCriticalSection" => {
            extern "win64" fn icsasc(cs: *mut ()) {
                warn!("todo: threads");
            }
            icsasc as usize
        }
        "TlsAlloc" => {
            extern "win64" fn alloc() -> u32 {
                warn!("todo: tls");
                u32::MAX
            }
            alloc as usize
        }
        "LoadLibraryExW" => {
            extern "win64" fn load_lib(name: *const u16, file: *const (), flags: u32) -> *const () {
                warn!("dyn load");
                let name = unsafe { widestring::U16CStr::from_ptr_str(name) };
                warn!("dyn load w {name:?}");
                // get_tib().set_last_error(0x11223344);
                0x11223344 as *const ()
            }
            load_lib as usize
        }
        "GetProcAddress" => {
            extern "win64" fn load_lib(module: *const (), proc: *const c_char) -> *const () {
                let proc = unsafe { CStr::from_ptr(proc) };
                warn!("get proc: {proc:?}");
                // get_tib().set_last_error(0x11223344);
                null()
            }
            load_lib as usize
        }
        "GetLastError" => {
            extern "win64" fn get_last_error() -> u32 {
                let tib = get_tib();
                tib.last_error()
            }
            get_last_error as usize
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

        "EncodePointer" => {
            extern "win64" fn encode(i: usize) -> usize {
                !i
            }
            encode as usize
        }
        "setlocale" => {
            extern "win64" fn perfcnt(cat: i32, loc: *const c_char) -> *const c_char {
                let locale = if loc.is_null() {
                    None
                } else {
                    Some(unsafe { CStr::from_ptr(loc) })
                };
                info!("setlocale! {locale:?}");
                unsafe { libc::setlocale(cat, loc) }
            }
            perfcnt as usize
        }
        // "_lock_locales" |
        // | "_unlock_locales"
        // | "___lc_codepage_func"
        // | "___lc_locale_name_func"
        // | "__pctype_func"
        //| "_wcsdup"
        "_initialize_onexit_table" => {
            extern "win64" fn dummy() {}
            dummy as usize
        }
        _ => return None,
    })
}
