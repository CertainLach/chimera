use std::arch::asm;
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::mem;

#[repr(C)]
struct ListEntry<T> {
    next: *const ListEntry<T>,
    prev: *const ListEntry<T>,

    _marker: PhantomData<T>,
}

#[repr(C)]
struct UnicodeString {}

#[repr(C)]
struct LdrDataEntry {
    in_load_order: ListEntry<()>,
    in_memory_order: ListEntry<()>,
    in_progress_links: ListEntry<()>,
    dll_base: *const (),
    ep: *const (),
    size_of_image: usize,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: u32,
    obsolete_load_count: u16,
    tls_index: u16,
    hash_links: ListEntry<()>,
    time_date_stamp: u32,
    ep_activation_context: *const (),
    lock: *const (),
    ddag_node: *const (),
    node_link: ListEntry<()>,
    load_context: *const (),
    parent_dll_base: *const (),
    switch_back_context: *const (),
    base_address_index_node: [*const (); 3],
    mapping_info_index_node: [*const (); 3],
    original_base: *const (),
    load_time: u64,
    base_name_hash_value: u32,
    load_reason: u32,
    implicit_path_options: u32,
    refcnt: u32,
    deploadflags: u32,
    signlevel: u32,
}

#[repr(C)]
struct LdrData {
    length: u32,
    initialized: u32,
    ss_handle: *const (),
    in_load_order_module_list: ListEntry<()>,
    in_memory_order_module_list: ListEntry<()>,
    in_initialization_order_module_list: ListEntry<()>,
    entry_in_progress: *const (),
    shutdown_in_progress: u32,
    shutdown_thread_id: *const (),
}

#[repr(C)]
struct Peb {
    r1: [u8; 4],
    r2: [*const (); 2],
    ldr: *const LdrData,
    proc_params: *const (),
    subsys_data: *const (),
    process_heap: *const (),
    fast_peb_lock: *const (),
    atl_thunks_list_ptr: *const (),
    ifeokey: *const (),
    cpflags: u32,
    r3: [u8; 4],
    user_pointer: *const (),
}

#[repr(C)]
struct TibNtrnl {
    ex_list: *const (),
    stack_base: *const (),
    stack_limit: *const (),
    sub_system_tib: *const (),
    version: usize,
    user_pointer: *const (),
    this: *const TibNtrnl,
    env: *const (),
    pid: *const (),
    tid: *const (),
    rpc: *const (),
    tls: *const (),
    peb: *const Peb,
    last_error: u32,
    critical_sections: u32,
}
pub struct LinuxTib(Box<UnsafeCell<TibNtrnl>>);
impl LinuxTib {
    pub fn new() -> Self {
        // Is POD
        let ntrnl: TibNtrnl = unsafe { mem::zeroed() };
        let mut boxed = Box::new(UnsafeCell::new(ntrnl));
        boxed.get_mut().this = boxed.get();
        Self(boxed)
    }
    pub fn enter(&self) -> EnteredLinuxTib {
        assert!(!HAVE_TIB.get());
        let prevbase: *const ();
        let gs: *const TibNtrnl = self.0.get();
        unsafe {
            asm!(
                "rdgsbase {prevbase}",
                "wrgsbase {gs}",
                prevbase = out(reg) prevbase,
                gs = in(reg) gs,
            );
        };
        HAVE_TIB.set(true);
        EnteredLinuxTib { prevbase }
    }
}
pub struct TibRef(*const UnsafeCell<TibNtrnl>);

#[must_use]
pub struct EnteredLinuxTib {
    prevbase: *const (),
}
impl Drop for EnteredLinuxTib {
    fn drop(&mut self) {
        assert!(HAVE_TIB.get());
        HAVE_TIB.set(false);
        unsafe { asm!("wrgsbase {gs}", gs = in(reg) self.prevbase) }
    }
}

#[thread_local]
static HAVE_TIB: Cell<bool> = Cell::new(false);

pub fn assert_have_tib() {
    assert!(HAVE_TIB.get())
}
pub fn get_tib() -> TibRef {
    assert_have_tib();
    let tib;
    unsafe { asm!("rdgsbase {tib}", tib = out(reg) tib) };
    TibRef(tib)
}
