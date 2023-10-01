use std::arch::asm;
use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::mem;
use std::pin::Pin;
use std::ptr::null;
use std::ptr::write_volatile;

use derivative::Derivative;
use nt_list::list::{NtList, NtListEntry, NtListHead};
use nt_list::NtListElement;
use nt_string::unicode_string::NtUnicodeString;

#[repr(C)]
struct ListEntry<T> {
    next: *const ListEntry<T>,
    prev: *const ListEntry<T>,

    _marker: PhantomData<T>,
}

#[derive(NtList)]
enum InLoad {}
#[derive(NtList)]
enum InMemory {}
#[derive(NtList)]
enum InProgress {}
#[derive(NtList)]
enum Hash {}
#[derive(NtList)]
enum Ddag {}

#[derive(NtListElement, Derivative)]
#[repr(C)]
#[derivative(Default)]
struct LdrDataEntry {
    in_load_order: NtListEntry<Self, InLoad>,
    in_memory_order: NtListEntry<Self, InMemory>,
    in_prngress_links: NtListEntry<Self, InProgress>,
    #[derivative(Default(value = "null()"))]
    dll_base: *const (),
    #[derivative(Default(value = "null()"))]
    ep: *const (),
    size_of_image: usize,
    full_dll_name: NtUnicodeString,
    base_dll_name: NtUnicodeString,
    flags: u32,
    obsolete_load_count: u16,
    tls_index: u16,
    hash_links: NtListEntry<Self, Hash>,
    time_date_stamp: u32,
    #[derivative(Default(value = "null()"))]
    ep_activation_context: *const (),
    #[derivative(Default(value = "null()"))]
    lock: *const (),
    #[derivative(Default(value = "null()"))]
    ddag_node: *const (),
    node_link: NtListEntry<Self, Ddag>,
    #[derivative(Default(value = "null()"))]
    load_context: *const (),
    #[derivative(Default(value = "null()"))]
    parent_dll_base: *const (),
    #[derivative(Default(value = "null()"))]
    switch_back_context: *const (),
    #[derivative(Default(value = "[null(); 3]"))]
    base_address_index_node: [*const (); 3],
    #[derivative(Default(value = "[null(); 3]"))]
    mapping_info_index_node: [*const (); 3],
    #[derivative(Default(value = "null()"))]
    original_base: *const (),
    load_time: u64,
    base_name_hash_value: u32,
    load_reason: u32,
    implicit_path_options: u32,
    refcnt: u32,
    deploadflags: u32,
    signlevel: u32,
}

/// Reference counted loader entry reference (currently leaks)
struct OwnedLdrData(*mut UnsafeCell<LdrDataEntry>);
impl OwnedLdrData {
    fn new() -> Self {
        let data = LdrDataEntry::default();
        let boxed = Box::new(UnsafeCell::new(data));
        Self(Box::into_raw(boxed))
    }
    /// SAFETY: Assuming no threads will alter this entry other than current.
    pub fn unchecked_get_pinned(&mut self) -> Pin<&mut LdrDataEntry> {
        unsafe { Pin::new_unchecked((*self.0).get_mut()) }
    }
}

#[pin_project::pin_project]
#[repr(C)]
struct LdrData {
    length: u32,
    initialized: u32,
    ss_handle: *const (),
    #[pin]
    in_load_order_module_list: NtListHead<LdrDataEntry, InLoad>,
    #[pin]
    in_memory_order_module_list: NtListHead<LdrDataEntry, InMemory>,
    #[pin]
    in_initialization_order_module_list: NtListHead<LdrDataEntry, InProgress>,
    entry_in_progress: *const (),
    shutdown_in_progress: u32,
    shutdown_thread_id: *const (),
}
impl LdrData {
    pub fn add_entry(self: Pin<&mut Self>, mut e: Pin<&mut LdrDataEntry>) {
        let proj = self.project();
        unsafe {
            proj.in_load_order_module_list
                .push_back(e.as_mut().get_unchecked_mut());
            proj.in_initialization_order_module_list
                .push_back(e.get_unchecked_mut());
        }
    }
    pub fn add_initialized(self: Pin<&mut Self>, e: Pin<&mut LdrDataEntry>) {
        unsafe {
            self.project()
                .in_initialization_order_module_list
                .push_back(e.get_unchecked_mut())
        };
    }
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
pub struct VirtualPeb(Box<UnsafeCell<Peb>>);
impl VirtualPeb {
    pub fn new() -> Self {
        let peb: Peb = unsafe { mem::zeroed() };

        let boxed = Box::new(UnsafeCell::new(peb));
        Self(boxed)
    }
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
pub struct VirtualTib(Box<UnsafeCell<TibNtrnl>>);
impl VirtualTib {
    pub fn new() -> Self {
        // Is POD
        let ntrnl: TibNtrnl = unsafe { mem::zeroed() };
        let mut boxed = Box::new(UnsafeCell::new(ntrnl));
        boxed.get_mut().this = boxed.get();
        boxed.get_mut().tls = 0xfafafafausize as *const ();
        Self(boxed)
    }
    /// SAFETY: Until returned EnteredVirtualTib is dropped, nothing should want data from original tib,
    /// or perform unbalanced (Ie setting, but not restoring) gs segment register access.
    pub fn enter(&self) -> EnteredVirtualTib {
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
        EnteredVirtualTib { prevbase }
    }
}
pub struct TibRef(&'static UnsafeCell<TibNtrnl>);
impl TibRef {
    pub fn last_error(&self) -> u32 {
        unsafe { (*self.0.get()).last_error }
    }
    pub fn set_last_error(&self, e: u32) {
        unsafe { write_volatile(&mut (*self.0.get()).last_error, e) }
    }
}

#[must_use]
pub struct EnteredVirtualTib {
    prevbase: *const (),
}
impl Drop for EnteredVirtualTib {
    fn drop(&mut self) {
        unsafe { asm!("wrgsbase {gs}", gs = in(reg) self.prevbase) }
    }
}

pub fn get_tib() -> TibRef {
    let tib: *const UnsafeCell<_>;
    unsafe { asm!("rdgsbase {tib}", tib = out(reg) tib) };
    TibRef(unsafe { &*tib })
}
