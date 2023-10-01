#![feature(pointer_byte_offsets, thread_local)]

use anyhow::{bail, ensure, Context, Result};
use memmap2::{Mmap, MmapMut, MmapOptions};
use pelite::image::{
    IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use pelite::pe64::exports::{Export, GetProcAddress};
use pelite::pe64::imports::Import;
use pelite::pe64::{Pe, PeFile};
use pelite::util::AlignTo;
use region::Protection;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::mem::transmute;
use std::ptr::{addr_of, null};
use tracing::{debug, info, info_span, trace, warn};
use tracing_subscriber::EnvFilter;

use crate::fuckup_cc::fuckup_cc;
use crate::mkstub::make_stub;
use crate::winapis::override_import;
use crate::wininternals::LinuxTib;

use self::fuckup_cc::KnownCcFunction;

mod fuckup_cc;
mod jitreg;
mod mkstub;
mod winapis;
mod wininternals;

trait ExportedFnRaw {
    fn exported_fn_raw(&self, name: &str) -> Result<*const ()>;
}

struct PeImage {
    image: MmapMut,
    ro_orig_image: Mmap,
    resolved_inputs: bool,
}
impl PeImage {
    fn new(file: File) -> Result<Self> {
        let ro_orig_image = unsafe { MmapOptions::new().map_copy_read_only(&file)? };
        let pe = PeFile::from_bytes(&ro_orig_image).context("pe validity check")?;
        let pe_data = pe.to_view();
        let mut image = MmapOptions::new()
            .populate()
            .len(pe_data.len())
            .map_anon()?;
        image.copy_from_slice(&pe_data);

        let mut img = Self {
            image,
            ro_orig_image,
            resolved_inputs: false,
        };

        {
            let (mut editor, data) = img.project();
            let image_base = editor.mapped_image_base() as u64;
            let orig_base = data.optional_header().ImageBase;
            let rebase_delta = image_base as i64 - orig_base as i64;
            debug!("rebasing by {rebase_delta:x}");

            for block in data.base_relocs()?.iter_blocks() {
                for word in block.words() {
                    let rva = block.rva_of(word);
                    let ty = block.type_of(word);
                    if ty == IMAGE_REL_BASED_ABSOLUTE {
                        trace!("absolute base {rva}");
                    } else if ty == IMAGE_REL_BASED_HIGHLOW || ty == IMAGE_REL_BASED_DIR64 {
                        let orig: &u64 = data.derva(rva)?;
                        let new = editor.mut_mirror(orig);
                        *new = orig.wrapping_add_signed(rebase_delta);
                        trace!("rebased {rva}: {orig:x} => {new:x}");
                    } else {
                        warn!("unknown base reloc: {ty}");
                    }
                }
            }
        }

        Ok(img)
    }
    fn project(&mut self) -> (PeEditor, PeFile) {
        let pe = PeFile::from_bytes(&self.ro_orig_image).expect("validity checked in new()");
        (
            PeEditor {
                mapped_image: &mut self.image,
                dll_file: &self.ro_orig_image,
                pe,
            },
            pe,
        )
    }
    fn resolve_imports(
        &mut self,
        default: fn(&str, &str) -> Option<usize>,
        linker: &LinkerData,
    ) -> Result<()> {
        trace!("resolving imports");
        let (mut editor, data) = self.project();
        for desc in data.imports()? {
            let dll = desc.dll_name()?;
            debug!("importing {dll}");
            let int = desc.int()?;
            let iat = desc.iat()?;

            ensure!(int.len() == iat.len(), "iat int mismatch");
            let mut printed_dll_not_found_warning = BTreeSet::new();
            for (int, iat) in int.zip(iat) {
                let int = int?;
                match int {
                    Import::ByName { hint: _, name } => {
                        let orig = iat;
                        let new = editor.mut_mirror(iat);
                        let dllstr = dll.to_str().expect("module not utf8").to_lowercase();
                        let namestr = name.to_str().expect("import not utf8");
                        *new = match default(&dllstr, namestr) {
                            Some(v) => v as u64,
                            None => {
                                if let Some(dll) = linker.get(&dllstr) {
                                    match dll.exported_fn_raw(namestr) {
                                        Ok(fun) => fun as u64,
                                        Err(e) => {
                                            warn!("dll was found, yet export is not: {dllstr}:{namestr}: {e}");
                                            make_stub(format!(
                                                "function was not defined: {dllstr}:{namestr}"
                                            )) as usize
                                                as u64
                                        }
                                    }
                                } else {
                                    if printed_dll_not_found_warning.insert(dllstr.to_owned()) {
                                        warn!("dll not found, stubbing: {dllstr}");
                                    }
                                    make_stub(format!(
                                        "function was not defined: {dllstr}:{namestr}"
                                    )) as usize as u64
                                }
                            }
                        };
                        trace!("resolved {dll}:{name}: {orig:x} => {new:x}");
                    }
                    Import::ByOrdinal { ord } => {
                        let orig = iat;
                        let new = editor.mut_mirror(iat);
                        *new = make_stub(format!("function was not defined: {dll}#ord")) as usize
                            as u64;
                        trace!("resolved {dll}:{ord}: {orig:x} => {new:x}");
                    }
                }
            }
        }
        self.resolved_inputs = true;
        Ok(())
    }
    fn finish(self) -> Result<FinishedPeImage> {
        if !self.resolved_inputs {
            warn!("resolve_inputs was not called, stubbing everything");
        }
        let exec = self.image.make_read_only()?;
        let pe = PeFile::from_bytes(&self.ro_orig_image).expect("validity checked in new()");
        let section_alignment = pe.optional_header().SectionAlignment;

        for ele in pe.section_headers() {
            let mut protection = Protection::NONE;
            let chr = ele.Characteristics;

            if chr & IMAGE_SCN_MEM_EXECUTE != 0 {
                protection |= Protection::EXECUTE
            }
            if chr & IMAGE_SCN_MEM_READ != 0 {
                protection |= Protection::READ
            }
            if chr & IMAGE_SCN_MEM_WRITE != 0 {
                protection |= Protection::WRITE
            }
            let lossy_name = String::from_utf8_lossy(ele.name_bytes());
            trace!(target:"section", "protecting {lossy_name} as {protection}");

            unsafe {
                region::protect(
                    exec.as_ptr().byte_offset(ele.VirtualAddress as isize),
                    ele.VirtualSize.align_to(section_alignment) as usize,
                    protection,
                )?
            };
        }
        // register_jit_code(exec.as_ptr().cast(), exec.len() as u64);

        Ok(FinishedPeImage {
            image: exec,
            ro_orig_image: self.ro_orig_image,
        })
    }
    fn pe(&self) -> PeFile {
        let file = PeFile::from_bytes(&self.ro_orig_image)
            .expect("file shouldn't be corrupted during linking");
        file
    }
    fn mirror<T>(&self, v: &T) -> &T {
        mirror_raw(&self.image, &self.ro_orig_image, &self.pe(), v)
    }
}
impl ExportedFnRaw for PeImage {
    fn exported_fn_raw(&self, name: &str) -> Result<*const ()> {
        let init_fn = self.pe().get_export(name)?;
        let init_or = match init_fn {
            Export::Symbol(s) => self.pe().derva::<u8>(*s)?,
            Export::Forward(_) => bail!("not forwarded"),
        };
        Ok(self.mirror(init_or) as *const _ as *const ())
    }
}
impl ExportedFnRaw for FinishedPeImage {
    fn exported_fn_raw(&self, name: &str) -> Result<*const ()> {
        let init_fn = self.pe().get_export(name)?;
        let init_or = match init_fn {
            Export::Symbol(s) => self.pe().derva::<u8>(*s)?,
            Export::Forward(_) => bail!("not forwarded"),
        };
        Ok(self.mirror(init_or) as *const _ as *const ())
    }
}

type LinkerData = BTreeMap<String, FinishedPeImage>;

struct FinishedPeImage {
    image: Mmap,
    ro_orig_image: Mmap,
}
impl FinishedPeImage {
    fn pe(&self) -> PeFile {
        let file = PeFile::from_bytes(&self.ro_orig_image)
            .expect("file shouldn't be corrupted during linking");
        file
    }
    fn assert_in_image<T>(&self, p: *const T) {
        let orig = p.cast::<u8>();
        let offset = unsafe { orig.offset_from(self.image.as_ptr().cast()) };
        assert!(offset > 0 && (offset as usize) < self.image.len());
    }
    fn mirror<T>(&self, v: &T) -> &T {
        mirror_raw(&self.image, &self.ro_orig_image, &self.pe(), v)
    }
    unsafe fn exported_fn<F: KnownCcFunction>(&self, name: &str) -> Result<F> {
        Ok(unsafe { F::from_ptr(self.exported_fn_raw(name)?) })
    }
    fn call_ep_if_exists(&self) -> Result<()> {
        if self.pe().optional_header().AddressOfEntryPoint != 0 {
            let ep = unsafe {
                self.image
                    .as_ptr()
                    .byte_offset(self.pe().optional_header().AddressOfEntryPoint as isize)
            };
            self.assert_in_image(ep);
            debug!("ep found: {ep:?}, calling it");
            let ep: extern "win64" fn(*const u8, u32, *const u8) -> i32 = unsafe { transmute(ep) };
            ep(self.image.as_ptr(), 1, null());
        }
        Ok(())
    }
}
fn mut_mirror_raw<'o, T>(
    mapped_image: &'o mut [u8],
    dll_file: &[u8],
    pe: &PeFile,
    v: &T,
) -> &'o mut T {
    let orig = addr_of!(*v).cast::<u8>();
    let offset = unsafe { orig.offset_from(dll_file.as_ptr().cast()) };
    assert!(
        offset > 0 && (offset as usize) < dll_file.len(),
        "can't mirror value not from source dll file"
    );
    let rva = pe.file_offset_to_rva(offset as usize).expect("in image");
    assert!((rva as usize) < mapped_image.len(), "rva is out of mapping");
    unsafe { &mut *mapped_image.as_mut_ptr().byte_offset(rva as isize).cast() }
}
fn mirror_raw<'o, T>(mapped_image: &'o [u8], dll_file: &[u8], pe: &PeFile, v: &T) -> &'o T {
    let orig = addr_of!(*v).cast::<u8>();
    let offset = unsafe { orig.offset_from(dll_file.as_ptr().cast()) };
    assert!(
        offset > 0 && (offset as usize) < dll_file.len(),
        "can't mirror value not from source dll file"
    );
    let rva = pe.file_offset_to_rva(offset as usize).expect("in image");
    assert!((rva as usize) < mapped_image.len(), "rva is out of mapping");
    unsafe { &*mapped_image.as_ptr().byte_offset(rva as isize).cast() }
}

struct PeEditor<'m> {
    mapped_image: &'m mut MmapMut,
    dll_file: &'m Mmap,
    pe: PeFile<'m>,
}
impl PeEditor<'_> {
    fn mapped_image_base(&self) -> usize {
        self.mapped_image.as_ptr() as usize
    }
    fn mut_mirror<T>(&mut self, v: &T) -> &mut T {
        mut_mirror_raw(self.mapped_image, self.dll_file, &self.pe, v)
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut data = LinkerData::new();
    let tib = LinuxTib::new();
    {
        let _span = info_span!("msvcp140").entered();
        let mut m = PeImage::new(File::open("libs/msvcp140.dll")?)?;
        m.resolve_imports(override_import, &data)?;
        let m = m.finish()?;
        {
            let _ent_tib = tib.enter();
            m.call_ep_if_exists()?;
        }
        data.insert("msvcp140.dll".to_owned(), m);
    }
    {
        let _span = info_span!("opencv_world").entered();
        let mut m = PeImage::new(File::open("opencv_world346.dll")?)?;
        m.resolve_imports(override_import, &data)?;
        let m = m.finish()?;
        {
            let _ent_tib = tib.enter();
            m.call_ep_if_exists()?;
        }
        data.insert("opencv_world346.dll".to_owned(), m);
    }
    {
        let _span = info_span!("libdistort").entered();
        let mut m = PeImage::new(File::open("LibLensDistortion.dll")?)?;
        m.resolve_imports(override_import, &data)?;
        let m = m.finish()?;
        {
            let _ent_tib = tib.enter();
            m.call_ep_if_exists()?;
        }

        unsafe {
            let init_fn = m.exported_fn::<unsafe extern "win64" fn() -> u64>("init")?;
            info!("calling init...");
            dbg!(init_fn)();
            info!("initialized!");
        }
    }

    // let mut header = editor.mut_mirror(data.optional_header());
    // header.ImageBase =
    //

    // info!("init call: {init:?}");
    // init();
    info!("init called!");

    Ok(())
}
