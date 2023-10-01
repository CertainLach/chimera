use codegen::ir::UserFuncName;
use codegen::isa::CallConv;
use cranelift::prelude::*;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, Linkage, Module};
use std::ffi::{CStr, CString};
use std::mem;
use std::process::abort;
use tracing::error;

use crate::jitreg::register_jit_code;

extern "C" fn print_message(msg: *const i8) {
    let message = unsafe { CStr::from_ptr(msg) };
    error!("stub was called: {message:?}");
    abort();
}

pub fn make_stub(message: String) -> extern "C" fn() -> ! {
    let msg_ptr = CString::new(message).expect("no nulls allowed").into_raw();

    let mut flag_builder = settings::builder();
    flag_builder.set("use_colocated_libcalls", "false").unwrap();
    // FIXME set back to true once the x64 backend supports it.
    flag_builder.set("is_pic", "false").unwrap();
    let isa_builder = cranelift_native::builder().unwrap_or_else(|msg| {
        panic!("host machine is not supported: {}", msg);
    });
    let isa = isa_builder
        .finish(settings::Flags::new(flag_builder))
        .unwrap();

    let mut builder = JITBuilder::with_isa(isa, default_libcall_names());
    builder.symbol("stub", print_message as *const u8);
    builder.symbol("message", msg_ptr.cast());

    let mut module = JITModule::new(builder);

    let mut ctx = module.make_context();
    let mut func_ctx = FunctionBuilderContext::new();

    let mut stub_sig = module.make_signature();
    stub_sig.params.push(AbiParam::new(types::I64));
    let stub_fn = module
        .declare_function("stub", Linkage::Import, &stub_sig)
        .unwrap();

    let msg_data = module
        .declare_data("message", Linkage::Import, false, false)
        .unwrap();

    let tramp_fn = {
        let tramp_sig = module.make_signature();
        let tramp_fn = module
            .declare_function("trampoline", Linkage::Local, &tramp_sig)
            .unwrap();

        ctx.func.signature = tramp_sig;
        ctx.func.name = UserFuncName::user(0, tramp_fn.as_u32());
        {
            let mut bcx: FunctionBuilder = FunctionBuilder::new(&mut ctx.func, &mut func_ctx);
            let block = bcx.create_block();
            bcx.switch_to_block(block);

            let stub_fn = module.declare_func_in_func(stub_fn, bcx.func);
            let msg_data = module.declare_data_in_func(msg_data, bcx.func);

            let msg_arg = bcx.ins().global_value(types::I64, msg_data);

            bcx.ins().call(stub_fn, &[msg_arg]);
            bcx.ins().trap(TrapCode::UnreachableCodeReached);

            bcx.seal_all_blocks();
            bcx.finalize();
        }
        module.define_function(tramp_fn, &mut ctx).unwrap();
        module.clear_context(&mut ctx);

        tramp_fn
    };

    module.finalize_definitions().unwrap();
    // register_jit_code(module.get_finalized_function(func_id), code_size)

    let code_b = module.get_finalized_function(tramp_fn);

    unsafe { mem::transmute::<_, extern "C" fn() -> !>(code_b) }
}

