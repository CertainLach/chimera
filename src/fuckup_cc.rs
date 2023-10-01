use codegen::ir::UserFuncName;
use codegen::isa::CallConv;
use cranelift::prelude::*;
use cranelift_codegen::settings::{self, Configurable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{default_libcall_names, Linkage, Module};

pub trait KnownCcFunction {
    unsafe fn from_ptr(ptr: *const ()) -> Self;
}
trait Win64Function {
    fn argc() -> usize;
}
pub trait SysvFunction {
    fn argc() -> usize;
    fn as_ptr(&self) -> *const u8 {
        self as *const _ as *const u8
    }
}

macro_rules! impl_args_like {
	($count:expr; $($gen:ident)*) => {
		impl<T, $($gen,)*> Win64Function for extern "win64" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
		impl<T, $($gen,)*> KnownCcFunction for unsafe extern "win64" fn($($gen,)*) -> T {
            unsafe fn from_ptr(ptr: *const ()) -> Self {
                unsafe{std::mem::transmute(ptr)}
            }
		}
		// Assuming linux here
		impl<T, $($gen,)*> SysvFunction for extern "C" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
		impl<T, $($gen,)*> SysvFunction for unsafe extern "C" fn($($gen,)*) -> T {
			fn argc() -> usize {
				$count
			}
		}
	};
	($count:expr; $($cur:ident)* @ $c:ident $($rest:ident)*) => {
		impl_args_like!($count; $($cur)*);
		impl_args_like!($count + 1usize; $($cur)* $c @ $($rest)*);
	};
	($count:expr; $($cur:ident)* @) => {
		impl_args_like!($count; $($cur)*);
	}
}
impl_args_like! {
   0usize; @ A B C D E F G H I J K L
}

// /// Floats are not supported
// fn fuckup_fn<F: SysvFunction>(af: F) -> Result<*const u8> {
//     let mut ops = Assembler::new()?;
//     let argc = F::argc();
//     // Save clobbered registers
//     for i in (0..argc).rev() {
//         match i {
//             0 | 1 => {}
//             2 => dynasm!(ops; push r8),
//             3 => dynasm!(ops; push r9),
//             _ => todo!(),
//         }
//     }
//     for i in 0..argc {
//         match i {
//             0 => dynasm!(ops; push rdi),
//             1 => dynasm!(ops; push rsi),
//             2 => dynasm!(ops; push rdx),
//             3 => dynasm!(ops; push rcx),
//             _ => todo!(),
//         }
//     }
//     for i in (0..argc).rev() {
//         match i {
//             0 => dynasm!(ops; pop rcx),
//             1 => dynasm!(ops; pop rdx),
//             2 => dynasm!(ops; pop r8),
//             3 => dynasm!(ops; pop r9),
//             _ => todo!(),
//         }
//     }
//     dynasm!(ops; call af);
//
//     todo!()
// }

/// Receives normal function, returns win64 abi function
/// Does not support float arguments
/// Assuming x86_64 system with sysv as primary conversion
pub fn fuckup_cc<F: SysvFunction>(target: F) -> usize {
    // More than argc is needed for floats
    let argc = F::argc();

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
    builder.symbol("target", target.as_ptr());

    let mut module = JITModule::new(builder);

    let mut ctx = module.make_context();
    let mut func_ctx = FunctionBuilderContext::new();

    let mut stub_sig = module.make_signature();
    stub_sig.call_conv = CallConv::WindowsFastcall;
    for _ in 0..argc {
        stub_sig.params.push(AbiParam::new(types::I64));
    }
    stub_sig.returns.push(AbiParam::new(types::I64));
    let stub_fn = module
        .declare_function("target", Linkage::Import, &stub_sig)
        .unwrap();

    let tramp_fn = {
        let mut tramp_sig = module.make_signature();
        for _ in 0..argc {
            // Assuming x64 system
            tramp_sig.params.push(AbiParam::new(types::I64));
        }
        tramp_sig.returns.push(AbiParam::new(types::I64));
        let tramp_fn = module
            .declare_function("trampoline", Linkage::Local, &tramp_sig)
            .unwrap();

        ctx.func.signature = tramp_sig;
        ctx.func.name = UserFuncName::user(0, tramp_fn.as_u32());
        {
            let mut bcx: FunctionBuilder = FunctionBuilder::new(&mut ctx.func, &mut func_ctx);
            let block = bcx.create_block();
            bcx.switch_to_block(block);
            bcx.append_block_params_for_function_params(block);

            let params = bcx.block_params(block);
            let mut args = vec![];
            for ele in params {
                args.push(*ele);
            }

            let stub_fn = module.declare_func_in_func(stub_fn, bcx.func);
            let call = bcx.ins().call(stub_fn, &args);
            let value = {
                let results = bcx.inst_results(call);
                assert_eq!(results.len(), 1);
                results[0]
            };
            bcx.ins().return_(&[value]);

            bcx.seal_all_blocks();
            bcx.finalize();
        }
        module.define_function(tramp_fn, &mut ctx).unwrap();
        module.clear_context(&mut ctx);

        tramp_fn
    };

    module.finalize_definitions().unwrap();
    // register_jit_code(module.get_finalized_function(func_id), code_size)

    module.get_finalized_function(tramp_fn) as usize
}
