dbg:
	cargo build
	RUST_LOG=debug,cranelift_codegen=warn,cranelift_jit=warn ~/build/lldbdev/outputs/out/bin/.lldb-wrapped ./target/debug/dllloader
run:
	RUST_LOG=debug,cranelift_codegen=warn,cranelift_jit=warn cargo run
