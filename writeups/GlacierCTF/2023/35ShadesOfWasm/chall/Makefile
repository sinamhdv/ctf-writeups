#build: wasm_host/src/main.rs
#	cd wasm_host && cargo build --release && cd ..
#	cp wasm_host/target/release/wasm_host chall
#	cp chall chall_no_rpath
#	patchelf --set-interpreter ../libs/ld-linux-x86-64.so.2 --set-rpath ../libs/ chall

debug: wasm_host/src/main.rs
	cd wasm_host && cargo build && cd ..
	cp wasm_host/target/debug/wasm_host chall_dbg
	patchelf --set-interpreter ../libs/ld-linux-x86-64.so.2 --set-rpath ../libs/ chall_dbg

