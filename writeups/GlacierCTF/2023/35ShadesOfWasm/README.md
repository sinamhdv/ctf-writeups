# GlacierCTF 2023 - 35 Shades of Wasm

**Summary**: Exploiting CVE-2023-26489 (OOB read/write due to an error in JIT/AOT compiler) in Wasmtime to get remote code execution

In this challenge, we are allowed to provide an arbitrary wasm binary for the server to execute, and we should get remote code execution with that. Of course, wasmtime is used in a mode that does not give us any capabilities to access the file system or any external resource so we need to break out of wasmtime and execute arbitrary code.

## Vulnerability

I just searched "wasm cve 35" in google (with a hint according the challenge name) and found CVE-2023-26489. This is the NVD description of it: https://nvd.nist.gov/vuln/detail/CVE-2023-26489. According to NVD:

> The specific bug in Cranelift's x86_64 backend is that a WebAssembly address which is left-shifted by a constant amount from 1 to 3 will get folded into x86_64's addressing modes which perform shifts. For example `(i32.load (i32.shl (local.get 0) (i32.const 3)))` loads from the WebAssembly address `$local0 << 3`. When translated to Cranelift the `$local0 << 3` computation, a 32-bit value, is zero-extended to a 64-bit value and then added to the base address of linear memory. Cranelift would generate an instruction of the form `movl (%base, %local0, 8), %dst` which calculates `%base + %local0 << 3`. The bug here, however, is that the address computation happens with 64-bit values, where the `$local0 << 3` computation was supposed to be truncated to a a 32-bit value. This means that `%local0`, which can use up to 32-bits for an address, gets 3 extra bits of address space to be accessible via this `movl` instruction. The fix in Cranelift is to remove the erroneous lowering rules in the backend which handle these zero-extended expression. The above example is then translated to `movl %local0, %temp; shl $3, %temp; movl (%base, %temp), %dst` which correctly truncates the intermediate computation of `%local0 << 3` to 32-bits inside the `%temp` register which is then added to the `%base` value. Wasmtime version 4.0.1, 5.0.1, and 6.0.1 have been released and have all been patched to no longer contain the erroneous lowering rules.

Cranelift is wasmtime's code generation backend for the JIT/AOT compiler, and in these versions wasmtime almost always compiles every wasm function into native code before running it, so it is always used. Wasm linear memory is a region of memory mapped to be used for general purposes by the application and this region of memory can be freely accessed using wasm load/store instructions. The pointers accepted by load/store instructions are 32-bit pointers, and there is a huge empty guard page with a size larger than 32-bit integers after the wasm linear memory region, so just by adding a 32-bit pointer to the 64-bit address of the linear memory base, we can never pass the guard page and write into the next pages. However, this vulnerability will compile `(i64.load (i32.shl (local.get 0) (i32.const 3)))` into an instruction like `mov rax, qword [r11+rsi*8]`, where `r11` is the base of wasm linear memory, and `rsi` is our specified index (same as `local.get 0`) to optimize the `shl` operation into the same instruction. However, because the 32-bit pointer is in `rsi` and it is multiplied by 8 and never truncated, we can control 3 more bits of the final read address, and potentially read/write past the guard pages.


The wasmtime version being used in this challenge is `v6.0.0` (according to the `chall/wasm_host/Cargo.toml` file), so it is vulnerable to this bug.

## Setup

In order to begin working on the challenge, I first extracted the libraries used by the `chall` binary inside the given docker container and put them in `libs/`. Then, I used `patchelf` to set the challenge binary to use the given libraries to simulate the remote environment. Also, I changed one line in the `main.rs` source code of the challenge from `config.debug_info(false);` to `config.debug_info(true);` to get function names and debug info for the wasm functions compiled into native code. Apparently, compiling the challenge binary (even without changing the source) changes the `link_map_call_offset` offset used in the `payload.c` exploit code, so I had to use different offsets for the debug binary and the actual binary/remote, so I did not recompile the original challenge binary. I just used `patchelf` on it, and backed up the original file into `chall_no_rpath`.

Also, to compile the `payload.c` exploit, I used a docker container that had the necessary compiler and libraries/headers to compile C into wasm targets, and modified the Makefile to compile the payload into a wasm binary using that container.

## Creating the exploit primitives

To trigger the vulnerability, according to NVD, we should have wasm instructions equivalent to
`(i64.load (i32.shl (local.get 0) (i32.const 3)))` for OOB read, and
`(i64.store (i32.shl (local.get 0) (i32.const 3)) (local.get 1))` for OOB write.
I couldn't find any useful way to write C code that gets exactly translated to these wasm instructions, so I decided to implement these small primitives in wat (wasm text) format and assemble them into wasm object files, and then link it with the object file compiled from the exploit C code. Eventually I couldn't get the object files assembled using `wat2wasm` to link with the object file generated by `clang`, so instead, I decided to write simple C code that resembles the needed primitives, and then compile them into object files using `clang`, and then patch the code of the generated object files to include the exact primitives that I want.

The `reader.c` and `writer.c` files are both like that. they access a global array named `arr`, which is defined in `payload.c` to prevent errors when linking all files together. The simple `read_qword` and `write_qword` functions read or write a 64-bit integer from/to the global array. There are two lines in the `Makefile` to compile the `reader.c` and `writer.c` files into `reader.o` and `writer.o`. Then, I used `wasm-objdump` to view the code of the object files and a hex editor to patch them to contain the needed wasm instructions to create the OOB read/write primitives (Ghidra can also be used for patching). You can view the difference between the original and patched object files by comparing `reader.o` and `reader_patched.o` with `wasm-objdump`. Then, I wrote the declaration of the `read_qword` and `write_qword` functions as `extern` functions in `payload.c` and compiled it into `payload.o`, and used the linker from clang to link `reader_patched.o`, `writer_patched.o`, and `payload.o`. Now we have a binary that has the OOB read/write primitives.

## Triggering the vulnerability

To trigger the vulnerability, You can just call the `read_qword` function with the input of `0x10000000` in `payload.c`. I put a call to `getchar` in the beginning of the `main` function so that I can just use `b getchar` before running the `chall_dbg` binary to break in `getchar` after all wasm functions have been compiled into native code. This is the code for the `read_qword` function disassembled in gdb:

```
(gdb) b getchar
(gdb) r < ../payload/payload.wasm.base64
Thread 1 "chall_dbg" hit Breakpoint 1, 0x00007ffff6c5a304 in getchar ()
(gdb) disassemble read_qword
Dump of assembler code for function read_qword:
   0x00007ffff6c59660 <+0>:	push   rbp
   0x00007ffff6c59661 <+1>:	mov    rbp,rsp
   0x00007ffff6c59664 <+4>:	mov    r9d,DWORD PTR [rdi+0xd0]
   0x00007ffff6c5966b <+11>:	mov    r11,QWORD PTR [rdi+0xc0]
   0x00007ffff6c59672 <+18>:	sub    r9d,0x10
   0x00007ffff6c59676 <+22>:	mov    DWORD PTR [r11+r9*1+0xc],edx
   0x00007ffff6c5967b <+27>:	mov    esi,edx
   0x00007ffff6c5967d <+29>:	mov    rax,QWORD PTR [r11+rsi*8+0x0]
   0x00007ffff6c59682 <+34>:	mov    rsp,rbp
   0x00007ffff6c59685 <+37>:	pop    rbp
   0x00007ffff6c59686 <+38>:	ret    
End of assembler dump.
```

As you can see in the code above, the instruction `mov rax, QWORD PTR [r11+rsi*8+0x0]` is vulnerable, because `r11` is a pointer to the beginning of wasm linear memory, and `rsi` is the 32-bit pointer passed to `i32.shl` in the wasm instructions. This instruction tries to merge the `i32.shl` and `i64.load` operations into one operation by using `rsi*8` in the address of the memory read instruction. However, because `rsi` can be any 32-bit value, multiplying it by 8 will allow us to read addresses up to 35 bits away from the base of wasm linear memory. This is a sample memory mapping of the application:

```
    0x555555554000     0x55555eb18000                      [elf file]
    0x55555eb18000     0x55555ecdd000 rw-p   1c5000      0 [heap]
    0x7ffdd0000000     0x7ffe50000000 ---p 80000000      0 [anon_7ffdd0000]
    0x7ffe50000000     0x7ffe50001000 rw-p     1000      0 /memfd:wasm-memory-image (deleted) => wasm linear memory
    0x7ffe50001000     0x7ffe50020000 rw-p    1f000      0 [anon_7ffe50001] => more wasm linear memory
    0x7ffe50020000     0x7fffd0000000 ---p 17ffe0000     0 [anon_7ffe50020] => guard page
    0x7fffd0000000     0x7fffd00a2000 rw-p    a2000      0 [anon_7fffd0000] => next page with leaks
    0x7fffd00a2000     0x7fffd4000000 ---p  3f5e000      0 [anon_7fffd00a2] => another guard page
    0x7fffd8000000     0x7fffd805c000 rw-p    5c000      0 [anon_7fffd8000]
	.... [more similar pages removed]
    0x7ffff7cdf000     0x7ffff7ce3000 rw-p     4000      0 [anon_7ffff7cdf]

    [libc]
	[libm]
	[libgcc_s]
	[vvar]
	[vdso]
	[ld.so]
	[stack]
	[vsyscall]
```

## Leaking addresses

To make things easier, I wrote two functions named `readmem` and `writemem` in `payload.c` which shift their 64-bit offset inputs to the right by 3 bits, and then pass the index to `read_qword`/`write_qword`. This will allow us to pass any offset from the base of the `wasm-memory-image` page in the mapping above, and read the qword at that offset. As you can see in the mapping, there is a page that is always mapped at offset `0x180000000` from the base of `wasm-memory-image` page. By examining values in this memory region, I found out that its first qword always contains a pointer to offset 0x30 in the same region, so by reading this pointer and subtracting `0x180000030` from it we can find the address of the base of `wasm-memory-image`. Also, the 3rd qword in that page contains the size of the page (0xa2000 in this example) so we can read that value and know how much of the page we should read to search for leaks.

Then, we can search through the whole next page to look for leaks. I thought maybe looking at the largest pointer value in this mamory area could give us a useful pointer into the mapped libraries. I wrote this loop:

```C
uint64_t max_ptr = 0;
for (uint64_t i = 0; i < next_size; i += 8) {
	uint64_t value = readmem(0x180000000 + i);
	if (value > max_ptr && value - membase < 0x200000000) {
		max_ptr = value;
	}
}
log(max_ptr);
```
This will search the whole page for the largest pointer value that is less than `0x200000000` bytes away from `membase`. Running this multiple times, I realized that the address shown has lower bytes of `0x2f0` many times (but not always). So I added a condition of `(value & 0xfff) == 0x2f0` to the if condition in the loop to always return that specific pointer. I inspected the address of the pointer in gdb and realized that this is a pointer conveniently pointing to the `link_map` pointer in `ld.so` memory region, and it's always present in the page we're searching. So, finding the largest pointer that ends in `0x2f0` will give us `link_map`. Then, we can just search for a libc pointer in ld memory (I used pwndbg `probeleak --point-to libc <ld_base> <size>` to find the pointers) and leak libc base by reading those.

## RCE with ROP chain

Now that we have ld base and libc base, we can write anything into their memories. Initially, the elf base is written into `link_map` in ld memory. When the program exits, the value written at `link_map` will be loaded into `rbx` and a constant offset is added to it (called `link_map_call_offset` in the exploit code), and whatever value is stored at the resulting address is called (`call qword ptr [rbx]`). Also, by writing `0x4141414141414141` in link map in gdb and waiting for the program to crash, we can see that at the time of crash `rbp` holds the address of link map. So, if we write the address of `link_map - 8 - link_map_call_offset` into link map, it will set rbx to `link_map - 8` and then `call qword ptr [rbx]`. Now if we write the address of a `leave ; ret` gadget at `link_map - 8`, it will move rbp into rsp (so rsp will be equal to `&link_map`), and then do a `pop rbp`, and then `ret`. So, the `ret` will be called when `rsp` is pointing to `link_map + 8`, and we can write our ROP chain there. I just used a simple ROP chain to call `system("/bin/sh")`.

ROP plan:

```
link_map - 8    => leave ; ret
link_map        => link_map - 8 - link_map_call_offset
link_map + 8    => ret
link_map + 16   => pop rdi ; ret
link_map + 24   => str_bin_sh address in libc
link_map + 32   => system()
```

And we get a shell!
