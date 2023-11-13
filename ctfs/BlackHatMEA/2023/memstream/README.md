The binary is packed with UPX. I initially made the mistake of unpacking it, however the packed binary
that is being run on the server has a security vulnerability compared to the unpacked one.
If you run the packed version, the offset of `ld.so` memory pages is constant to the binary base.
(Unpacking is useful for exploring the binary and understanding how it looks though because the packed
version has no symbols and might look pretty scary).

We have arbitary write before the `g_buf` buffer by seeking to negative values, and in the packed
binary `ld.so` is loaded before the binary, so we have arbitary write into `ld.so` memory. At offset `0x3b2e0` from ld base,
there is a pointer to the base address of the binary. Also, at the offset `0x3d88` of the binary there is
a readonly pointer to the function `__do_global_dtors_aux`. What happens is that when the binary exits,
ld will get the pointer at its offset `0x3b2e0` and add `0x3d88` to it. Then it will call whatever value is
stored there. You can observe this by overwriting the value at offset `0x3b2e0` from ld base with a junk
value and see that gdb will show segfault at a `call qword [rax]` instruction where `rax` is `0x3d88` more
than your junk value. Also, there is a pointer in the binary data section (offset `0x4008` from binary base)
that points to itself. We will partially overwrite this pointer to point to the `win` function instead. Then
we will partially overwrite the pointer inside `ld.so` memory to point to a value, which if added to `0x3d88`, will point
to the offset `0x4008` from binary (we basically have to add `0x4008 - 0x3d88` to the pointer inside ld).
This will result in `win` being called instead of `__do_global_dtors_aux`.

Note: Exploits that rely on the memory pages having constant offsets might not be 100% reliable, and also these
offsets might change between different kernel/libc/... versions. In this case the offset was the same between
my local environment and docker and also the remote CTF server. However, disabling ASLR will change the offset by
loading `vvar` and `vdso` between `ld.so` and binary. So I did the exploit development and debugging with ASLR enabled
to better simulate the remote memory layout.
