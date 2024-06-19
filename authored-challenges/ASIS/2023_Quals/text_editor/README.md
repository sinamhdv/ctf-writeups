# ASIS CTF 2023 Quals - text editor

CTFtime: https://ctftime.org/event/1952

Distributed files: `Dockerfile`, `chall`, `xinetd.conf`

This is a format string challenge. The text buffer in global memory has an overflow which lets us change the `error_string` pointer to point to the text buffer itself (with a partial overwrite). The `error_string` pointer is passed directly to printf when we enter an invalid option in the menu. So by controlling its content we can use a format-string attack. `save_text` function will copy the text buffer onto the stack so we can use that to move our format string payload onto the stack as well, which gives us arbitrary write with format string. We can leak the binary base, libc, and stack, using format string, and then use it to write a ROP payload for `system("/bin/sh")` onto the stack after the return address of `main`.
