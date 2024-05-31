**Summary**: Exploiting a stack overflow in a MIPS binary to get RCE.

This is the first MIPS pwn challenge I've solved!

I opened the binary in ghidra, and started reversing it. It first checks that the first two characters of the input string are `LE` and the 8th and 9th characters are `GO` (the ones in between them don't matter). Then, it will take the first 15 characters of the input away and decrypt the rest of it with AES with a random key that is printed in the beginning of the program. Then, this payload is passed to the `parse` function. So, we just need to encrypt this part of our payload with the key we're given before sending it.

the `parse` function will split the input by `&` and for the parts that start with `t=`, `sscanf("%s")` them onto a buffer on the stack, which is almost equivalent to `strcpy` and is a vulnerability. We can therefore overwrite the `ra` register saved on the stack (which holds the return address of our function).

There is a function in the binary called `logging`, which uses the `system` function. We can overwrite the return address with `0x401054` which is an address in this function that loads the address of `system()` and calls it. In MIPS, arguments are passed in the `a0`, `a1`, `a2`, ... registers. So, we just need to load `a0` with an address that points to `/bin/sh` or `sh`. By breaking at the call to system in gdb and sending some more `AAAA` bytes after our input payload, we can see that the value written at offset 0x20 of the vulnerable stack buffer will be copied into `a0` (with a small constant offset subtracted from it) when we reach the `system` call in our payload. So, we can just write the address of `sh` in this address. To have a constant and known address for `sh`, we can write the string `sh` among the first 15 bytes of our input string, and since the initial input string is read into a buffer in global memory and since there is no PIE, we will know the constant address of `sh` string.

We just need to use two `t=` keys in our input so that the null-bytes at the end of the return address value don't terminate our string (and disrupt `strtok`/`sscanf`)
