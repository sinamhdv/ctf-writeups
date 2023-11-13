In this challenge, the input of `employee.age` in `main` is vulnerable, because `age` is a 4-byte number but we are using `%ld` to read an 8-byte number in its address. Therefore, we will be able to overwrite the lowest 32 bits of `employee.name` through that. Also, `n` is not initialized to 0 in the `get_string` function and it happens to hold the value of 8 when `getline` is being called. Therefore, as long as our input is not more than 8 bytes long, `getline` will not try to call `realloc` on `employee.name` and will write our input there. So we have an arbitrary write of at most 8 bytes. We will use this to write some GOT entries and make `main` call itself again to repeat the vulnerability. Then, we write `printf@plt` into `free@got` to create a format string which can help us leak everything. After leaking libc addresses we just overwrite `free@got` with `system@libc` to get RCE by passing `/bin/sh` into `employee.name`. This was a nice example of overwriting a function's GOT entry with `printf@plt` to get a format string for leaking stuff.