# ASIS CTF 2023 Finals - game of luck

CTFtime: https://ctftime.org/event/1953

Distributed files: `chall`, `libc.so.6`, `ld-linux-x86-64.so.2`, `Dockerfile`

In this challenge, there is no check on the number you enter as your bet value to be less than your current money. Thus, you can change your money into -1 to pass the size check when reading user feedback, and cause `read()` to be called with a size of `0xffffffff`. This will enable you to write into the `lives` buffer on the stack to prevent losing and change your money to something non-negative to prevent the `money < 0` check as well. The buffer `lives` on the stack is printed in each turn so we can write into the first null-byte of the canary so that the canary is leaked when `lives` is printed. Same way, we can leak the return address of `main()` which is a libc address. Then, we can write a normal ROP payload to call `execve("/bin/sh", 0, 0)` on the stack.

NOTE: the large `read()` might sometimes fail and is not 100% reliable.
