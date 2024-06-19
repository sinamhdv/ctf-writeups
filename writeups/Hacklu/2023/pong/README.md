CTFtime: https://ctftime.org/task/26618

In this challenge, the function epilogue does not return rsp to the base of the stack frame, and rsp will
point to our input buffer when we reach `ret`. So we can send any ROP payload. We will use SROP because
we don't hae enough gadgets but we have `inc rax` and `syscall`. Because of the unreliability of the stack leak,
we will not be able to use the exact address of "/bin/sh" string in our input when calling execve. Therefore,
we use SROP once to read a second ROP payload onto any known fixed location and in the second payload we include
another SROP to call execve("/bin/sh"). This was a nice challenge to learn about chaining SROP payloads together,
and exploiting binaries that have very limited gadgets for normal ROP.
