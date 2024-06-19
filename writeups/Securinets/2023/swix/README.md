I finished solving this challenge 40 minutes after the end of the competition.

The main problem in this challenge is getting a sufficient amount of data into the process memory to be used as ROP chains. we can only write 8 bytes in data section and 8 bytes on the heap. We are also allowed to write 4 dwords on and after the return address of `main()`, the 3rd of which is overwritten with `0xdeadbeef` before returning from `main()`.

The first 2 ROP chains are the username field of the friend object on the heap (2 dwords) and 2 dwords we can write after the stack frame of `main()`. We pivot the stack with a stack pivot gadget in the ROP chain on the stack. We point esp to the username field of friend to begin the other ROP chain. I also wrote the address of `main()` and then `read@plt` in the username field. Therefore, `main()` is re-executed and lets us write 4 more dwords after its frame on the heap. Due to subtle address alignments in the prologue of `main` (`and esp, 0xfffffff0`), This time we can write these 4 dwords at offset 8 after the return address of `main()`. So we can make the end of `main` stack frame look like this (the payload corresponding to this is called `rop2` in the exploit code):

```
[read@plt] => already is there from the username field payload. main() will return to this.
[0x0] => read will return to here <----
[0x0] => rop2 starts here             |
[the address after read@plt in this diagram (where read() will return to)]
[0xdeadbeef]
```

So this will call `read(0, ..., 0xdeadbeef)` and we can write a new ROP payload (called `rop3` in the code) after `read@plt`. We will write a new payload that calls `puts@plt` on the GOT and leaks libc addresses and then We can read in a 4th ROP chain (called `rop4`) to call `execve("/bin/sh", 0, 0)`.

However, due to libc buffering, this solution only worked locally because `puts()` output would not be flushed; and when I added `stdin=PIPE, stdout=PIPE, stderr=PIPE` in the local process spawning, it also stopped working locally. To fix this, I included a very large buffer of A's in `rop3` payload and called `puts()` on it to force libc buffer to flush.
