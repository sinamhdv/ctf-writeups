# ASIS CTF 2023 Finals - text editor v2

CTFtime: https://ctftime.org/event/1953

Distributed files: `chall`, `libc.so.6`, `ld-linux-x86-64.so.2`, `Dockerfile`

This challenge was a heap challenge with a single null-byte overflow (an off-by-one) in the `String_push` function in
`custom_string.h`. The custom string data structure keeps a current length and a maximum length (`capacity`) and will double
the size of its allocated buffer (i.e. double its capacity) when its length reaches the capacity (i.e. the current buffer is full). However, it doesn't count for the extra null-byte written one byte after the end of the buffer when writing the last character before expanding the buffer. This lets us clear the `PREV_INUSE` bit of the next chunk, that can be used to perform an unlink attack on the heap. the details of the unlink attack and setting up the heap for it are mentioned in the `exploit.py` script. After the unlink attack, we can't directly change the buffer pointer of a tab to some arbitrary value, because characters are pushed one-by-one and after changing one byte of the pointer we can't change the rest and the pointer will be corrupted. We will instead overwrite the `tabs_count` variable which is located after the buffer pointers in global memory, to let us select tabs with indexes larger than 1. Then we create a fake `String` object as a tab with index 3 and write an arbitrary value into its buffer pointer to get arbitrary read/write in the GOT. Then we just leak libc and change `puts@GOT` to the address of a one_gadget.
