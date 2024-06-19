**Summary**: Fastbin-dup attack on glibc 2.38 with tcache enabled.

In this challenge, we have to write 0 into the `user_level_` field of the `User` object on the heap
in order to gain admin priviledges and be able to read the flag with `doAdminStuff` function. To do
this, we will use the double-free bug in the program for the ratings allocated and freed through
`writeRating` and `deleteRating` to perform a fastbin-dup attack.

One of the problems we have here is that our libc is glibc 2.38 with tcache. So, we need to fill tcache
by freeing 7 chunks before performing the fastbin-dup attack and making the fastbin list circular.
Also, before allocating from the corrupted fastbin list, we need to clear tcache by allocating 7 chunks
so that malloc starts serving next requests from the fastbin.

Because of the `PROTECT_PTR` macro used in `malloc` source code, and also because our target address is a heap
address, we need a heap leak as well. I used the read-after-free vulnerability to print the content of the
free'd chunks that were placed in the fastbins (by using the `showRatings` functionality). The chunk that was in the end
of the fastbin had its `FD` set to zero, but because of `PROTECT_PTR` macro, its `FD` was actually set to zero XORed with
a heap address right-shifted by 12. So, by reading the `FD` field of this chunk, we can get a heap leak.

A more detailed description of the exploitation steps is mentioned in the exploit script.
