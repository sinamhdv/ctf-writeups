# Google CTF 2024 - Unicornel

**Summary**: Given an implementation of a small multithreaded emulator/kernel using unicorn engine, use a race condition in the management of shared memory pages between emulator threads to cause a UAF on the heap, and then overlap that chunk with unicorn `uc_engine` struct to get control of function pointers. Smuggle shellcode into rwx pages mapped by unicorn for JIT compilation, and jump to the shellcode by overwriting the function pointers.

## Intro

I played in Google CTF 2024 Quals with MMM, and we ended up qualifying for the finals! I solved this pwn challenge during the competition and definitely enjoyed it!

## Initial analysis

The challenge gives us the implementation of Unicornel, "a multi-process, multi-architecture emulator server
with concurrency and system call support". Some interesting notes about this emulator from the file `Documentation`:

- Can have at most one thread of each architecture at once.
- There are syscalls to create a shared memory page, and then multiple threads can map it using another syscall. One thread can have at most one shared memory page mapped at a time.
- There is a syscall to "bookmark" the CPU state and another syscall to "rewind" to it, and this rewind process will unmap any shared memory page mapped from the bookmark point to that moment, but won't revert writes to memory.
- A process can "pause" itself with pause syscall and another process can resume it with the resume syscall.
- There is a `switch_arch` syscall that can switch the architecture of an emulator thread at most once in its lifetime.

Some notes about the source code:

- It is including `unicorn/unicorn.h` (which is in `include/unicorn/unicorn.h` in unicorn's repo) to access some constants, structs, and functions from unicorn.
- The `hook_call` function in `chal.c` will be installed into the emulated vm using `uc_hook_add` function from unicorn, and whenever the emulated code interrupts the CPU, `hook_call()` will be called, and will dispatch the call to different syscall functions in `syscall.c` based on the syscall number (in the corresponding register of that arch).
- There is a mutex lock used by many functions to prevent race conditions on global state variables like `shared_buffers[]`, `processes[]`, `arch_used[]`, etc.
- The main thread will use `poll` to get any `unicornelf` format sent by user input and create a new emulator thread with it, or display any output from the emulator threads to stdout. Note that the standard fd's of the threads are not closed or changes, and the pipes created in `start_process` are just used for the `print_integer` or `unicornel_write` or similar syscalls that will directly write to them, so we don't need to worry about standard IO being closed if we get a shell on one of the emulator threads.
- There is reference counting implemented for shared memory buffers to know when to free them.
- The `ref` field in `shared_buffer` struct is an atomic int so arithmetic operations on it don't race with each other.

## Vulnerability

The `map_shared` function will get a shared memory handle (index in `shared_buffer[]` array) and map it in the emulator process memory. It will also increment the reference count `shared_buffer.ref` of that shared memory buffer. It also uses the mutex lock.The way it checks for the given handle to actually point to a valid shared buffer is that it will check `ref` to not be 0 on that slot:

```C
if(handle >= MAX_PROCESSES || !shared_buffers[handle].refs) {
	pthread_mutex_unlock(&task_lock);
	return -2;
}
```

The `unicornel_rewind` function, as mentioned before, will unmap any shared memory mapped after the bookmark was set. It will also decrease the reference count on that shared buffer, and if the reference count reaches 1 after decreasing, it will `free` the buffer and set the refcount to 0.

```C
/* If we bookmarked, then mapped a shared buffer, we need to unmap the shared buffer to
 * restore the original state properly.
 * We can skip a full unmap_shared call because we do the checking here directly.
 */
if(current->sbr.va && current->sbr.unmap_on_rewind)
{
	uc_err e = uc_mem_unmap(current->uc,current->sbr.va,current->sbr.length);
	if(e == UC_ERR_OK)
	{
		shared_buffers[current->sbr.handle].refs--;
	}
	current->sbr.va = 0;
	current->sbr.unmap_on_rewind = false;
	if(shared_buffers[current->sbr.handle].refs == 1)
	{
		//last reference, destroy it
		free(shared_buffers[current->sbr.handle].buffer);
		shared_buffers[current->sbr.handle].refs--;
	}
}
```

However, it doesn't use the mutex, so it can cause a race condition. The general idea is to have one thread call `map_shared` on a shared buffer and another thread call a `rewind` that will unmap the buffer at the same time. This is the vulnerable sequence:

- First thread checks `!shared_buffer.ref` on the buffer and the second thread hasn't zeroed the refcount yet so it passes.
- Second thread will decrement the refcount to 1. The first thread hasn't reached the `ref++` line yet.
- `ref` is now 1 so second thread will go into the `ref == 1` condition and `free()` the buffer.
- the first thread will map the buffer and increase `ref` again, so the final value of `ref` will be 1.

## UAF to RCE

My first idea was to play around with syscalls and calls into unicorn to allocate some tcache chunks in the UAF'd area and be able to corrupt the fd pointer of tcache chunks, and then do glibc heap exploitation. However, this ended up being really frustrating because the heap style was really fragile and sometimes not even deterministic. Unicorn uses the heap A LOT!

I did a `switch_arch` syscall after triggering the UAF to ARM and searched for function pointers on the heap, and found a `0x39c0`-sized chunk that had several `arm_....()` function pointers in it. I set conditional breakpoints on `malloc`/`calloc` with that size and realized it's the `uc_open` function in `switch_arch` allocating a `uc_engine` struct, which has function pointers to various unicorn functions for that arch. For example, the `arm_reg_read` is called whenever we call `ARG_REGR`, which calls `uc_reg_read`. I changed the size of the shared buffer we're creating and UAFing to 0x5000, and the `uc_engine` struct ended up being allocated in the UAF'd area!!! Now we have full read/write access to those function pointers so we basically have `pc` control. (look at unicorn source code `uc.c` and `qemu/target/arm/unicorn_arm.c` for some of this functionality)

The next step was to get RCE. I couldn't find any libc leaks in the UAF'd heap region, and didn't initially find any working ROP plans (although I didn't continue looking at that for long). Looking at `vmmap`, there are some `rwx` pages mapped, probably by unicorn to JIT-compile the emulated code. I searched for some big constant values I put in my x86 code, and they were in one of the rwx regions, JIT-compiled to some `movaps` instructions! So, I ended up adding a few more of those constants and smuggling my shellcode into the rwx region in the constants (kinda JIT-spraying but not spraying all over the place :) ) The shellcode offset in the rwx region ended up being deterministic and there was also a leak to that rwx page right at the first qword of the UAF'd heap region which we could read. So, I just overwrote the `arm_reg_read` function pointer with the address of shellcode.

I didn't want to have a long shellcode and do everything with the limiting situation of chaining shellcode parts in 64-bit constant values. So, I wrote a first-stage shellcode to call `read` in the same region (I used `rax` as the `read` location because after looking at the context after our `pc` control, `rax` had the same value as the function pointer's value) and then sent a normal `execve(/bin/sh)` shellcode as the second stage.

## Conclusion

I really liked this challenge, because of both giving me a look into some internals of unicorn engine, and the interesting vulnerability and exploitation path!
