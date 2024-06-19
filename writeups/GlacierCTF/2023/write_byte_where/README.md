**Summary**: Going from one-byte arbitrary write to full RCE via `FILE` struct exploitation on libc 2.38 and either writing a ROP chain on the stack or `FILE` vtable attack.

In this challenge, we can write one arbitrary byte into any address we want, and then the program will call `getchar()` twice before calling `exit(0)`. Also, we are given full leak of the process memory by printing the contents of `/proc/<pid>/maps` in the beginning, and also a stack leak which reliably locates the stack frame of `main()` so that we can reliably write values to the stack (without environment variables and argv changing the offsets).

I decided to write one byte into the `_IO_buf_base` pointer of the `FILE` struct of `stdin` in libc memory. Because `stdin` is unbuffered (via the `setbuf` call in the beginning of program), the `_IO_buf_base` pointer initially points to the `_short_buf` field in the `FILE` struct, and `_IO_buf_end` points to one byte after it. By reading the execution path of `getchar()`, we can see that if `_IO_read_ptr` is not less than `_IO_read_end`, it will eventually call `_IO_file_underflow()` which will use the syscall `read(fp->_fileno, fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base)`. Before calling `read`, it sets all the buffer/read/write pointers in the file struct to `_IO_buf_base`, and after calling `read` it will increase `_IO_read_end` by the number of bytes read (the value returned by syscall `read`).

A part of the code for `_IO_file_underflow()`:
```C
fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
fp->_IO_read_end = fp->_IO_buf_base;
fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

count = _IO_SYSREAD (fp, fp->_IO_buf_base,
	       fp->_IO_buf_end - fp->_IO_buf_base);

...
fp->_IO_read_end += count;
```

If we overwrite one byte in the `_IO_buf_base` pointer so that it points to somewhere right before the `stdin` file struct, the `getchar()` call will allow us to overwrite everything in the `stdin` file struct up to the `_short_buf` field. This allows us to overwrite the pointers again in a way that after the first `getchar()` call, `_IO_buf_base` points to any arbitrary location, and `_IO_buf_end` points to somewhere after that location. Then, when the second `getchar()` is called, we have arbitrary write of however many bytes we want in any location. As we have a reliable stack leak, we can just point `_IO_buf_base` to where the return address of the `getchar()` call would be on the stack, and write a ROP chain there so that when `getchar()` returns, we get a shell.

### Alternative Solution: vtable attack

If we were not given leaks from all memory regions and we only had libc leaks, we could get code execution using vtable attack on the same `stdin` file struct. In the previous solution, after the first `getchar()` call we set `_IO_buf_base` and `_IO_buf_end` of `stdin` to point to the stack and wrote our ROP chain there. Instead, if we weren't given a stack leak, we could point `_IO_buf_base` to the beginning of `stdin` and `_IO_buf_end` to somewhere far after it, and overwrite the whole `stdin` struct in the second `getchar()` call.

When `exit(0)` is called after the second `getchar()` call, somewhere in `exit()` function, `_IO_cleanup()` is called, which itself calls `_IO_flush_all()` to flush the buffers of all file structs:

```C
int
_IO_flush_all (void)
{
  int result = 0;
  FILE *fp;

#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif

  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      _IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      _IO_funlockfile (fp);
      run_fp = NULL;
    }

#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif

  return result;
}
```

This will go though the linked list of all opened file streams (using the `_chain` field in their structs) and flush the ones that require being flushed. If we can reach the code path that calls `_IO_OVERFLOW()` in this function, we can overwrite the vtable of `stdin` so that another IO function is called instead of the overflow function. It appears that to trigger this code path one way is to have `fp->_mode <= 0` and `fp->_IO_write_ptr > fp->_IO_write_base`. So we will set the `_mode` field to zero when overwriting `stdin` struct in our second `getchar()` call, and we will set `_IO_write_base` to 0 and `_IO_write_ptr` to 1.

Now to do a vtable attack, we will overwrite the vtable of `stdin` in a way that when `_IO_OVERFLOW()` is called on it in the above code, `_IO_wfile_overflow()` is executed instead (`_IO_wfile_overflow` is located in `_IO_wfile_jumps` vtable which is somewhere before `_IO_file_jumps` vtable in this libc version). The reason we're doing this is that somewhere in `_IO_wfile_overflow()`, `_IO_wdoallocbuf()` is called, which will then call an offset of the `fp->_wide_data->_wide_vtable` without vtable validation.

```C
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0
      || f->_wide_data->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
...
```

The conditions to reach the `_IO_wdoallocbuf()` call is to have `_IO_NO_WRITES` flag set to zero and `_fp->_wide_data->_IO_write_base` zero.

```C
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
...
```

Now in `_IO_wdoallocbuf()`, in order to call `_IO_WDOALLOCATE()`, `fp->_wide_data->_IO_buf_base` must be `NULL` and the `_IO_UNBUFFERED` flag must be zero. If we meet all these requirements, `_IO_WDOALLOCATE()` macro will call the `__doalloc` function of the `fp->_wide_data->_wide_vtable` field without vtable validation. I overwrote `stdin->_wide_data` with the address of `stdin` and overlapped the `FILE` and `_IO_wide_data` structs to meet all these requirements. You can see the details in `exploit_vtable_attack.py` script. Unfortunately, none of the one_gadgets worked, so I had to put the address of `system()` in the fake vtable, and because all vtable functions are passed the `FILE *fp` pointer as their first argument, I wrote something in the `_flags` field of `stdin` to give me a shell when passed to `system()`. Again, you can see the details in the exploit script.

I learned a lot about file stream exploitation techniques in this challenge :)
