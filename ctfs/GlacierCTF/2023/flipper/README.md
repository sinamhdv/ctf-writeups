In this challenge we have a small educational kernel as our target. There is a system call added that can flip a bit only once anywhere in memory, and our goal is to read the `flag` variable that is in kernel memory.

We can download the original version of the OS from its git repository, too. Then, we can checkout to the commit specified in the challenge description, and do `git apply challenge.diff` to make the necessary changes for this challenge to the code. The result for this is inside the `sweb` directory in the files here.

By looking at the code of `Syscall::write` in `common/source/kernel/Syscall.cpp`, we can see that the only condition in this function that prevents us from calling `write(1, <address of flag>, 100)` is the line with the condition `(buffer >= USER_BREAK) || (buffer + size > USER_BREAK)`, where `USER_BREAK` is just some constant defined threshold. Therefore, if we can somehow patch this condition we can enable reading all kernel memory without any other constraints. By looking at the disassembly, we can see this:

```
<Syscall::write>
ffffffff8010a732: push   rbp
ffffffff8010a733: mov    rbp,rsp
ffffffff8010a736: sub    rsp,0x30
ffffffff8010a73a: mov    QWORD PTR [rbp-0x18],rdi
ffffffff8010a73e: mov    QWORD PTR [rbp-0x20],rsi
ffffffff8010a742: mov    QWORD PTR [rbp-0x28],rdx
ffffffff8010a746: movabs rax,0x7fffffffffff
ffffffff8010a750: cmp    rax,QWORD PTR [rbp-0x20]
ffffffff8010a754: jb     0xffffffff8010a770
ffffffff8010a756: mov    rdx,QWORD PTR [rbp-0x20]
ffffffff8010a75a: mov    rax,QWORD PTR [rbp-0x28]
ffffffff8010a75e: add    rax,rdx
ffffffff8010a761: movabs rdx,0x800000000000
ffffffff8010a76b: cmp    rdx,rax
ffffffff8010a76e: jae    0xffffffff8010a77a
ffffffff8010a770: mov    eax,0xffffffff
ffffffff8010a775: jmp    0xffffffff8010a816 -------> *****
ffffffff8010a77a: mov    QWORD PTR [rbp-0x8],0x0
ffffffff8010a782: cmp    QWORD PTR [rbp-0x18],0x1
ffffffff8010a787: jne    0xffffffff8010a7f0
ffffffff8010a789: mov    rdx,0xffffffff80133c48
ffffffff8010a790: mov    esi,0x22
ffffffff8010a795: mov    rdi,0xffffffff80133c50
ffffffff8010a79c: mov    eax,0x0
```

The `jmp` instruction at address `ffffffff8010a775` is what is moving us to the failure branch of the function. If we can patch it into something else, we will win. The opcode of this `jmp` starts with `e9`, which we can change into `a9` by flipping its 6th bit (zero based). This will change it into a `test` instruction with exactly the same length! So by doing `flipBit(jmp_addr, 6)` and then `write(1, flag_addr, 100)` we can see the flag! The only step that remains is to find the address of flag and the jmp addr. This is easy in the kernel that can be compiled with `-DDEBUG=1` from the `sweb` directory, which has all symbols. However, the version given in the challenge does not have symbols when compiled. We can use Ghidra to search for and find the address of `flag` string, but to find the address of the `write` function and its `jmp` instruction I ended up doing searching for a less common instruction in `write()` by doing `objdump -Mintel -d build/kernel64.x | grep -B10 -A20 -i 'movabs.*rax,0x7f'`, and the first result appeared to be the code of `write` when I compared it to the version with symbols.

## Alternative idea:

We initially worked on another idea which involved flipping the `user_access` bits of the x86 page table data structure (which is a trie with 4 levels) to make the page containing the flag accessible to user programs. Then we could just do `mov [flag_addr], %rax` in our exploit and print `rax`.

The problem was that we only had 1 bit flip, but for this idea to work we needed to flip all 4 `user_access` bits in the entries for the page containing the flag all the way from the root of the tree to its corresponding leaf node. However, I learned a lot about x86-64 paging along the way, and it was a really cool experience! So, it is worth explaining.

The paging structure will allow you to resolve a virtual address of a page into a physical address corresponding to it. The physical address of the root of this tree is stored in the `CR3` register. The implementation of the paging structures for this OS are in `arch/x86/64/source/ArchMemory.cpp` and `arch/x86/64/include/ArchMemory.h`. The list of children for each node of the tree is an array of 512 `qwords`, each of which is an instance of one of the structs in `ArchMemory.h`. We will divide our current address into 9-bit blocks (starting from the 47th bit because the left 16 bits are not used in paging) and according to the current 9 bits we will move to the corresponding child of the current node (trie data structure). After 4 levels, the resulting leaf node will have the physical address of the page we are looking for. It is helpful to look at the code of the function `ArchMemory::resolveMapping()` to see how the kernel parses this data structure and resolves a virtual address using it. Also, looking at the `getIdentAddressOfPPN` function in `ArchMemory.h` as well, we will see that the kernel is apparently assuming that the virtual addresses for the nodes of this data structure themselves are always `0xfffff00000000000` plus the physical address, so we can use this to parse the data structure ourselves in gdb. `gdbscript.gdb` has commands that will print the nodes of this data structure from the root to the leaf for the page containing `flag`. (it will only work for the version compiled with symbols using `./compile.sh sweb/` but not for `./compile.sh dist/` which does not have symbols).
If we could flip the `user_access` bits for all these 4 nodes, we would win. (you can try doing this manually in gdb).

There is some explanation on the implementation of paging in this kernel [here](https://www.iaik.tugraz.at/teaching/materials/os/tutorials/paging-on-intel-x86-64/).

