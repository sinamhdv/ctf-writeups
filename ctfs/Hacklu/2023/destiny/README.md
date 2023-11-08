CTFtime: https://ctftime.org/task/26626

This is a shellcoding challenge, where our shellcode will be considered as an array of 4-byte numbers
and sorted in a weird way (comparing bytes of numbers in reverse order so the most significant byte will
actually be the rightmost byte) and then executed. To prevent our shellcode from being altered, we will
use small chunks of instructions which begin with a custom byte as the most significant byte of that dword, and we will manually keep these custom bytes ordered.
We also have to carefully choose some instructions that have suitable opcodes and don't change the ordering
when we need to have longer blocks of instructions or instructions with longer length. [This](http://ref.x86asm.net/coder64.html) was a helpful resource in exploring the opcodes of instructions and choosing them for this challenge. This was a good challenge to explore shellcoding with specific limits and conditions.
