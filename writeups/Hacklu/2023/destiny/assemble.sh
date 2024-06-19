gcc -nostdlib -static -o elf-shellcode $1
objcopy elf-shellcode --dump-section .text=raw-shellcode

