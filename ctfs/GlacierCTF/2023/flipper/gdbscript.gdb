# a gdb script to parse and print the page table data structure
file kernel64.x
target remote :1234
b Syscall::write
continue

# At this point, CR3 = 0x3f0000
p/x (*(PageMapLevel4Entry *)(0xfffff00000000000 + 0x3f0000)@512)[0b111111111]
p/x (*(PageMapLevel4Entry *)(0xfffff00000000000 + 0x156000)@512)[0b111111110]
p/x (*(PageMapLevel4Entry *)(0xfffff00000000000 + 0x158000)@512)[0b000000000]
p/x (*(PageMapLevel4Entry *)(0xfffff00000000000 + 0x159000)@512)[0b100110010]


