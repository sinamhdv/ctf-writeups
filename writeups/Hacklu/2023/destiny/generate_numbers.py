# generate the numbers format from raw shellcode to
# send as input to the challenge binary
import struct

with open("raw-shellcode", "rb") as f:
	shellcode = f.read()

outf = open("numbers.txt", "w")

for i in range(0, len(shellcode), 4):
	chunk = shellcode[i:i + 4]
	num = struct.unpack("<I", chunk)[0]
	print(num)
	outf.write(str(num) + "\n")

outf.write("\n")
outf.close()

