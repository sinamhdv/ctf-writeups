# a script to reproduce the remote environment
import os
import string
import random

random.seed(1)

MAX_LEN = 16
FILES_CNT = 40
CHARSET = string.digits + string.ascii_letters
names = set()

def get_filename():
	global names
	while True:
		n = random.randint(1, MAX_LEN)
		name = "".join(random.choice(CHARSET) for i in range(n))
		if name not in names:
			names.add(name)
			return name

for i in range(FILES_CNT):
	new_file = get_filename()
	if not os.path.isfile(new_file):
		with open(new_file, "w") as f:
			f.write("not flag")
with open(get_filename() + ".txt", "w") as f:
	f.write("flag{placeholder_for_flag}")

