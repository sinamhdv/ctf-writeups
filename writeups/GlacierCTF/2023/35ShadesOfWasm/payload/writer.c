extern unsigned long long arr[0x10];

void write_qword(unsigned int idx, unsigned long long value) {
	arr[idx] = value;
}

