extern unsigned long long arr[0x10];

unsigned long long read_qword(unsigned int idx) {
	return arr[idx];
}

