CTFtime: https://ctftime.org/task/26602

This challenge has a UAF vulnerability which lets you edit data of freed chunks. We will change the FD pointer of
a freed fastbin to get our arbitrary address into the fastbin head and get `malloc` to return an arbitrary
location. We will use `0x23` bytes before `__malloc_hook` to pass the libc protection which checks for
correct size metadata on fastbin chunks being reused. We use this to write the address of `system` into
`__malloc_hook` and call `malloc` with the size argument equal to the address of string `"/bin/sh"` to win.
