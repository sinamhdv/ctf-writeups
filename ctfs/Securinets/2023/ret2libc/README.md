In this challenge, we have a simple stack buffer overflow in a 32-bit binary. However, because a saved register (`ecx`) on the
stack is later used to restore `esp`, it is not possible to reliably execute our ROP payload. To overcome this challenge, we
do a partial overwrite on the saved `ecx` to make it end up in the beginning of our ROP payload. Then, we use stack pivoting
and also return to `puts@plt` to get libc leaks and perform a normal ret2libc. This was a good challenge to experience tricky
function prologue/epilogue cases.
