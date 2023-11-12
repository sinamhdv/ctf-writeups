There is an off-by-one vulnerability in the `readInput` function (because it uses `jae` instead of `ja` at address `0x004017c8`).
This allows us to overwrite the LSB of the saved `rbp` in the stack frame of `readUsername`. This will cause `rbp` to be
smaller than expected when we return to the stack frame of `main`. Next time, we call `readDescription` and pass it
`rbp - 0xb0` from the stack frame of `main` as a pointer to `memMove` the data into. However, this time `rbp` is smaller than
expected and this buffer might overlap with the end of `readDescription` stack frame. Thus, we will overwrite the `readDescription` saved return address after `memMove` is called. Note that the src and dest of `memMove` cannot overlap because
of how it is implemented, otherwise the start or end of our input might be messed up (depending on how they overlap). Therefore, we need to also get lucky with this after several tries so that `rbp - 0xb0` pointer from the `main` stack frame overlaps with the saved return address of `readDescription` stack frame, but does not overlap with the `memMove` source.
This was challenge was a nice demonstration of how an off-by-one can lead to RCE on the stack.
