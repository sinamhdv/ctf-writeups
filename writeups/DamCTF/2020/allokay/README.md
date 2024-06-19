CTFtime: https://ctftime.org/task/13353

In this task we have a for loop that lets us overwrite the loop end variable and counter to "jump over" the canary and
write onto the saved return address. We will use this to write a ROP payload on the stack and win.
