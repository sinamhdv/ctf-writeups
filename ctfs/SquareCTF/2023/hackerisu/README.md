CTFtime: https://ctftime.org/task/27127

**Summary**: Reversing and finding implementation vulnerabilities in a C++ game and then modifying a string object in memory to get RCE.

This challenge is a C++ implementation of the popular *Baba Is You* game. I wrote its psuedo-code after reversing the game in `psuedocode.cpp`. Using Ghidra's struct editor to specify different fields of `Object` class (as I guessed what they were in the reversing process) was a helpful step in reversing the code and making the decompilation more clear and understandable. The game map has different objects on it with different types. The `objectType` of an object determines its characteristics (more explanation on object types is mentioned in `ObjectType` enum in `psuedocode.cpp`). There are two types of phrases on the game map. `XisY` phrases (e.g. `cloudispush`) determine the type of objects, and `XatY` phrases are used to overwrite the name of an object at a specific address. For example, by changing `cloudispush` to `cloudisu`, you can control the cloud objects! The game will scan the whole game map vertically and horizontally for these phrases each turn and then it will set the types of objects based on them. It will also change the name of the object at address `Y` to `X` after seeing an `XatY` phrase.

The first vulnerability is in `Game::removeMelted()` when the game handles destroying objects that move onto another object with the type `MELT`. It removes elements from a vector as it is traversing the same vector in a for-each loop. This will cause it to skip removing one of two consecutive objects, whereas both of those objects should have been removed.
I used this vulnerability to escape the first closed area in the game. By changing `kekeispush` into `kekeisu`, I could control the character `keke` as well, and then I moved both of my controllable characters into the same cell. Then, I moved them onto the sun object that prevented me from escaping. Because of this bug, only one of the characters would be destroyed, so I could move one of these characters out of the first closed area! This will have the challenge print the first flag for us (`flag0` string). The rest of my solution will just get a shell and I won't try to escape the second area to get `flag1` as well. Instead, after getting a shell we can just `cat` or `strings` the challenge binary on the server to read `flag1`.

After escaping the first area, we can directly change the `babaat0x...` phrase on the game board. I noticed that the game calls `system(theend.c_str())` in the `alarmHandler` function, which will be called 20 seconds after the start of the game using `SIGALRM`. `theend` is a global string object. So, if we can change the address at the right of the `babaat0x...` phrase into somewhere around the address of `theend`, and change the `baba` at the left side of this to `sh` we will call `system("sh")` in the alarm handler and get a shell!

Inspecting this process more carefully, the game seems to be calling the `setObjectName` function on the object at the specified address. `setObjectName` gets `Object *this` as its first argument and `string name` as the second argument, and then calls `string::operator=` on the string at `this+0x18` and the string passed to it as the new name. So, we can set the address on the game map to `theend - 0x18`. This will cause `setObjectName` to call `string::operator=(theend, <the string on game map>)`.
The address of `theend - 0x18` is `0x660bc8`. To build this address in the game, we can use the `b`, `0`, and `x` characters that are already in the `babaat0x...` phrase. The initial address also seems to be always ending with a `0` so we can use that as an extra `0` to build the third digit of our address. However, we need to get lucky with ASLR so that the initial address (which is the address of baba object on the stack) contains at least one `8`, one `c`, and two `6` digits. This is an approximately 1/200 brute-force.

We can build the address, and then use the `sh` characters at the end of `digitispush` to change the string at the right of this address to `sh` and finally we will win!

We might be able to reduce our dependance on ASLR and make the brute-force more reliable by controlling the cloud objects in the first area at the same time as keke and moving some of the necessary digits out of the first area by the same method. However, writing an exploit that does this takes longer, and 1/200 was a reasonable chance so I didn't try to do that. I made an attempt to do that in `failed_exploit.py`, but I realized I made a mistake in the beginning and needed to correct all of the moves after that mistake. This was a long process so I just decided to stick with the less reliable approach.