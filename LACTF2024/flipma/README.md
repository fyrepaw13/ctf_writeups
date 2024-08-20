I did not solve this challenge but I decided to look back at it because I wanted to learn FSOP and overwriting exit funcs with one gadget.

## Challenge

> This challenge provides us with 4 bit flips, and our addresses are calculated at an offset from `_IO_2_1_stdin_`. The path to a solution, as with many other bit flip challenges, is to first get infinite bit flips for arbitrary write. The bit flip counter is stored in the base program’s bss, but PIE is enabled. Our goal should be to leak the base address before our 4th bit flip so that we can overwrite the counter. The flip being relative to stdin hints that we will need some form of leak-oriented FSOP. Unbuffered file streams hold libc addresses to themselves in the buffer fields, but the file write function called from puts will treat the stream as buffered as long as there is a difference between _IO_write_base and _IO_write_ptr. This will cause the write function to print out memory from libc between those two addresses.

