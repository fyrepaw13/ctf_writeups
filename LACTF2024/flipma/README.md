I did not solve this challenge but I decided to look back at it because I wanted to learn FSOP and overwriting exit funcs with one gadget.

## Challenge

This challenge provides us with 4 bit flips, and our addresses are calculated at an offset from `_IO_2_1_stdin_`. Hence, we will use FSOP to get info leaks.
