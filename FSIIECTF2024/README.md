# LACTF2024

## Table of Contents
- [rev/easy-crackme](#reveasy-crackme)
- [pwn/orcwars](#pwnorcwars)

## Rev/Easy-Crackme

![image](https://github.com/user-attachments/assets/0bb9c9fc-0c5f-4733-82f8-96ef33e8e61a)

Looking at the decompilation in Ghidra, we can just reassemble the flag from local_78 to local_4f but I decided to use angr to solve it.

```py
import angr
import claripy

FLAG_LEN = 42# Provide flag length
STDIN_FD = 0
base_addr = 0x00100000

proj = angr.Project("./easy_crackme", main_opts={'base_addr': base_addr})

flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(FLAG_LEN)]                                               

flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])  # so that stdin works by adding \n to the end

state = proj.factory.entry_state(stdin=flag)

for c in flag_chars:					# make sure only printable characters
	state.solver.add(c >= ord('!'))
	state.solver.add(c <= ord('~'))

my_simgr = proj.factory.simgr(state)
find_addr = 0x00101435
avoid_addr = 0x0010145a 
my_simgr.explore(find=find_addr, avoid=avoid_addr)

if (len(my_simgr.found) > 0): # If a found state exists
	for found in my_simgr.found:
		print(found.posix.dumps(STDIN_FD)) # Print out the input
```

![image](https://github.com/user-attachments/assets/dd8c6a01-e80e-4f25-ab30-54c1e2fad345)

## Pwn/Orcwars
