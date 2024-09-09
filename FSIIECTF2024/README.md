![image](https://github.com/user-attachments/assets/484bcec5-0ac8-4155-a9b0-396d3eae19e5)# LACTF2024

## Table of Contents
- [rev/easy-crackme](#reveasy-crackme)
- [pwn/orcwars](#pwnorcwars)
- [pwn/flag-service](#pwnflag-service)

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

![image](https://github.com/user-attachments/assets/21264960-b2c2-461c-91eb-f2ebbe3cfa66)

We are presented with a menu based game where we need to get more troops than the enemy

![image](https://github.com/user-attachments/assets/f8699ce3-687a-4789-bd29-237626d15822)

Our total troops must be at least 0x22a to get the flag.

![image](https://github.com/user-attachments/assets/6b8eeebf-0b8d-492b-9987-9bd50448e129)

The problem lies in the line `if ((int)local_34 < (int)(uVar5 * 100)) {`. The variable uVar5 is declared as an unsigned integer but is being casted to an integer. Hence, we can give a large number of mercenaries. After multiplying by 100, it should result in a negative number due to how integer works.

![image](https://github.com/user-attachments/assets/8903b488-c489-436b-84a8-cd229f4b0bd8)

Enter 1.1 billion

![image](https://github.com/user-attachments/assets/67e7ef6a-00e7-436b-b3aa-f8d4b575d062)

Fake flag because the remote server is not active anymore, so I just ran this locally.

## Pwn/Flag-service
