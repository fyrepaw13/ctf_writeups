![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/821f9720-c70c-4f8e-b171-361268854f69)

This was the first time I faced a challenge that was using aarch64 architecture. Unfortunately, I wasn't able to solve this during the CTF but I read the writeups and was able to try it myself.

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

We found that the leak is located inside __libc_start_main at offset 152
