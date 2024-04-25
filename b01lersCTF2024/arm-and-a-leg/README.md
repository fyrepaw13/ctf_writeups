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

<details>
<summary>Output</summary>
  
```c
undefined8 main(void)

{
  int iVar1;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  setup(&__stack_chk_guard,0);
  iVar1 = puts(
              "Hello! \nWelcome to ARMs and Legs, here for all of your literal and metaphorical need s!"
              );
  print_menu(iVar1);
  __isoc99_scanf(&DAT_00400d08,&local_c);
  if (local_c == 1) {
    iVar1 = puts(
                "So, you\'d like to purchase an ARM...are you worthy enough to purchase such an appe ndage?"
                );
    iVar1 = worthyness_tester(iVar1);
    if (iVar1 == 0) {
      get_address();
      feedback();
    }
    else {
      puts("Close, but no cigar. Maybe try a Leg?");
    }
  }
  else if (local_c == 2) {
    iVar1 = puts(
                "So, you\'d like to purchase a Leg...are you worthy enough to purchase such an appen dage?!"
                );
    iVar1 = worthyness_tester(iVar1);
    if (iVar1 == 0) {
      get_address();
      feedback();
    }
    else {
      puts("Close, but no cigar. Maybe try an ARM?");
    }
  }
  if (local_8 - ___stack_chk_guard == 0) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(&__stack_chk_guard,0,0,local_8 - ___stack_chk_guard);
}
```

</details>
