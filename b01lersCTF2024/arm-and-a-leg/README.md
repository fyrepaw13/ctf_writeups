![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/821f9720-c70c-4f8e-b171-361268854f69)

This was the first time I faced a challenge that was using aarch64 architecture. Unfortunately, I wasn't able to solve this during the CTF but I read the writeups and was able to try it myself.

To be able solve this challenge, we first must set up the environment for the challenge.

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
