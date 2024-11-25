# Audit

## No-name minor

This was a challenge similar to the one I created for Battle of Hackers 2024 so we solved it relatively fast. The challenge provides us with a binary that presents a menu that allows the user to borrow a loan, repay the loan, mining for money, buy a name and change name. The goal is to get a name. But 

- To buy a name, you need to have money.
- To have money you cannot simply mine, cause it will take a lot of time.
- So you need to loan and then repay them.

The vulnerability lies in the way the program keeps track of the user's loan.

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

The user's loan is defined as a float, which can be subjected to **floating point inaccuracy.**  A float is 32 bit and it has 1 bit for sign, 23 bit for mantissa and 8 bit for exponent. For integers, the inaccuracy starts at 2^24. In other words, all integers can be represented as floats up to 2^24 but not beyond that. Specifically, in the range of 2^24 to 2^25, float does not support odd numbers, only even numbers.

### Proof of Concept

![image](https://github.com/user-attachments/assets/e75708b0-e383-4faa-bb98-5bbff0919289)

![image](https://github.com/user-attachments/assets/592a968a-5ee3-4b0d-a6b0-281de6eae7fa)