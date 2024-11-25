# Audit

## No-name minor

The challenge provides us with a binary that presents a menu that allows the user to borrow a loan, repay the loan, mining for money, buy a name and change name. The goal is to get a name. But 

- To buy a name, you need to have money.
- To have money you cannot simply mine, cause it will take a lot of time.
- So you need to loan and then repay them.

The vulnerability lies in the way the program keeps track of the user's loan.

```c
# Miner struct
struct MinerAccount {
	float cash;
	float debt_balance;
	int mining_attempts;
	char name[0x20];
};

# Loan function
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

The user's loan is defined as a float, which can be subjected to **floating point inaccuracy.**
