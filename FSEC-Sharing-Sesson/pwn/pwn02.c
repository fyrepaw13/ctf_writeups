#include <stdio.h>
#include <stdlib.h>

void setup(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
}

void win(){
	puts("The flag is flag{pwn02}");
}

int main(){
	char buffer[32];

	setup();

	printf("What is your name?\n>> ");
	gets(buffer);
	printf("Hi ");
	printf(buffer);
	puts("");

	printf("Tell me about yourself\n>> ");
	gets(buffer);
	return 0;
}

// gcc pwn02.c -o pwn02 -fstack-protector -no-pie -z execstack