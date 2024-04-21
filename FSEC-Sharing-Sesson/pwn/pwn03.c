#include <stdio.h>
#include <stdlib.h>

void setup(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
}

void win(){
	puts("The flag is flag{pwn03}");
}

int main(){
	char buffer[64];

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


// gcc pwn03.c -o pwn03 -fno-stack-protector -z execstack