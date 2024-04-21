#include <stdio.h>
#include <stdlib.h>

void win(){
	puts("The flag is flag{pwn01}");
}

int main(){
	char buffer[16];

	gets(buffer);
	return 0;
}

// gcc pwn01.c -o pwn01 -fno-stack-protector -no-pie -z execstack