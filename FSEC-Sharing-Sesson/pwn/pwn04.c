#include <stdio.h>
#include <stdlib.h>

void setup(){
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
}

int main(){
	char buffer[64];

	setup();

	printf("Heres a present for you : %p\n", &buffer);
	printf(">> ");
	gets(buffer);
	return 0;
}

// gcc pwn04.c -o pwn04 -fno-stack-protector -no-pie -z execstack
// gcc pwn04.c -o pwn04 -no-pie -fno-stack-protector 