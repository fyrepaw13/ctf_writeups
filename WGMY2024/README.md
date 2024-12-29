# WGMY2024

## Table of Contents
- [pwn/screenwriter](#pwnscreenwriter)
- [game/world 1](#gameworld-1)
- [game/world 2](#gameworld-2)
- [rev/stones](#revstones)
- [rev/sudoku](#revsudoku)

## Pwn/Screenwriter

Challenge Description : Use our software to craft your next blockbuster hit!

<details>
<summary>Source Code</summary>

```c
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void init(){
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    return;
}

void menu(){
    puts("1. Set screenwriter name");
    puts("2. Write script");
    puts("3. View reference");
    puts("4. Exit");
}

int get_choice(){
    char tmp[5] = "";
    printf("Choice: ");
    fgets(tmp,4,stdin);
    return atoi(tmp);
}

void main(){
    init();
    char* name = malloc(0x28);
    FILE *ref_script = fopen("bee-movie.txt","r");
    FILE *own_script = fopen("script.txt","w");
    puts("Welcome to our latest screenwriting program!");
    
    while (true){
        int choice = 0;
        menu();

        switch (get_choice()) {
            case 1:
                printf("What's your name: ");
                read(0,name,0x280);
                break;        

            case 2:
                char own_buf[0x101] = "";
                printf("Your masterpiece: ");
                read(0,own_buf,0x100);
                fwrite(own_buf,1,0x100,own_script);
                break;

            case 3:
                char ref_buf[0x11] = "";
                memset(ref_buf,0,0x11);
                fread(ref_buf,1,0x10,ref_script);
                puts("From the reference:");
                puts(ref_buf);
                break;

            default:
                printf("Goodbye %s",name);
                exit(0);
        }
    }
}
```

</details>

## Game/World 1

## Game/World 2

## Rev/Stones

## Rev/Sudoku
