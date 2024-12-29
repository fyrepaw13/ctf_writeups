# WGMY2024

## Table of Contents
- [pwn/screenwriter](#pwnscreenwriter)
- [game/world 1](#gameworld-1)
- [game/world 2](#gameworld-2)
- [rev/stones](#revstones)
- [rev/sudoku](#revsudoku)

## Pwn/Screenwriter

Challenge Description : Use our software to craft your next blockbuster hit!

Challenge Summary : This challenge involves overwriting the FILE struct to gain arbitrary read and write

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

Looking at the source code, we can see an obvious buffer overflow in option 1 which lets us overwrite data in the heap. However, it is not immediately clear what we are suppose to overwrite.

![image](https://github.com/user-attachments/assets/34f34683-5893-4583-8a32-cc9c67c230cc)

Looking at it in gdb, we can see our name chunk with size 0x31 at the top. After that, theres another chunk with size 0x1e1 followed by the value 0xfbad2488. When I saw this value, FSOP immediately came to mind. What is a FILE struct? Lets let @Ren explain 

![image](https://github.com/user-attachments/assets/9614f272-4910-4799-9d79-8f3a70ec1e0d)

You can take a look at the definition in [elixir bootlin](https://elixir.bootlin.com/linux/v6.12.6/source)

<details>
<summary>FILE Struct</summary>

```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};
```

</details>

--------

The FILE Struct contains many fields which manage buffering.

![image](https://github.com/user-attachments/assets/03c4a9dd-ef7a-4ef6-a6df-42a5cf45204f)

After using option 3, we can see that the struct is now populated with values.

![image](https://github.com/user-attachments/assets/d9123403-d0ad-450e-b409-864d182c755a)

The contents of the bee script is read into 0x405690 which corresponds to the values in the struct above.

## Game/World 1

## Game/World 2

## Rev/Stones

## Rev/Sudoku
