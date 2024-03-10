For this challenge, we were given a Simduino board connected to a joystick module and LCD display.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/9307cd28-311b-47a8-89b5-b0f1403f4899)

We were also given this

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/a8045054-9f60-471b-bfb6-dfb9b32f59cd)

I was really confused at what the symbols meant but after playing around with the joystick, my teammate @solaris analyzed it and said that the U, R, D, L meant Up Right Down Left. Additionally,

```
1 - J P J T X
2 - 6 1 5 4 5
```

this could be the sequence of input to get the flag because there were 10 inputs and the LCD only displayed a maximum of 10 characters. After playing around more with the joystick, we realised there were kind of like 2 stages of input, which is why there is U1 and U2. To get the flag, we need to move from

```
1 2 1 2 1 2 1 2 1 2
```

So, we will first look at 1 and its first character is "J". In the table, "J" corresponds to Down.

Then, we will look at 2 and its first character is "6". In the table, "6" corresponds to Up

Then, we will go back to 1 and its next character is "P". In the table, "P" corresponds to Left

Then, we move to 2 and its next character is "1". In the table, "1" corresponds to Right

We kept doing this until all 10 characters were complete. However, the flag was a jumble of words that did not make sense. So, we turned the joystick in different directions because we dont know which position is considered "upright" when made by the creator. Eventually, we got the flag on one of it.

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/508543e8-ce80-4678-8736-0a19114377d2)

Note : The characters that are input to the screen has nothing to do with 

![image](https://github.com/fyrepaw13/ctf_writeups/assets/62428064/67b1ca73-2b7b-489a-9b92-41cfa825d4cf)

