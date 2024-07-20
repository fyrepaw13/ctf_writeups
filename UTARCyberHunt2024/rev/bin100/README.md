Since we are given an exe file, I like to do it on my Windows VM with my RE tools

![image](https://github.com/user-attachments/assets/e350d7b4-c764-429e-bb22-2ccb797b494a)

Using Detect-It-Easy (DIE), we can see its a .Net binary. We will use [dnSpy](https://github.com/dnSpy/dnSpy) to decompile the .Net binary. Just download it through the releases.

![image](https://github.com/user-attachments/assets/8108b53e-d698-434d-a879-63f9d9b49007)

Looking at the main function, it looks like its just printing out one character of the flag randomly each time.

```
private static int getUltraSuperL33tWatchaNumber()
{
	return new Random().Next(1, 38);
}

private static int getSuperL33tNumber()
{
	return Program.random.Next(1, 38);
}
```

These are the 2 functions responsble for generating random numbers. The first function creates a new Random object while the second function assumes that there is a static Random object named "random" in the Program class:

![image](https://github.com/user-attachments/assets/5af1838e-32f5-415f-864d-7346aa56a8cc)

There are also 2 additional interesting things in the binary

![image](https://github.com/user-attachments/assets/1b93d98e-467b-4a9b-8a81-1bf3ff7dee24)

Theres a secret variable which presumably contains our encrypted flag characters.

![image](https://github.com/user-attachments/assets/c993ce7b-8a46-4039-9e98-1b0a3484a8f2)

A random object is created with the value of 123456.

![image](https://github.com/user-attachments/assets/9828bde7-0166-42e0-9be7-524e6018f904)

We can confirm this by looking at the code for Random which contains a constructor to initialize the seed value. So with all the information we have, we just let ChatGPT do all the hard work because I have skill issues lol.

First I copy and pasted the Random class into ChatGPT and asked it to convert to Java. Heres the output from ChatGPT

```java
import java.util.Arrays;

public class CustomRandom {
    private static final int MBIG = 2147483647;
    private static final int MSEED = 161803398;
    private static final int MZ = 0;

    private int inext;
    private int inextp;
    private int[] seedArray = new int[56];

    public CustomRandom(int seed) {
        int num = (seed == Integer.MIN_VALUE) ? Integer.MAX_VALUE : Math.abs(seed);
        int num2 = MSEED - num;
        this.seedArray[55] = num2;
        int num3 = 1;

        for (int i = 1; i < 55; i++) {
            int num4 = 21 * i % 55;
            this.seedArray[num4] = num3;
            num3 = num2 - num3;
            if (num3 < 0) {
                num3 += MBIG;
            }
            num2 = this.seedArray[num4];
        }

        for (int j = 1; j < 5; j++) {
            for (int k = 1; k < 56; k++) {
                this.seedArray[k] -= this.seedArray[1 + (k + 30) % 55];
                if (this.seedArray[k] < 0) {
                    this.seedArray[k] += MBIG;
                }
            }
        }

        this.inext = 0;
        this.inextp = 21;
    }

    private int internalSample() {
        int num = this.inext;
        int num2 = this.inextp;
        if (++num >= 56) {
            num = 1;
        }
        if (++num2 >= 56) {
            num2 = 1;
        }
        int num3 = this.seedArray[num] - this.seedArray[num2];
        if (num3 == MBIG) {
            num3--;
        }
        if (num3 < 0) {
            num3 += MBIG;
        }
        this.seedArray[num] = num3;
        this.inext = num;
        this.inextp = num2;
        return num3;
    }

    public int next() {
        return this.internalSample();
    }

    public int next(int minValue, int maxValue) {
        if (minValue > maxValue) {
            throw new IllegalArgumentException("minValue cannot be greater than maxValue.");
        }

        long range = (long)maxValue - minValue;
        if (range <= Integer.MAX_VALUE) {
            return (int) (this.internalSample() / (double) MBIG * range) + minValue;
        }

        throw new IllegalArgumentException("Range is too large.");
    }

    public double nextDouble() {
        return this.internalSample() / (double) MBIG;
    }

    public void nextBytes(byte[] buffer) {
        if (buffer == null) {
            throw new IllegalArgumentException("buffer cannot be null");
        }
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (this.internalSample() % 256);
        }
    }
}
```

Then, heres the main file

```java
import java.util.Arrays;

public class Main {
    // Define the secret array as a static field
    private static final byte[] SECRET = new byte[]{
            95, 80, 67, 92, 100, 32, 58, 56, 116, 40,
            103, 57, 37, 52, 47, 64, 127, 45, 35, 48,
            42, 99, 120, 71, 52, 104, 101, 99, 44, 118,
            108, 36, 71, 49, 19, 96, 120, 110
    };

    public static void main(String[] args) {
        // Initialize the custom random class with seed 123456
        CustomRandom random = new CustomRandom(123456);

        // Define the SECRET array
        byte[] SECRET = {
                95, 80, 67, 92, 100, 32, 58, 56, 116, 40,
                103, 57, 37, 52, 47, 64, 127, 45, 35, 48,
                42, 99, 120, 71, 52, 104, 101, 99, 44, 118,
                108, 36, 71, 49, 19, 96, 120, 110
        };

        // Create a key array of size 38
        int[] key = new int[38];

        // Populate the key array with random values between 1 and 37 (inclusive)
        for (int i = 0; i < key.length; i++) {
            key[i] = random.next(1, 38);
        }

        // Initialize a StringBuilder to accumulate characters
        StringBuilder result = new StringBuilder();

        // XOR each element of the SECRET array with corresponding element of the key array
        // Process up to the length of the SECRET array
        for (int i = 0; i < SECRET.length; i++) {
            // Ensure to wrap around if key array is longer than SECRET array
            int keyIndex = i % key.length;
            char x = (char) (SECRET[i] ^ key[keyIndex]);
            result.append(x);
        }

        // Print the resulting string
        System.out.println("Decrypted String: " + result.toString());
    }
}
```

![image](https://github.com/user-attachments/assets/4d73146d-cb29-44fd-9697-654206efc9ae)

:D
