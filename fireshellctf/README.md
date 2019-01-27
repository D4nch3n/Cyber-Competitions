# Casino (pwn)
Even though this had a low point value, this is definitely the hardest CTF binary exploitation challenge that I have solved in a long while...

## Problem Statement:

![alt text](imgs/problem_statement.PNG "Chall")

## Initial Analysis:
As always, with every binary exploitation problem, we begin by taking a look at the protections enabled on the binary:

![alt text](imgs/checksec.PNG "checksec")

What's noteworthy is that full-RELRO is enabled. Normally, this is disabled for performance reasons. Since full-RELRO makes the GOT-table read only, we can infer that one of the vulnerabilities could allow us to write to the GOT table, and so we need to find some other ways to exploit this program. Let's run this binary and see what happens:

![alt text](imgs/init.PNG "init")

Ok, there seems to be some number guessing going on (hence the name "casino"). Also, the first input that we gave to the program is echo'd out back to us. From experience, this might hint to us to try out format strings, which is confirmed below:

![alt text](imgs/fmt.PNG "fmt")

This also explains why full-RELRO is enabled on the binary. Now, time to look at the assembly code for in-depth analysis.

## Disassembly Analysis:

Below is the code for the random seed generation:

![alt text](imgs/seedgen.PNG "fmt")

and below is the code for the random numbers:

![alt text](imgs/randgen.PNG "fmt")

Basically, time() is called with a given parameter of 0, which returns the current epoch time in seconds. Frequently, this is enough to serve as a seed of rand(), however within this program it gets a bit more complex. The "mov edx, cccccccDh; mul edx" instructions multiplies the time by 0xcccccccd, the "shr eax, 3" instruction shifts the most significant 32 bits of eax from the multiplication result to the right by 3, and the "mov eax, cs:bet; add [rbp+seed], eax;" adds the final result by whatever is stored in the global variable bet. This is then finally saved as the seed for the srand() function. Although this looks complicated, we can emulate the seed generation by using the below python snippet:

```python
seed = int(time())
seed = seed * 0xcccccccd
seed = int(str(hex(seed))[:10], 16)
seed = seed >> 3
seed = seed + bet
```

The rest of main() generates 100 values based on the returned result of rand(). Using the same idea described in one of the challenge writeups in [TJCTF](https://medium.com/@mihailferaru2000/tjctf-2018-full-binary-exploitation-walk-through-a72a9870564e), we can generate 100 values using the rand() number generater by passing the seed as a command line parameter below:

```C
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    int seed = atoi(argv[1]);
    srand(seed);
    for(int i = 0; i < 100; i++) {
        printf("%d\n", rand());
    }
    return 0;
}
```
Combine the output of the 100 numbers, and we should be good to go............
