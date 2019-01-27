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

## Disassembly
