import hashlib

in_first = "4634"
out_first = "2767"

target_hash = "CAE671D3486F4F4674401508BCDB9232"

max_guess = 99999999
for middle_guess in reversed(xrange(max_guess)):
	guess = in_first + str(middle_guess).zfill(8) + out_first
	found_hash = hashlib.md5(guess).hexdigest().upper()

	if middle_guess % 10000 == 0:
		print guess
	
	if target_hash == found_hash:
		print "Found it: " + guess
		break
