import Crypto
from Crypto import Random
def p_hash(secret,seed,x):
	h = Crypto.Hash.SHA256.new(seed)
	cnt = h.digest_size
	ans = h.digest()
	while cnt<x:
		cnt = cnt + 32
		h.update(secret)
		ans += h.digest()
		h = Crypto.Hash.SHA256.new((h.digest()+seed))
	return ans
def PRF(x,y,z):
	p_hash(x,y+z,96)
x = Random.get_random_bytes(40)
y = Random.get_random_bytes(28)
z = Random.get_random_bytes(28)
print p_hash(bytearray("Hello"),bytearray("World"),96)
print len(p_hash(bytearray("Hello"),bytearray("World"),96))