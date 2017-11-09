from __future__ import print_function

from Crypto.PublicKey import RSA
from Crypto import Random

src_data = 'To be, or not to be - that is the question.'
print(repr(src_data))

random_generator = Random.new().read
key = RSA.generate(1024, random_generator)
pub_key = key.publickey()
print(type(pub_key))