import random
class client_state:
	'''Module that defines the structure and parameters of SSL client'''
	cipher_list = ['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA384','ECDHE-RSA-AES256-SHA', 
	'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA256', 'DHE-RSA-AES256-SHA','DHE-RSA-CAMELLIA256-SHA',
	'AES256-GCM-SHA384', 'AES256-SHA256', 'AES256-SHA', 'CAMELLIA256-SHA', 
	'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-RSA-AES128-SHA','DHE-RSA-AES128-GCM-SHA256', 
	'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES128-SHA', 'DHE-RSA-SEED-SHA','DHE-RSA-CAMELLIA128-SHA',
	'AES128-GCM-SHA256', 'AES128-SHA256', 'AES128-SHA', 'SEED-SHA', 'CAMELLIA128-SHA','ECDHE-RSA-RC4-SHA',
	'RC4-SHA', 'RC4-MD5', 'ECDHE-RSA-DES-CBC3-SHA', 'EDH-RSA-DES-CBC3-SHA','DES-CBC3-SHA']
	def __init__(self,R = 0,Cipher = -1):
		if R == 1 or Cipher == -1:
			x = random.randint(0,len(client_state.cipher_list)-1)
			self.cur_cipher = self.synthcipher(x)
		else:
			self.cur_cipher = self.synthcipher(Cipher)
	def getcurcipher(self):
		return self.cur_cipher
	def synthcipher(self,x):
		return bytes(client_state.cipher_list[x])