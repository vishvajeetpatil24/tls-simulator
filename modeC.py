'''
Author - Vishvajeet Patil
Module 3 : Manual handshake and message transmission simulation
Note - Since this is just the simulation the protocol implementation will be minimal
We will be simulating only one cipher of a kind
'''
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Cipher
from Crypto import Random
from base64 import b64decode,b64encode
import sys
import time
import socket
import SocketServer
import os
import OpenSSL
global mac_size
global aes_size
global iv_size
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
def PRF(x,y,z,m):
	return p_hash(x,y+z,m)
class demosecure(SocketServer.BaseRequestHandler):
	def handle(self):
		sock = server_side(self.request)
		while True:
			try:
				x = self.request.recv(500)
				if x == "":
					continue
				else:
					#print list(map(ord,x))
					sock.process_msg(x)
			except:
				return
		return
def initserver():
	x = os.fork()
	if x==0:
		demoloc = ("127.0.0.1",7000)
		SocketServer.TCPServer.allow_reuse_address = True
		demossl = SocketServer.TCPServer(demoloc,demosecure)
		demossl.serve_forever()
	else:
		time.sleep(2)
class client_side():
	def __init__(self):
		self.src = socket.socket()
		self.src.connect(("127.0.0.1",7000))
		self.state = 0
	def stchange(self,state):
		self.state = state
		print "Client state changed"
	def genclrandom(self):
		self.client_random = Random.get_random_bytes(28)
		return self.client_random
	def bytetolist(self,x):
		return list(map(ord,x))
	def process_msg(self,x):
		raw_msg = list(map(ord,x))
		header = raw_msg[:2]
		if header[0] == 22:
			#the message must be server handshake message
			if self.state == 0:
				client_error(1)
			elif self.state == 1:
				self.masterfunc(raw_msg[2:])
				pass
			elif self.state == 2:
				#print "Client Error"
				self.printdata()
				self.stchange(4)
				pass
			elif self.state == 4:
				client_error(2)
		elif header[0] == 23:
			#the message must be application data
			pass
	def printdata(self):
		print "Client Side" +"-"*75
		print "The final configuration of SSL is as follows."
		print "CL MAC write\t\t" + str(self.clmac)
		print "SE MAC write\t\t" + str(self.semac)
		print "CL ENC write\t\t" + str(self.clenc)
		print "SE ENC write\t\t" + str(self.seenc)
		print "CL IV write\t\t"  + str(self.cliv)
		print "SE IV write\t\t"  + str(self.seiv)
	def start_handshake(self):
		header = [22, 3]
		header.extend(self.bytetolist(self.genclrandom()))
		self.src.send(bytearray(header))
		self.stchange(1)
		certinfo = self.src.recv(2000)
		self.process_msg(certinfo)
		work_done = self.src.recv(1000)
		self.process_msg(work_done)
	def finalcalc(self,A,B,C):
		total_size = 2*(aes_size+mac_size+iv_size)
		tmp = B+A
		key_material = PRF(C,"key expansion",tmp,total_size)
		self.clmac = key_material[:mac_size]
		self.semac = key_material[mac_size:mac_size*2]
		self.clenc = key_material[mac_size*2:aes_size+mac_size*2]
		self.seenc = key_material[aes_size+mac_size*2:2*aes_size+mac_size*2]
		self.cliv = key_material[2*aes_size+mac_size*2:2*aes_size+mac_size*2+iv_size]
		self.seiv = key_material[2*aes_size+mac_size*2+iv_size:2*aes_size+mac_size*2+2*iv_size]
	def masterfunc(self,msg):
		self.server_random = bytes(bytearray(msg[:28]))
		certbuff = msg[28:]
		self.servercert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,str(bytearray(certbuff)))
		self.serverpkey = (self.servercert).get_pubkey()
		self.mastersecret = Random.get_random_bytes(40)
		#self.mastersecret = bytes("Hello world")
		self.serverpkey = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM,self.serverpkey)
		tmp_pem = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_PEM,self.serverpkey)
		tmp_der = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1,tmp_pem)
		keyPub = RSA.importKey(tmp_der)
		cipher = PKCS1_OAEP.new(keyPub)
		cipher_text = cipher.encrypt(self.mastersecret)
		#print len(cipher_text)
		#print cipher_text
		#print list(map(ord,cipher_text))
		#print self.mastersecret
		#print cipher_text
		header = [22, 3]
		header.extend(self.bytetolist(bytes(cipher_text)))
		self.src.send(bytearray(header))
		#print self.client_random
		#print self.server_random
		#print self.mastersecret
		self.finalcalc(self.client_random,self.server_random,self.mastersecret)
		#print "Calculation done"
		self.stchange(2)

class server_side():
	def __init__(self,x):
		self.src = x
		self.state = 0
	def stchange(self,state):
		self.state = state
		print "Server state changed"
	def gensrrandom(self):
		self.server_random = Random.get_random_bytes(28)
		return self.server_random
	def bytetolist(self,x):
		return list(map(ord,x))
	def process_msg(self,x):
		raw_msg = list(map(ord,x))
		header = raw_msg[:2]
		if header[0] == 22:
			if self.state == 0:
				#self.stchange(1)
				self.client_random = bytes(bytearray(raw_msg[2:]))
				self.respond_hello()
			elif self.state == 1:
				self.genkeymaterial(raw_msg[2:])
				#self.senddone()
				self.printdata()
				self.stchange(4)
			else:
				server_error()
	def printdata(self):
		print "Server Side" +"-"*75
		print "The final configuration of SSL is as follows."
		print "CL MAC write\t\t" + str(self.clmac)
		print "SE MAC write\t\t" + str(self.semac)
		print "CL ENC write\t\t" + str(self.clenc)
		print "SE ENC write\t\t" + str(self.seenc)
		print "CL IV write\t\t"  + str(self.cliv)
		print "SE IV write\t\t"  + str(self.seiv)
	def finalcalc(self,A,B,C):
		total_size = 2*(aes_size+mac_size+iv_size)
		tmp = B+A
		key_material = PRF(C,"key expansion",tmp,total_size)
		self.clmac = key_material[:mac_size]
		self.semac = key_material[mac_size:mac_size*2]
		self.clenc = key_material[mac_size*2:aes_size+mac_size*2]
		self.seenc = key_material[aes_size+mac_size*2:2*aes_size+mac_size*2]
		self.cliv = key_material[2*aes_size+mac_size*2:2*aes_size+mac_size*2+iv_size]
		self.seiv = key_material[2*aes_size+mac_size*2+iv_size:2*aes_size+mac_size*2+2*iv_size]
	def genkeymaterial(self,x):
		#print x
		x = bytes(bytearray(x))
		file = open("./privkey.pem","r")
		buf = file.read()
		tmp_pem = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM,buf)
		tmp_der = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1,tmp_pem)
		keypriv = RSA.importKey(tmp_der)
		#print keypriv
		cipher = PKCS1_OAEP.new(keypriv)
		#cipher_text = cipher.encrypt(bytes("msg"))
		self.mastersecret = cipher.decrypt(x)
		#generate key material
		#print self.client_random
		#print self.server_random
		#print self.mastersecret
		self.finalcalc(self.client_random,self.server_random,self.mastersecret)
		#print "Hello Server side done"
		header = [22, 3, 50,50,50,50,50,50]
		self.src.send(bytearray(header))

	def respond_hello(self):
		header = [22, 3]
		file = open("./cert.pem","r")
		buf = file.read()
		header.extend(self.bytetolist(self.gensrrandom()+bytes(buf)))
		self.src.send(bytearray(header))
		self.stchange(1)	
class client_error(Exception):
	def __init__(self,x):
		if x==1:
			print "Client is uninitialized.Fatal exception."
			sys.exit(1)
		elif x==2:
			print "Handshake is already done and for simulation purposes this is fatal error."
			sys.exit(1)
class server_error(Exception):
	def __init__(self):
		print "Error occured on server side. Wrong state message received. Abort"
		sys.exit(1)
def init():
	global aes_size
	global mac_size
	global iv_size
	print "Input following parameters."
	print "1.AES block size "
	aes_size = int(raw_input())
	print "2.MAC size "
	mac_size = int(raw_input())
	print "3.IV size "
	iv_size = int(raw_input())
	initserver()
	x = client_side()
	x.start_handshake()