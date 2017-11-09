'''
Author - Vishvajeet Subhash Patil
Cipher performance modelling and simulation
'''
import matplotlib.pyplot as plt; plt.rcdefaults()
import numpy as np
import matplotlib.pyplot as plt
import socket
import threading
import OpenSSL
import time
from mymodule import client_state
state_arr = []
yval = []
cnt = 0
def starttls(i,j):
	global state_arr
	#Socket connection with proxy
	rootsock = socket.socket()
	rootsock = socket.create_connection(("127.0.0.1",6001))
	#Context Writing
	cntxt = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
	cntxt.use_certificate_file("cert.pem")
	cntxt.use_privatekey_file("privkey.pem")
	cntxt.use_certificate_chain_file("cacert.pem")
	cntxt.load_tmp_dh("dhparams.pem")
	cntxt.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve("prime256v1"))
	cntxt.set_cipher_list(state_arr[i-1].getcurcipher())
	if cmpr == False:
		cntxt.set_options(OpenSSL.SSL.OP_NO_COMPRESSION)
	sock = OpenSSL.SSL.Connection(cntxt,rootsock)
	#print sock.get_cipher_list()
	sock.set_connect_state()
	sock.do_handshake()
	if j==True:
		for m in range(1,msg_cnt):
			sock.send(buf="Hello World")
	global cnt
	cnt = cnt+1
class tlsclient(threading.Thread):
	def __init__(self,x,H):
		threading.Thread.__init__(self)
		self.i = x
		self.H = H
	def run(self):
		starttls(self.i,self.H)
def calculator(x,H):
	global state_arr
	global cnt
	state_arr = []
	for i in range(1,con_num+1): 
		state_arr.append(client_state(0,x))
	start_time = time.time()
	for i in range(1,con_num+1):
		tlsclient(i,H).run()
	while cnt!=con_num:
		continue
	cnt = 0
	return (time.time() - start_time)
def start():
	global state_arr
	global yval
	if con_num<131 and msg_cnt<1001:
		objects = []
		for j in range(0,len(client_state.cipher_list)):
			yval.append(calculator(j,False))
			objects.append(str(j))
		objects = tuple(objects)
		y_pos = np.arange(len(objects))
		plt.bar(y_pos, yval, align='center', alpha=0.5)
		plt.xticks(y_pos, objects)
		plt.ylabel('Timing')
		plt.title('Cipher Handshake Performance Calculated')
		plt.show()
		state_arr = []
		objects = []
		yval = []
		for j in range(0,len(client_state.cipher_list)):
			yval.append(calculator(j,True))
			objects.append(str(j))
		objects = tuple(objects)
		y_pos = np.arange(len(objects))
		plt.bar(y_pos, yval, align='center', alpha=0.5)
		plt.xticks(y_pos, objects)
		plt.ylabel('Timing')
		plt.title('Cipher Response Performance Calculated')
		plt.show()
def init():
	global con_num
	global msg_cnt
	global cmpr
	con_num = int(raw_input("Enter the number of connections whose expected performance you wanna guess.Less than 131 for accurate results.\n"))
	msg_cnt = int(raw_input("Enter the number of messages to be simulated by each connection after handshake.Less than 1001 for accurate results\n"))
	cmpr = False
	cmpr = True if raw_input("Enable Compression?(Y/N)") == "Y" else False
	print "Following are the supported ciphers.To choose any one of them use the number to left of them."
	for i in range(0,len(client_state.cipher_list)):
		print str(i) + " " + client_state.cipher_list[i]
	start()
