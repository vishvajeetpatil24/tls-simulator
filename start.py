'''
This will denote the start of the simulation program.
Various settings for simulation will be in this.
Single server simulation with multiple clients
'''
#Imports and libraries
import socket
import OpenSSL
import threading
import modeA
import modeB
import modeC
import sys
from mymodule import client_state

#Modes of Simulation
print("Available modes of simulation.")
print("1.Cipher performance comparison\t\t2.Average Cipher performance\t\t3.Handshake simulation")
mode = int(raw_input("Please select the mode from above using the number preceeding the mode.(1/2/3)\n"))
#Various parameters which are needed
if mode == 1:
	modeA.init()
	sys.exit(0)
elif mode == 2:
	modeB.init()
	sys.exit(0)
elif mode == 3:
	modeC.init()
	sys.exit(0)

con_num = int(raw_input("Enter the number of connections.\n"))
if con_num>100:
	print "It is advised that you should use randomized mode of simulation.\n"
random_mode = True
random_mode = False if raw_input("Wanna use random connection parameters? Yes/No\n") == "No" else True
attack_demo = False
attack_demo = True if raw_input("Wanna simulate attacks on TLS? Yes/No\n") == "Yes" else False
state_arr = []
if random_mode == False:
	print "Following are the supported ciphers.To choose any one of them use the number to left of them."
	for i in range(0,len(client_state.cipher_list)):
		print str(i) + " " + client_state.cipher_list[i]

for i in range(1,con_num+1):
	if random_mode == True:
		state_arr.append(client_state(1,-1))
	else:
		x = int(raw_input("Select cipher for "+str(i)+"th client")) 
		state_arr.append(client_state(0,x))
def starttls(i):
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
	sock = OpenSSL.SSL.Connection(cntxt,rootsock)
	#print sock.get_cipher_list()
	sock.set_connect_state()
	sock.do_handshake()
class tlsclient(threading.Thread):
	def __init__(self,x):
		threading.Thread.__init__(self)
		self.i = x
	def run(self):
		starttls(self.i)
for i in range(1,con_num+1):
	if con_num<1000:
		tlsclient(i).start()
	else:
		starttls(i)