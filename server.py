'''
This is the server for the TLS simulation. We will keep this server static and one which supports all possible configurations.
'''
import SocketServer
import socket
import OpenSSL
from OpenSSL import crypto
from OpenSSL import SSL

cntxt = SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)
cntxt.use_certificate_file("cert.pem")
cntxt.use_privatekey_file("privkey.pem")
cntxt.load_client_ca("cacert.pem")
cntxt.load_tmp_dh("dhparams.pem")
cntxt.set_tmp_ecdh(OpenSSL.crypto.get_elliptic_curve("prime256v1"))
class securessl(SocketServer.BaseRequestHandler):
	def handle(self):
		ssl_conn = SSL.Connection(cntxt,self.request)
		ssl_conn.set_accept_state()
		ssl_conn.do_handshake()
		while True:
			try:
				x = ssl_conn.recv(bufsiz = 100)
				if x == "":
					return
			except:
				return
		return

ssl_serverloc = ("127.0.0.1",6000)
SocketServer.TCPServer.allow_reuse_address = True
ssl_server = SocketServer.TCPServer(ssl_serverloc,securessl)
ssl_server.serve_forever()