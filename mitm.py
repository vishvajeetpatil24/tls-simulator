import socket
import SocketServer
import select
import struct
import binascii
class mitmserver(SocketServer.BaseRequestHandler):
    def handle(self):
        count = 0
        destination = socket.create_connection(("127.0.0.1",6000))
        sockets = [self.request,destination]
        while True:
            inp, out, exce = select.select(sockets,[],[])
            for s in inp:
                if s == self.request:
                    data = s.recv(1048576)
                    count +=1
                    if data == "":
                        print "-"*144
                        return
                    print "Going Content"
                    print list(map(ord,str(data)))
                    destination.send(data)
                elif s == destination:
                    data = s.recv(1048576)
                    if data == "":
                        print "-"*144
                        return
                    content,ver,length = struct.unpack('>BHH',data[:5])
                    print "Receiving Content"
                    print list(map(ord,str(data)))
                    self.request.send(data)
        return

ssl_serverloc = ("127.0.0.1",6001)
SocketServer.TCPServer.allow_reuse_address = True
ssl_server = SocketServer.TCPServer(ssl_serverloc,mitmserver)
ssl_server.serve_forever()