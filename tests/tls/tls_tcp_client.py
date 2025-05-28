from samson.protocols.tls.channel import Channel
from samson.protocols.tls.tls_client import TLSHandshakeClientFSM, TLSConfiguration
from samson.protocols.tls.ciphersuite import Ciphersuite
from samson.protocols.tls.messages import *
import socket
import logging

logging.getLogger("samson").setLevel(logging.DEBUG)

kex = ECDHE(G=P256.G, d=35042064935119888273941612190705043299487775348963584978024758587526493285412)

def aes_gcm(key):
    rij = Rijndael(key)
    gcm = GCM(rij)
    return gcm


GOOGLE_IP = '142.250.189.196'
cs        = Ciphersuite(aes_gcm, SHA256())
config    = TLSConfiguration(kex, cs)
sock      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((GOOGLE_IP, 443))

class TCPChannel(Channel):
    def __init__(self, socket, fsm):
        self.socket = socket
        self.fsm    = fsm
        self.buffer = b''
        self.expected_len = 0

    def send(self, message):
        self.socket.send(bytes(message))


    def recv(self, buffer_size: int):
        self.buffer += self.socket.recv(buffer_size)
    
        left_over = self.buffer
        while left_over:
            if not self.expected_len:
                self.expected_len = TLSPlaintextHeader.deserialize(left_over)[1].length.val

            if len(left_over) > self.expected_len:
                left_over, record = TLSPlaintext.deserialize(left_over)
                self.fsm.reply_queue.put(record)
                self.expected_len = 0
            else:
                self.buffer = left_over
                break


fsm     = TLSHandshakeClientFSM(config, None)
channel = TCPChannel(sock, fsm)
fsm.channel = channel
fsm.start()


while True:
    channel.recv(8192)
    fsm.next()

