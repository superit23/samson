from samson.core.base_object import BaseObject
from samson.utilities.bytes import Bytes
from samson.protocols.tls.messages import HandshakeType, Handshake, HELLO_RETRY_MAGIC


class Transcript(BaseObject):
    def __init__(self, hash_obj, messages: list=None):
        self.hash_obj = hash_obj
        self.messages = messages or []

    

    def append(self, message: Handshake):
        # Gives us more control/validation
        # TODO: Implement checks
        self.messages.append(message)


    def extend(self, messages: list):
        for msg in messages:
            self.append(msg)


    def calculate_retry_cookie_data(self):
        client_hello1 = self.messages[0]
        ch_hash       = self.hash_obj.hash(client_hello1.serialize())

        cookie = HandshakeType.message_hash.serialize() \
        + Bytes(len(ch_hash)).zfill(3) \
        + ch_hash

        return cookie


    def hash(self):
        # https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1

        if len(self.messages) > 1 and self.messages[1].msg_type == HandshakeType.server_hello and self.messages[1].message.val.val.random == HELLO_RETRY_MAGIC:
            to_hash = self.calculate_retry_cookie_data() + b''.join([msg.serialize() for msg in self.messages[1:]])
        else:
            to_hash = b''.join([msg.serialize() for msg in self.messages])
        
        return self.hash_obj.hash(to_hash)
