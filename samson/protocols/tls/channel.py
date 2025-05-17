from samson.core.base_object import BaseObject

class Channel(BaseObject):
    def __init__(self, recv_callback: 'function'):
        self.recv_callback = recv_callback

    def send(self, msg_bytes: bytes):
        pass
