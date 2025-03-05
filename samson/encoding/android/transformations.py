from samson.padding.oaep import OAEP
from samson.hashes.sha2 import SHA256
from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject

class Transformation(BaseObject):
    def transform(self, key: bytes) -> bytes:
        raise NotImplementedError


class RSA_OAEP_ECB(Transformation):
    def __init__(self, keypair: 'RSA', hash_obj=None) -> None:
        self.keypair  = keypair
        self.hash_obj = hash_obj or SHA256()

    def transform(self, key: bytes):
        oaep = OAEP(self.keypair.n.bit_length(), hash_obj=self.hash_obj)
        return Bytes(self.keypair.encrypt(oaep.pad(key)))
