from samson.hashes.sha2 import SHA256
from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject

class Transformation(BaseObject):
    def transform(self, key: bytes) -> bytes:
        raise NotImplementedError
    
    def decrypt(self, key: bytes):
        raise NotImplementedError


class RSA_OAEP_ECB(Transformation):
    def __init__(self, keypair: 'RSA', hash_obj=None) -> None:
        self.keypair  = keypair
        self.hash_obj = hash_obj or SHA256()
    

    def _create_oaep(self):
        from samson.padding.oaep import OAEP
        return OAEP(self.keypair.n.bit_length(), hash_obj=self.hash_obj)


    def transform(self, key: bytes):
        return Bytes(self.keypair.encrypt(self._create_oaep().pad(key)))


    def decrypt(self, key: bytes):
        oaep = self._create_oaep()(self.keypair.n.bit_length(), hash_obj=self.hash_obj)
        return Bytes(oaep.unpad(self.keypair.decrypt(key)))
