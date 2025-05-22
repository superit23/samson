from samson.core.base_object import BaseObject
from samson.core.primitives import Hash
from samson.protocols.tls.messages import S1
from samson.kdfs.hkdf import HKDF


# struct {
#     uint16 length = Length;
#     opaque label<7..255> = "tls13 " + Label;
#     opaque context<0..255> = Context;
# } HkdfLabel;

class HkdfLabel(S1):
    length: S1.UInt16
    label: S1.Bytes
    context: S1.Bytes


class Ciphersuite(BaseObject):
    def __init__(self, cipher_cls, hash_obj: Hash):
        self.cipher_cls = cipher_cls
        self.hash_obj   = hash_obj
        self.length     = len(self.hash_obj.hash(b''))

        self.hkdf = HKDF(self.hash_obj, self.length)


    def hkdf_expand_label(self, secret: bytes, label: bytes, context: bytes, length: int):
        label = HkdfLabel(
            length=length,
            label=b'tls13 ' + label,
            context=context
        )
        hkdf = HKDF(self.hash_obj, length)
        return hkdf.expand(secret, label.serialize(), length)


    def derive_secret(self, secret: bytes, label: bytes, transcript_hash: bytes):
        return self.hkdf_expand_label(secret, label, transcript_hash, self.length)


    def encrypt(self, key, nonce, data, aad):
        cipher = self.cipher_cls(key)
        return cipher.encrypt(nonce, data, aad)

    def decrypt(self, key, nonce, data, aad, verify=True):
        cipher = self.cipher_cls(key)
        return cipher.decrypt(nonce, data, aad, verify)
