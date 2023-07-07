from samson.utilities.bytes import Bytes
from samson.stream_ciphers.salsa import Salsa
from samson.stream_ciphers.chacha import ChaCha
from samson.stream_ciphers.xchacha import XChaCha
from samson.core.metadata import SizeType, SizeSpec, EphemeralSpec, EphemeralType, FrequencyType
from samson.core.primitives import StreamCipher, Primitive, AuthenticatedCipher
from samson.ace.decorators import register_primitive
from samson.macs.poly1305 import Poly1305
from samson.utilities.runtime import RUNTIME

class StreamAEADPoly1305(AuthenticatedCipher, StreamCipher):
    CIPHER     = None
    STATE_SIZE = 64
    NONCE_SIZE = None

    def __init__(self, key: bytes):
        self.key = Bytes.wrap(key)
    

    def prepare_cipher(self, nonce):
        cc  = self.CIPHER(self.key, nonce)
        r,s = cc.full_round(0)[:32].chunk(16)
        cc.counter = self.STATE_SIZE

        return (r,s), cc


    def build_mac(self, aad, ciphertext, r, s):
        mac_data  = aad.pad_congruent_right(16)
        mac_data += ciphertext.pad_congruent_right(16)
        mac_data += Bytes(len(aad), 'little').zfill(8)
        mac_data += Bytes(len(ciphertext), 'little').zfill(8)

        poly1305 = Poly1305(r)
        print(poly1305)
        tag = poly1305.generate(mac_data.change_byteorder('little'), s)
        return tag


    def encrypt(self, plaintext, nonce, aad):
        aad, nonce, plaintext = Bytes.wrap(aad), Bytes.wrap(nonce), Bytes.wrap(plaintext)

        (r,s), cc = self.prepare_cipher(nonce)

        print("Poly (r,s)", r.hex(), s.hex())
        print("Keystream", cc.full_round(1).hex())
        ciphertext = cc.encrypt(plaintext)
        tag        = self.build_mac(aad, ciphertext, r, s)
        return nonce + ciphertext + tag


    def decrypt(self, ciphertext: bytes, aad):
        ciphertext = Bytes.wrap(ciphertext)
        nonce, encrypted, tag = ciphertext[:self.NONCE_SIZE], ciphertext[self.NONCE_SIZE:-16], ciphertext[-16:]

        (r,s), cc = self.prepare_cipher(nonce)

        generated_tag = self.build_mac(aad, encrypted, r, s)

        self.verify_tag(generated_tag, tag)
        
        return cc.decrypt(encrypted)



class ChaCha20Poly1305(StreamAEADPoly1305):
    CIPHER     = ChaCha
    NONCE_SIZE = 12


class XChaCha20Poly1305(StreamAEADPoly1305):
    CIPHER     = XChaCha
    NONCE_SIZE = 24
