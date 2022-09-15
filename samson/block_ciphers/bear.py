from types import FunctionType
from samson.utilities.bytes import Bytes
from samson.core.primitives import MAC, BlockCipher, Primitive, StreamCipher
from samson.core.metadata import SizeType, SizeSpec
from samson.ace.decorators import register_primitive
import math


# https://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
@register_primitive()
class BEAR(BlockCipher):
    """
    """

    # KEY_SIZE   = SizeSpec(size_type=SizeType.RANGE, sizes=range(0, 2041))
    # BLOCK_SIZE = SizeSpec(size_type=SizeType.RANGE, sizes=[32, 64, 128])

    def __init__(self, key: bytes, hash_obj: MAC, stream_cipher: StreamCipher, key_schedule: FunctionType, block_size: int=128):
        Primitive.__init__(self)
        self.key = key
        self.H   = hash_obj
        self.S   = stream_cipher
        self.block_size = block_size
        self.key_schedule = key_schedule

        self.K1, self.K2 = self.key_schedule(self.key)
        self.k = len(self.H(b'\x00').generate(b'\x00')) 
    


    def encrypt(self, plaintext: bytes) -> bytes:
        Ls = self.k // 8
        Rs = max((self.block_size - self.k) // 8, 0)

        L, R = plaintext[:Ls], plaintext[Ls:]
        L ^= self.H(self.K1).generate(R)
        R ^= self.S(L).generate(Rs)
        L ^= self.H(self.K2).generate(R)

        return L + R



    def decrypt(self, ciphertext: bytes) -> bytes:
        Ls = self.k // 8
        Rs = max((self.block_size - self.k) // 8, 0)

        L, R = ciphertext[:Ls], ciphertext[Ls:]
        L ^= self.H(self.K2).generate(R)
        R ^= self.S(L).generate(Rs)
        L ^= self.H(self.K1).generate(R)

        return L + R
