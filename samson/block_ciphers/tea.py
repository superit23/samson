from samson.utilities.bytes import Bytes
from samson.core.primitives import  BlockCipher, Primitive, ConstructionType
from samson.core.metadata import SizeType, SizeSpec
from samson.ace.decorators import register_primitive

DELTA  = 0x9E3779B9
MASK32 = 2**32-1


@register_primitive()
class TEA(BlockCipher):
    """
    Reference:
        https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
    """

    KEY_SIZE           = SizeSpec(size_type=SizeType.SINGLE, sizes=128)
    BLOCK_SIZE         = SizeSpec(size_type=SizeType.SINGLE, sizes=64)
    CONSTRUCTION_TYPES = [ConstructionType.FEISTEL_NETWORK]


    def __init__(self, key: bytes):
        Primitive.__init__(self)
        self.key = Bytes.wrap(key).zfill(16)


    def encrypt(self, plaintext: bytes) -> bytes:
        k0, k1, k2, k3 = [r.int() for r in self.key.chunk(4)]
        v0, v1         = [r.int() for r in Bytes.wrap(plaintext).chunk(4)]

        d_sum = 0
        for _ in range(32):
            d_sum += DELTA
            v0    += ((v1<<4) + k0) ^ (v1 + d_sum) ^ ((v1>>5) + k1)
            v0    &= MASK32
            v1    += ((v0<<4) + k2) ^ (v0 + d_sum) ^ ((v0>>5) + k3)
            v1    &= MASK32
        
        return Bytes(v0).zfill(4) + Bytes(v1).zfill(4)



    def decrypt(self, ciphertext: bytes) -> bytes:
        k0, k1, k2, k3 = [r.int() for r in self.key.chunk(4)]
        v0, v1         = [r.int() for r in Bytes.wrap(ciphertext).chunk(4)]

        d_sum = 0xC6EF3720
        for _ in range(32):
            v1    -= ((v0<<4) + k2) ^ (v0 + d_sum) ^ ((v0>>5) + k3)
            v1    &= MASK32
            v0    -= ((v1<<4) + k0) ^ (v1 + d_sum) ^ ((v1>>5) + k1)
            v0    &= MASK32
            d_sum -= DELTA

        return Bytes(v0).zfill(4) + Bytes(v1).zfill(4)
