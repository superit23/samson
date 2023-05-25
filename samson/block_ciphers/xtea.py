from samson.utilities.bytes import Bytes
from samson.core.primitives import  BlockCipher, Primitive, ConstructionType
from samson.core.metadata import SizeType, SizeSpec
from samson.ace.decorators import register_primitive

DELTA  = 0x9E3779B9
MASK32 = 2**32-1


@register_primitive()
class XTEA(BlockCipher):
    """
    Reference:
        https://en.wikipedia.org/wiki/XTEA
    """

    KEY_SIZE           = SizeSpec(size_type=SizeType.SINGLE, sizes=128)
    BLOCK_SIZE         = SizeSpec(size_type=SizeType.SINGLE, sizes=64)
    CONSTRUCTION_TYPES = [ConstructionType.FEISTEL_NETWORK]


    def __init__(self, key: bytes, rounds: int=32):
        Primitive.__init__(self)
        self.key    = Bytes.wrap(key).zfill(16)
        self.rounds = rounds


    def encrypt(self, plaintext: bytes) -> bytes:
        k      = [r.int() for r in self.key.chunk(4)]
        v0, v1 = [r.int() for r in Bytes.wrap(plaintext).chunk(4)]

        d_sum = 0
        for _ in range(self.rounds):
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (d_sum + k[d_sum & 3])
            v0    &= MASK32
            d_sum += DELTA
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (d_sum + k[(d_sum>>11) & 3])
            v1    &= MASK32
        
        return Bytes(v0).zfill(4) + Bytes(v1).zfill(4)



    def decrypt(self, ciphertext: bytes) -> bytes:
        k      = [r.int() for r in self.key.chunk(4)]
        v0, v1 = [r.int() for r in Bytes.wrap(ciphertext).chunk(4)]

        d_sum = DELTA*self.rounds
        for _ in range(self.rounds):
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (d_sum + k[(d_sum>>11) & 3])
            v1    &= MASK32
            d_sum -= DELTA
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (d_sum + k[d_sum & 3])
            v0    &= MASK32

        return Bytes(v0).zfill(4) + Bytes(v1).zfill(4)
