from samson.utilities.bytes import Bytes
from samson.core.primitives import  BlockCipher, Primitive, ConstructionType
from samson.core.metadata import SizeType, SizeSpec
from samson.ace.decorators import register_primitive
from samson.utilities.manipulation import left_rotate, right_rotate

BLOCK_SIZE_KEY_SIZE_MAP = {
    32: (64,),
    48: (72, 96),
    64: (96, 128),
    96: (96, 144),
    128: (128, 192, 256)
}

BLOCK_KEY_SIZE_ROUNDS_MAP = {
    (32, 64): 22,
    (48, 72): 22,
    (48, 96): 23,
    (64, 96): 26,
    (64, 128): 27,
    (96, 96): 28,
    (96, 144): 29,
    (128, 128): 32,
    (128, 192): 33,
    (128, 256): 34
}

BLOCK_KEY_SIZE_KEYWORDS_MAP = {
    (32, 64): 4,
    (48, 72): 3,
    (48, 96): 4,
    (64, 96): 3,
    (64, 128): 4,
    (96, 96): 2,
    (96, 144): 3,
    (128, 128): 2,
    (128, 192): 3,
    (128, 256): 4
}


@register_primitive()
class Speck(BlockCipher):
    """
    References:
        https://eprint.iacr.org/2013/404.pdf
        https://en.wikipedia.org/wiki/Speck_(cipher)
        https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=da7a0ab5b4babbe5d7a46f852582be06a00a28f0
    """

    KEY_SIZE           = SizeSpec(size_type=SizeType.RANGE, sizes=[64, 72, 96, 128, 144, 192, 256])
    BLOCK_SIZE         = SizeSpec(size_type=SizeType.RANGE, sizes=[32, 48, 64, 96, 128])
    CONSTRUCTION_TYPES = [ConstructionType.FEISTEL_NETWORK]
    ENDIANNESS         = 'little'


    def __init__(self, key: bytes, block_size: int):
        Primitive.__init__(self)
        key = self._ensure_endianness(key)

        if len(key)*8 not in BLOCK_SIZE_KEY_SIZE_MAP[block_size]:
            raise ValueError(f"Key ({len(key)*8} bits) is incorrect size for blocksize {block_size}")

        self.key        = key
        self.bs_bits    = block_size
        self.rounds     = BLOCK_KEY_SIZE_ROUNDS_MAP[(block_size, len(key)*8)]
        self.alpha, self.beta = (7,2) if self.bs_bits == 32 else (8,3)
        self.keywords   = BLOCK_KEY_SIZE_KEYWORDS_MAP[(block_size, len(key)*8,)]
        self.round_keys = [None]*self.rounds
        self.mask       = 2**(self.bs_bits // 2)-1

        self.key_schedule()


    @property
    def block_size(self):
        return self.bs_bits // 8



    def key_schedule(self):
        keys = self.key.chunk(len(self.key) // self.keywords)
        l    = [k.int() for k in keys[1:]]
        k    = keys[0].int()

        for i in range(self.rounds):
            self.round_keys[i] = k
            l[i % (self.keywords-1)], k = self.forward_round(l[i % (self.keywords-1)], k, i)



    def forward_round(self, x, y, k):
        x  = right_rotate(x, self.alpha, self.bs_bits // 2)
        x += y
        x &= self.mask
        x ^= k
        y  = left_rotate(y, self.beta, self.bs_bits // 2)
        y ^= x
        return x, y


    def backwards_round(self, x, y, k):
        y ^= x
        y  = right_rotate(y, self.beta, self.bs_bits // 2)
        x ^= k
        x -= y
        x &= self.mask
        x  = left_rotate(x, self.alpha, self.bs_bits // 2)
        return x, y



    def encrypt(self, plaintext: bytes) -> bytes:
        plaintext = self._ensure_endianness(plaintext).zfill(self.bs_bits // 8)
        y,x = [chunk.int() for chunk in plaintext.chunk(self.bs_bits // 16)]

        for k in self.round_keys:
            x,y = self.forward_round(x, y, k)


        return Bytes(y, 'little').zfill(self.bs_bits // 16) + Bytes(x, 'little').zfill(self.bs_bits // 16)



    def decrypt(self, ciphertext: bytes) -> bytes:
        ciphertext = self._ensure_endianness(ciphertext).zfill(self.bs_bits // 8)
        y,x = [chunk.int() for chunk in ciphertext.chunk(self.bs_bits // 16)]

        for k in self.round_keys[::-1]:
            x,y = self.backwards_round(x, y, k)


        return Bytes(y, 'little').zfill(self.bs_bits // 16) + Bytes(x, 'little').zfill(self.bs_bits // 16)
