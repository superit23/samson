from samson.core.primitives import BlockCipher
from samson.hashes.sha2 import SHA256
from samson.utilities.bytes import Bytes
from samson.constructions.feistel_network import FeistelNetwork
from samson.macs.hmac import HMAC
from samson.kdfs.hkdf import HKDF
import math

def build_dinglebob(SIZE, HASH=None, ROUNDS=16, SUBKEY_SIZE=512):
    assert not SIZE % 2

    SIZE_HALF     = SIZE // 2
    MASK          = 2**SIZE_HALF - 1
    SIZE_BYTES    = math.ceil(SIZE/8)
    INTERNAL_HALF = math.ceil(SIZE_BYTES/2)
    HASH          = HASH or SHA256()


    def cut_to_bitsize(b, size):
        modulus = 2**size
        q = b
        results = []

        while q:
            q, r = divmod(q, modulus)
            results.append(r)

        return results[::-1]


    def to_feistel_native(b):
        return Bytes.wrap(b''.join([Bytes(r).zfill(INTERNAL_HALF) for r in cut_to_bitsize(b.int(), SIZE_HALF)])).zfill(math.ceil(SIZE / 16)*2)


    def from_feistel_native(b):
        half = len(b) // 2
        return Bytes(b[:half].int() * 2**SIZE_HALF + b[half:].int())



    def round_func(state, subkey):
        return HMAC(subkey, HASH).generate(state)[:INTERNAL_HALF] & MASK


    def key_schedule(key):
        keys = HKDF(HASH, (SUBKEY_SIZE*ROUNDS) // 8).derive(key, salt=f'{SIZE}-bit cipher'.encode('utf-8')).int()
        n    = keys.bit_length()

        for i in range(n // SUBKEY_SIZE):
            yield (keys >> SUBKEY_SIZE*i) % 2**SUBKEY_SIZE


    def generate_whiteners(key):
        w_keys = HMAC(key, HASH).generate(Bytes().zfill(16))[:SIZE_BYTES*2]
        w_keys = [Bytes(w).zfill(SIZE_BYTES) for w in cut_to_bitsize(w_keys.int(), SIZE)][:2]
        
        # Possible if w0 or both are all zeros
        if len(w_keys) < 2:
            w_keys = [Bytes().zfill(SIZE_BYTES)] * (2-len(w_keys)) + w_keys
        return w_keys


    class DINGLEBOB(BlockCipher):
        BLOCK_SIZE = SIZE // 8

        def __init__(self, key):
            self.key         = key
            self.network     = FeistelNetwork(round_func, key_schedule)
            self.block_size  = self.BLOCK_SIZE
            self.w0, self.w1 = generate_whiteners(key)


        def encrypt(self, plaintext):
            plaintext  = to_feistel_native(Bytes.wrap(plaintext) ^ self.w0)
            ciphertext = self.network.encrypt(self.key, plaintext)
            return from_feistel_native(ciphertext) ^ self.w1


        def decrypt(self, ciphertext):
            ciphertext = to_feistel_native(Bytes.wrap(ciphertext) ^ self.w1)
            plaintext  = self.network.decrypt(self.key, ciphertext)
            return from_feistel_native(plaintext) ^ self.w0

    return DINGLEBOB
