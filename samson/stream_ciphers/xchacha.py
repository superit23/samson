from samson.stream_ciphers.chacha import ChaCha
from samson.core.metadata import SizeType, SizeSpec, EphemeralSpec, EphemeralType, FrequencyType
from samson.ace.decorators import register_primitive
from samson.hashes.hchacha import HChaCha



@register_primitive()
class XChaCha(ChaCha):
    """
    XChaCha stream cipher

    Add-rotate-xor (ARX) structure.
    """

    EPHEMERAL = EphemeralSpec(ephemeral_type=EphemeralType.NONCE, size=SizeSpec(size_type=SizeType.SINGLE, sizes=192))


    def __init__(self, key: bytes, nonce: bytes, rounds: int=20, constant: bytes=b"expand 32-byte k"):
        """
        Parameters:
            key      (bytes): Key (128 or 256 bits).
            nonce    (bytes): Nonce (24 bytes).
            rounds     (int): Number of rounds to perform.
            constant (bytes): Constant used in generating the keystream (16 bytes).
        """
        super().__init__(key, nonce, rounds, constant)
        self.subkey = HChaCha().hash(self.key + self.nonce[:16])
        self.chacha = ChaCha(key=self.subkey, nonce=self.nonce[16:].zfill(12))


    

    def yield_state(self, start_chunk: int=0, num_chunks: int=1, state: list=None):
        """
        Generates `num_chunks` chunks of keystream starting from `start_chunk`.

        Parameters:
            num_chunks  (int): Desired number of 64-byte keystream chunks.
            start_chunk (int): Chunk number to start at.
            state      (list): Custom state to be directly injected.

        Returns:
            generator: Keystream chunks.
        """
        for iteration in range(start_chunk, start_chunk + num_chunks):
            yield self.chacha.full_round(iteration, state=state)
