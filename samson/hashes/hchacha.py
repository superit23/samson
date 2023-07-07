from samson.utilities.manipulation import left_rotate, get_blocks
from samson.utilities.bytes import Bytes
from samson.core.metadata import SizeType, SizeSpec, EphemeralSpec, EphemeralType, FrequencyType
from samson.core.primitives import Hash
from samson.ace.decorators import register_primitive
from samson.stream_ciphers.chacha import QUARTER_ROUND


@register_primitive()
class HChaCha(Hash):
    """
    ChaCha stream cipher

    Add-rotate-xor (ARX) structure.
    """

    USAGE_FREQUENCY = FrequencyType.NORMAL
    INPUT_SIZE      = SizeSpec(size_type=SizeType.SINGLE, sizes=384)
    OUTPUT_SIZE     = SizeSpec(size_type=SizeType.SINGLE, sizes=256)

    def __init__(self, rounds: int=20, constant: bytes=b"expand 32-byte k"):
        """
        Parameters:
            rounds     (int): Number of rounds to perform.
            constant (bytes): Constant used in generating the keystream (16 bytes).
        """
        self.rounds   = rounds
        self.constant = constant


    def hash(self, message: bytes) -> Bytes:
        """
        Hash `message` with HChaCha. First 32 bytes are the key, and the second 16 are the nonce.

        Parameters:
            message (bytes): Message to be hashed.

        Returns:
            Bytes: HChaCha hash.
        """
        x = [
            *[int.from_bytes(block, 'little') for block in get_blocks(self.constant, 4)],
            *[int.from_bytes(block, 'little') for block in get_blocks(message, 4)],
        ]

        for _ in range(self.rounds // 2):
            # Odd round
            x[0], x[4], x[ 8], x[12] = QUARTER_ROUND(x[0], x[4], x[ 8], x[12])
            x[1], x[5], x[ 9], x[13] = QUARTER_ROUND(x[1], x[5], x[ 9], x[13])
            x[2], x[6], x[10], x[14] = QUARTER_ROUND(x[2], x[6], x[10], x[14])
            x[3], x[7], x[11], x[15] = QUARTER_ROUND(x[3], x[7], x[11], x[15])

            # Even round
            x[0], x[5], x[10], x[15] = QUARTER_ROUND(x[0], x[5], x[10], x[15])
            x[1], x[6], x[11], x[12] = QUARTER_ROUND(x[1], x[6], x[11], x[12])
            x[2], x[7], x[ 8], x[13] = QUARTER_ROUND(x[2], x[7], x[ 8], x[13])
            x[3], x[4], x[ 9], x[14] = QUARTER_ROUND(x[3], x[4], x[ 9], x[14])

        output = Bytes(b''.join([int.to_bytes(state_int & 0xFFFFFFFF, 4, 'little') for state_int in x]), byteorder='little')
        return output[:16] + output[-16:]
