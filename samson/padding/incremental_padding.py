from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from samson.utilities.exceptions import InvalidPaddingException

class IncrementalPadding(BaseObject):
    """
    Incremental padding. Used in OpenSSH's keys.
    """

    def __init__(self, block_size: int=8, always_pad: bool=True):
        """
        Parameters:
            block_size  (int): Block size to pad to.
            always_pad (bool): Whether or not to always pad even if plaintext is congruent.
        """
        self.block_size = block_size
        self.always_pad = always_pad



    def pad(self, plaintext: bytes) -> Bytes:
        """
        Pads the plaintext.

        Parameters:
            plaintext (bytes): Plaintext to pad.

        Returns:
            Bytes: Padded plaintext.
        """
        if self.always_pad:
            padding = self.block_size - len(plaintext) % self.block_size
        else:
            padding = -len(plaintext) % self.block_size

        return plaintext + Bytes([_ for _ in range(1, padding + 1)])



    def unpad(self, plaintext: bytes) -> Bytes:
        """
        Unpads the plaintext.

        Parameters:
            plaintext (bytes): Plaintext to unpad.

        Returns:
            Bytes: Unpadded plaintext.
        """
        if not self.always_pad and not len(plaintext) % self.block_size:
            return plaintext
        else:
            if plaintext[-1] <= self.block_size:
                raise InvalidPaddingException

            return plaintext[:-plaintext[-1]]
