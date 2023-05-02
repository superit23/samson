from samson.utilities.bytes import Bytes
from samson.core.base_object import BaseObject
from types import FunctionType

class EvenMansourScheme(BaseObject):
    """
    Block cipher construction built from a prewhitening key, unkeyed pseudorandom permutation, and postwhitening key.
    """

    def __init__(self, F0: FunctionType, F1: FunctionType, K1: bytes, K2: bytes=None):
        """
        Parameters:
            F0  (func): Unkeyed pseudorandom permutation (encrypt).
            F1  (func): Unkeyed pseudorandom permutation (decrypt).
            K1 (bytes): Bytes-like object to key the cipher.
            K2 (bytes): (Optional) Bytes-like object to key the cipher.
        """
        self.F0 = F0
        self.F1 = F1
        self.K1 = Bytes.wrap(K1)
        self.K2 = Bytes.wrap(K2 or K1)
        self.block_size = len(self.K1)



    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.

        Returns:
            Bytes: Resulting ciphertext.
        """
        k1_p = self.K1 ^ plaintext
        f_p  = self.F0(k1_p)
        return f_p ^ self.K2



    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.

        Returns:
            Bytes: Resulting plaintext.
        """
        k2_p = self.K2 ^ ciphertext
        f_p  = self.F1(k2_p)
        return f_p ^ self.K1
