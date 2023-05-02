
from samson.math.general import mod_inv, generate_superincreasing_seq, find_coprime
from samson.utilities.bytes import Bytes
from samson.utilities.runtime import RUNTIME
from samson.core.primitives import EncryptionAlg


class MerkleHellmanKnapsack(EncryptionAlg):
    """
    Merkle-Hellman Knapsack cryptosystem.

    Broken and extremely rare cryptosystem based off of the hardness of the Knapsack problem.
    """

    def __init__(self, priv: list=None, q: int=None, r: int=None, max_diff: int=2**20, key_len: int=8):
        """
        Parameters:
            priv    (list): Private key made from a superincreasing sequence.
            q        (int): Modulus. Integer greater than the sum of `priv`.
            r        (int): Multiplier. Integer coprime to `q` and between `q // 4` and `q`.
            max_diff (int): Maximum difference between integers in the superincreasing sequence. Used for generating `priv`.
            key_len  (int): Desired length of the key.
        """
        super_seq = generate_superincreasing_seq(key_len + 1, max_diff, starting=Bytes.random(max(1, key_len // 8)).int())
        self.priv = priv or super_seq[:key_len]
        self.q = q or super_seq[-1]
        self.r = r or find_coprime(self.q, range(self.q // 4, self.q))

        self.pub = [(w * self.r) % self.q for w in self.priv]



    def __reprdir__(self):
        return ['priv', 'pub', 'q', 'r']


    def encrypt(self, message: bytes) -> list:
        """
        Encrypt `message`.

        Parameters:
            message (bytes): Message to encrypt.

        Returns:
            list: List of ciphertext integers. List cardinality dependent on message/key-length ratio.
        """
        bin_str = ''
        for byte in message:
            bin_str += bin(byte)[2:].zfill(8)

        all_sums = []

        for i in range(len(bin_str) // len(self.pub)):
            byte_str = bin_str[i * len(self.pub):(i + 1) * len(self.pub)]
            all_sums.append(sum([int(byte_str[j]) * self.pub[j] for j in range(len(self.pub))]))

        return all_sums



    def decrypt(self, sums: list) -> Bytes:
        """
        Decrypts `sums` back into plaintext.

        Parameters:
            sums (list): List of ciphertext sums.

        Returns:
            Bytes: Decrypted plaintext.
        """
        r_inv = mod_inv(self.r, self.q)
        inv_sums = [(byte_sum * r_inv) % self.q for byte_sum in sums]
        plaintext = Bytes(b'')

        for inv_sum in inv_sums:
            curr = inv_sum
            bin_string = ''

            for i in range(len(self.pub) - 1, -1, -1):
                if self.priv[i] <= curr:
                    curr -= self.priv[i]
                    bin_string += '1'
                else:
                    bin_string += '0'

            plaintext += int.to_bytes(int(bin_string[::-1], 2), len(self.pub) // 8, 'big')

        return plaintext


    @classmethod
    @RUNTIME.report
    def recover_plaintext(cls: object, ciphertext: int, pub: list, alpha: int=1) -> Bytes:
        """
        Attempts to recover the plaintext without the private key.

        Parameters:
            ciphertext (int): A ciphertext sum.
            pub        (int): The public key.
            alpha      (int): Punishment coefficient for deviation from guessed bit distribution.

        Returns:
            Bytes: Recovered plaintext.
        """
        from samson.math.matrix import Matrix
        from samson.math.algebra.all import QQ

        # Construct the problem matrix
        ident          = Matrix.identity(len(pub), coeff_ring=QQ)
        pub_matrix     = ident.col_join(Matrix([pub], coeff_ring=QQ))
        problem_matrix = pub_matrix.row_join(Matrix([[0] * len(pub) + [-ciphertext]], coeff_ring=QQ).T)

        # Attempt to crack the ciphertext using various punishment coefficients
        for i in RUNTIME.report_progress(range(len(pub)), desc='Alphaspace searched'):
            alpha_penalizer      = Matrix([[alpha] * len(pub) + [-alpha * i]], coeff_ring=QQ)
            problem_matrix_prime = problem_matrix.col_join(alpha_penalizer).T
            solution_matrix      = problem_matrix_prime.LLL(0.99)

            for row in solution_matrix.rows:
                relevant = row[:-2]
                new_row  = [item for item in relevant if item >= QQ.zero and item <= QQ.one]

                if len(new_row) == len(relevant):
                    return Bytes(int(''.join([str(int(float(val))) for val in relevant]), 2))
        return solution_matrix
