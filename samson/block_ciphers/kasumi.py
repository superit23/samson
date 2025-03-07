from samson.constructions.feistel_network import FeistelNetwork
from samson.utilities.bytes import Bytes
from samson.encoding.general import int_to_bytes, bytes_to_bitstring
from samson.core.primitives import BlockCipher, Primitive
from samson.core.metadata import SizeType, SizeSpec, UsageType
from samson.ace.decorators import register_primitive

# https://asecuritysite.com/encryption/kasumi
S7 = (
     54, 50, 62, 56, 22, 34, 94, 96, 38,  6, 63, 93, 2,  18,123, 33,
     55,113, 39,114, 21, 67, 65, 12, 47, 73, 46, 27, 25,111,124, 81,
     53,  9,121, 79, 52, 60, 58, 48,101,127, 40,120,104, 70, 71, 43,
     20,122, 72, 61, 23,109, 13,100, 77,  1, 16,  7, 82, 10,105, 98,
    117,116, 76, 11, 89,106,  0,125,118, 99, 86, 69, 30, 57,126, 87,
    112, 51, 17,  5, 95, 14, 90, 84, 91,  8, 35,103, 32, 97, 28, 66,
    102, 31, 26, 45, 75,  4, 85, 92, 37, 74, 80, 49, 68, 29,115, 44,
     64,107,108, 24,110, 83, 36, 78, 42, 19, 15, 41, 88,119, 59,  3,
)

S9 = (
    167,239,161,379,391,334,  9,338, 38,226, 48,358,452,385, 90,397,
    183,253,147,331,415,340, 51,362,306,500,262, 82,216,159,356,177,
    175,241,489, 37,206, 17,  0,333, 44,254,378, 58,143,220, 81,400,
     95,  3,315,245, 54,235,218,405,472,264,172,494,371,290,399, 76,
    165,197,395,121,257,480,423,212,240, 28,462,176,406,507,288,223,
    501,407,249,265, 89,186,221,428,164, 74,440,196,458,421,350,163,
    232,158,134,354, 13,250,491,142,191, 69,193,425,152,227,366,135,
    344,300,276,242,437,320,113,278, 11,243, 87,317, 36, 93,496, 27,
    487,446,482, 41, 68,156,457,131,326,403,339, 20, 39,115,442,124,
    475,384,508, 53,112,170,479,151,126,169, 73,268,279,321,168,364,
    363,292, 46,499,393,327,324, 24,456,267,157,460,488,426,309,229,
    439,506,208,271,349,401,434,236, 16,209,359, 52, 56,120,199,277,
    465,416,252,287,246,  6, 83,305,420,345,153,502, 65, 61,244,282,
    173,222,418, 67,386,368,261,101,476,291,195,430, 49, 79,166,330,
    280,383,373,128,382,408,155,495,367,388,274,107,459,417, 62,454,
    132,225,203,316,234, 14,301, 91,503,286,424,211,347,307,140,374,
     35,103,125,427, 19,214,453,146,498,314,444,230,256,329,198,285,
     50,116, 78,410, 10,205,510,171,231, 45,139,467, 29, 86,505, 32,
     72, 26,342,150,313,490,431,238,411,325,149,473, 40,119,174,355,
    185,233,389, 71,448,273,372, 55,110,178,322, 12,469,392,369,190,
      1,109,375,137,181, 88, 75,308,260,484, 98,272,370,275,412,111,
    336,318,  4,504,492,259,304, 77,337,435, 21,357,303,332,483, 18,
     47, 85, 25,497,474,289,100,269,296,478,270,106, 31,104,433, 84,
    414,486,394, 96, 99,154,511,148,413,361,409,255,162,215,302,201,
    266,351,343,144,441,365,108,298,251, 34,182,509,138,210,335,133,
    311,352,328,141,396,346,123,319,450,281,429,228,443,481, 92,404,
    485,422,248,297, 23,213,130,466, 22,217,283, 70,294,360,419,127,
    312,377,  7,468,194,  2,117,295,463,258,224,447,247,187, 80,398,
    284,353,105,390,299,471,470,184, 57,200,348, 63,204,188, 33,451,
     97, 30,310,219, 94,160,129,493, 64,179,263,102,189,207,114,402,
    438,477,387,122,192, 42,381,  5,145,118,180,449,293,323,136,380,
     43, 66, 60,455,341,445,202,432,  8,237, 15,376,436,464, 59,461,
)

def key_schedule(key):
    K_prime = (key ^ int_to_bytes(0x123456789ABCDEFFEDCBA9876543210, 'big')).chunk(2)
    K = key.chunk(2)

    round_keys = []
    for i in range(8):
        round_keys.append([
            K[i % 8].lrot(1),
            K_prime[(i + 2) % 8],
            K[(i + 1) % 8].lrot(5),
            K[(i + 5) % 8].lrot(8),
            K[(i + 6) % 8].lrot(13),
            K_prime[(i + 4) % 8],
            K_prime[(i + 3) % 8],
            K_prime[(i + 7) % 8],
            i + 1
        ])

    return round_keys


def round_func(R_i, K_i):
    KL_i = K_i[:2]
    KO_i = K_i[2:5]
    KI_i = K_i[5:8]
    counter = K_i[-1]


    if counter % 2 == 1:
        state  = fun_fl(KL_i, R_i)
        output = fun_fo(KO_i, KI_i, state)
    else:
        state  = fun_fo(KO_i, KI_i, R_i)
        output = fun_fl(KL_i, state)

    return output


def fun_fl(KL_i, x):
    l, r = x.chunk(2)

    r_prime = (l & KL_i[0]).lrot(1) ^ r
    l_prime = (r_prime | KL_i[1]).lrot(1) ^ l

    return l_prime + r_prime


def fun_fi(K_i, x):
    as_bin = bytes_to_bitstring(x)
    l, r = int(as_bin[:9], 2), int(as_bin[9:], 2)

    K_int = int.from_bytes(K_i, 'big')
    K_l, K_r = K_int >> 9, K_int & 0b111111111

    l_1, r_1 = r, S9[l] ^ r

    l_2 = r_1 ^ K_r
    r_2 = S7[l_1] ^ (r_1 & 0b1111111) ^ K_l

    l_3, r_3 = r_2, S9[l_2] ^ r_2
    l_3 = S7[r_2] ^ (r_3 & 0b1111111)

    return Bytes(int.to_bytes(l_3 << 9 | r_3, 2, 'big'))


def fun_fo(KO_i, KI_i, x):
    l, r = x.chunk(2)

    # Some sort of deranged Feistel network...
    for i in range(3):
        l, r = r, fun_fi(KI_i[i], l ^ KO_i[i]) ^ r

    return l + r


# I WANT TO GET OFF MR. BONES' WILD RIDE
@register_primitive()
class KASUMI(FeistelNetwork, BlockCipher):
    """
    Structure: Feistel Network
    Key size: 128
    Block size: 64
    """

    KEY_SIZE   = SizeSpec(size_type=SizeType.SINGLE, sizes=128)
    BLOCK_SIZE = SizeSpec(size_type=SizeType.SINGLE, sizes=64)
    USAGE_TYPE = UsageType.CELLULAR

    def __init__(self, key: bytes):
        """
        Parameters:
            key (bytes): Bytes-like object to key the cipher.
        """
        Primitive.__init__(self)
        self.key = Bytes.wrap(key)
        self.key_schedule = key_schedule
        self.round_func = round_func



    def __reprdir__(self):
        return ['key']

    # For some reason KASUMI reverses the L_0 and R_0, so we need to feed it correctly into the FeistelNetwork
    def encrypt(self, plaintext: bytes) -> Bytes:
        """
        Encrypts `plaintext`.

        Parameters:
            plaintext (bytes): Bytes-like object to be encrypted.

        Returns:
            Bytes: Resulting ciphertext.
        """
        plaintext = Bytes.wrap(plaintext)
        half = len(plaintext) // 2
        L_i, R_i = plaintext[:half], plaintext[half:]

        return FeistelNetwork.encrypt(self, self.key, R_i + L_i)


    def decrypt(self, ciphertext: bytes) -> Bytes:
        """
        Decrypts `ciphertext`.

        Parameters:
            ciphertext (bytes): Bytes-like object to be decrypted.

        Returns:
            Bytes: Resulting plaintext.
        """
        plaintext = FeistelNetwork.decrypt(self, self.key, Bytes.wrap(ciphertext))

        half = len(plaintext) // 2
        plaintext = Bytes.wrap(plaintext)
        L_i, R_i = plaintext[:half], plaintext[half:]
        return R_i + L_i
