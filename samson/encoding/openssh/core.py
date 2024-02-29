from samson.auxiliary.serialization import Serializable
from samson.padding.incremental_padding import IncrementalPadding
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA512, SHA256
from types import FunctionType

S = Serializable[4]

class SSHCertType(S.Enum[S.UInt32]):
    USER = 1
    HOST = 2


class SSHECDSASig(S):
    r: S.MPInt
    s: S.MPInt

    def get_sig(self):
        return int(self.r), int(self.s)


class SSHDSASig(S):
    r: S.UInt[160]
    s: S.UInt[160]

    def get_sig(self):
        return int(self.r), int(self.s)


class SSHRSASig(S):
    s: S.GreedyBytes

    def get_sig(self):
        return Bytes(bytes(self.s))


class SSHEdDSASig(S):
    s: S.Bytes[64]

    def get_sig(self):
        return bytes(self.s)



class SSHSignature(S):
    algorithm: S.Bytes
    signature: S.Bytes

    SIG_ALG_DEFAULT = None

    def subcls_deserialize(self):
        for klass in SSHSignature.__subclasses__():
            if self.algorithm.val in klass.SIG_ALGS:
                return klass.deserialize(self.serialize())[1]
        return self


class ECDSASSHSignature(SSHSignature):
    algorithm: S.Bytes = b''
    signature: S.Opaque[SSHECDSASig]

    SIG_ALGS = (
        b'ecdsa-sha2-nistp256',
        b'ecdsa-sha2-nistp384',
        b'ecdsa-sha2-nistp521'
    )

    @staticmethod
    def sign(alg, key, data):
        r,s = key.sign(data)
        return SSHECDSASig(r, s)



class DSASSHSignature(SSHSignature):
    algorithm: S.Bytes = b''
    signature: S.Opaque[SSHDSASig]

    SIG_ALGS = (
        b'ssh-dss',
    )

    SIG_ALG_DEFAULT = b'ssh-dss'

    @staticmethod
    def sign(alg, key, data):
        r,s = key.sign(data)
        return SSHDSASig(r, s)


class RSASSHSignature(SSHSignature):
    algorithm: S.Bytes = b''
    signature: S.Opaque[SSHRSASig]

    SIG_ALGS = (
        b'ssh-rsa',
        b'rsa-sha2-512'
    )

    SIG_ALG_DEFAULT = b'rsa-sha2-512'

    @staticmethod
    def sign(alg, key, data):
        from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner

        if alg == b'ssh-rsa':
            hash_obj = SHA1()
        elif alg == b'rsa-sha2-512':
            hash_obj = SHA512()
        else:
            raise ValueError(f'SSH RSA algorithm {alg.decode()} does not exist')

        signer = PKCS1v15RSASigner(key, hash_obj)
        return SSHRSASig(signer.sign(data))


class EdDSASSHSignature(SSHSignature):
    algorithm: S.Bytes = b''
    signature: S.Opaque[SSHEdDSASig]

    SIG_ALGS = (
        b'ssh-ed25519',
    )

    SIG_ALG_DEFAULT = b'ssh-ed25519'

    @staticmethod
    def sign(alg, key, data):
        s = key.sign(data)
        return SSHEdDSASig(s)


class SSHArmoredSignature(S):
    magic: S.Bytes[6]
    sig_version: S.UInt32
    public_key: S.Bytes
    namespace: S.Bytes
    reserved: S.Bytes
    signature: S.Opaque[SSHSignature]


class SSHOption(S):
    name: S.Bytes
    value: S.Bytes


class SSHCertificateHeader(S):
    cert_type: S.Bytes
    nonce: S.Bytes


class SSHCertificateData(S):
    serial: S.UInt64 = 0
    type: SSHCertType = 1
    key_id: S.Bytes = b''
    valid_principals: S.Opaque[S.GreedyList[S.Bytes]] = b''
    valid_after: S.UInt64 = 0
    valid_before: S.UInt64 = 0
    critical_options: S.Bytes = b''
    extensions: S.Opaque[S.GreedyList[SSHOption]] = []
    reserved: S.Bytes = b''
    signature_key: S.Bytes = b''


def key_class_selector(cls, state):
    if state['header'] == b'ssh-rsa':
        return RSAPublicKey, RSAPrivateKey

    elif state['header'] == b'ssh-dss':
        return DSAPublicKey, DSAPrivateKey

    elif b'ecdsa' in bytes(state['header']):
        return ECDSAPublicKey, ECDSAPrivateKey

    elif state['header'] == b'ssh-ed25519':
        return EdDSAPublicKey, EdDSAPrivateKey

    elif state['header'] == b'ssh-rsa':
        return RSAPublicKey, RSAPrivateKey
    
    else:
        raise ValueError("Key type not supported")


def pub_key_class_selector(cls, state):
    return key_class_selector(cls, state)[0]


def priv_key_class_selector(cls, state):
    return key_class_selector(cls, state)[1]


class PublicKey(S):
    header: S.Bytes
    key: S.Selector[pub_key_class_selector]


class PrivateKey(S):
    header: S.Bytes
    key: S.Selector[priv_key_class_selector]


class PrivateKeyContainer(S):
    check_1: S.Bytes[4]
    check_2: S.Bytes[4]
    key: PrivateKey
    host: S.Bytes


class PublicPrivatePair(S):
    public: S.Opaque[PublicKey]
    private: S.Opaque[S.Padded[PrivateKeyContainer, IncrementalPadding(8, always_pad=False)]]

    def encrypt(self, encryptor, padding_size):
        return EncryptedPublicPrivatePair(
            public=self.public,
            private=bytes(encryptor(IncrementalPadding(padding_size, always_pad=True).pad(self.private.val.val.serialize())))
        )


class EncryptedPublicPrivatePair(S):
    public: S.Opaque[PublicKey]
    private: S.Bytes

    def decrypt(self, decryptor):
        return PublicPrivatePair(
            public=self.public,
            private=S.Padded[PrivateKeyContainer, IncrementalPadding(16, always_pad=False)].deserialize(decryptor(self.private.val))[1]
        )


class KDFParams(S):
    salt: S.Bytes
    rounds: S.UInt32


def optional_kdf_params(cls, state):
    if state['kdf'] != b'none':
        return KDFParams
    else:
        return S.Null



from samson.block_ciphers.rijndael import Rijndael
from samson.block_ciphers.modes.ctr import CTR
from samson.kdfs.bcrypt_pbkdf import BcryptPBKDF


def init_aes256_ctr(key_iv):
    key, iv = key_iv[:32], key_iv[32:]
    ctr = CTR(Rijndael(key), nonce=b'')
    ctr.counter = iv.int()

    return ctr


def derive_bcrypt_pbkdf(passphrase, rounds, key_size, salt=None):
    kdf = BcryptPBKDF(rounds=rounds)
    return kdf.derive(passphrase, salt, key_size)


KDF_ALGS = {
    'bcrypt': derive_bcrypt_pbkdf
}

ENC_ALGS = {
    'aes256-ctr': (init_aes256_ctr, 48, 16)
}

class OpenSSHPrivateHeader(S):
    magic: S.Bytes[15] = b'openssh-key-v1\x00'
    encryption: S.Bytes
    kdf: S.Bytes
    kdf_params: S.Opaque[S.Selector[optional_kdf_params]]


    def generate_encryptor(self, passphrase: bytes) -> (FunctionType, int):
        """
        Generates an encryptor based on the KDF parameters and `passphrase`.

        Parameters:
            passphrase (bytes): Passphrase for key derivation.

        Returns:
            (func, int): Encryption function and padding size.
        """
        enc_func, key_size, padding_size = ENC_ALGS[bytes(self.encryption.val).decode()]
        key_iv = KDF_ALGS[self.kdf.val.decode()](passphrase, int(self.kdf_params.val.val.rounds), key_size, bytes(self.kdf_params.val.val.salt.val))
        return enc_func(key_iv).encrypt, padding_size


    # TODO: Add more decryption algorithms
    def generate_decryptor(self, passphrase: bytes) -> FunctionType:
        """
        Generates an decryptor based on the KDF parameters and `passphrase`.

        Parameters:
            passphrase (bytes): Passphrase for key derivation.

        Returns:
            func: Encryption function.
        """
        return self.generate_encryptor(passphrase)[0]



def encrypted_key_selector(cls, state):
    if state['header'].kdf.val == b'none':
        return S.SizedList[PublicPrivatePair]
    else:
        return S.SizedList[EncryptedPublicPrivatePair]


class OpenSSHPrivateKey(S):
    header: OpenSSHPrivateHeader
    keypairs: S.Selector[encrypted_key_selector]


class RSAPublicKey(S):
    e: S.MPInt
    n: S.MPInt


class RSAPrivateKey(S):
    n: S.MPInt
    e: S.MPInt
    d: S.MPInt
    q_mod_p: S.MPInt
    p: S.MPInt
    q: S.MPInt


class DSAPublicKey(S):
    p: S.MPInt
    q: S.MPInt
    g: S.MPInt
    y: S.MPInt


class DSAPrivateKey(S):
    p: S.MPInt
    q: S.MPInt
    g: S.MPInt
    y: S.MPInt
    x: S.MPInt


class ECDSAPublicKey(S):
    curve: S.Bytes
    public_key: S.Bytes


class ECDSAPrivateKey(S):
    curve: S.Bytes
    public_key: S.Bytes
    d: S.MPInt


class SSHECDSAPublicKey(S):
    header: S.Bytes
    key: ECDSAPublicKey


class EdDSAPublicKey(S):
    pk: S.Bytes


class SSHEdDSAPublicKey(S):
    header: S.Bytes = b'ssh-ed25519'
    key: EdDSAPublicKey


class EdDSAPrivateKey(S):
    pk: S.Bytes
    h: S.Bytes
