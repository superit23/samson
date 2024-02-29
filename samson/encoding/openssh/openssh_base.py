from samson.core.base_object import BaseObject
from samson.encoding.openssh.general import generate_openssh_private_key, parse_openssh_key
from samson.encoding.openssh.core import PrivateKeyContainer, OpenSSHPrivateHeader
from samson.utilities.bytes import Bytes

class OpenSSHBase(BaseObject):
    DEFAULT_MARKER = 'OPENSSH PRIVATE KEY'
    DEFAULT_PEM    = True

    PRIVATE_DECODER = None
    PUBLIC_DECODER  = None

    def __init__(self, key: object, user: bytes=b'nohost@localhost', **kwargs):
        self.key  = key

        if user and type(user) is str:
            user = user.encode('utf-8')

        self.user = user


    @classmethod
    def parse_keys(cls, buffer: bytes, passphrase: bytes=None):
        return parse_openssh_key(buffer, cls.SSH_PUBLIC_HEADER, passphrase)


    @classmethod
    def check(cls, buffer: bytes, passphrase: bytes=None, **kwargs):
        return OpenSSHPrivateHeader.magic in buffer and cls.SSH_PUBLIC_HEADER in buffer


    def encode(self, encode_pem: bool=True, marker: str=None, encryption: bytes=None, iv: bytes=None, passphrase: bytes=None, **kwargs):
        public_key, private_key = self.build_keys(self.user, self.check_1, self.check_2)
        encoded = generate_openssh_private_key(public_key, private_key, encode_pem, marker, encryption, iv, passphrase, header=self.header)
        return Bytes.wrap(encoded)


    @classmethod
    def decode(cls, buffer: bytes, passphrase: bytes=None, **kwargs):
        priv, pub, user, check_1, check_2, header = cls.parse_keys(buffer, passphrase)
        return cls(cls._extract_key(priv, pub), user, check_1=check_1, check_2=check_2, header=header)


    def build_keys(self, user, check_1, check_2):
        return self.build_pub(), self.build_priv(user, check_1, check_2)


    def build_priv(self, user, check_1=None, check_2=None):
        check = Bytes.random(4)
        check_1 = check_1 or check
        check_2 = check_2 or check_1

        private_key = PrivateKeyContainer(
            check_1=check_1,
            check_2=check_2,
            key=self._build_priv_key(),
            host=user
        )

        return private_key


    def build_pub(self):
        return self._build_key(self.key)


class OpenSSHPrivateBase(OpenSSHBase):
    def __init__(self, key: object, user: bytes = b'nohost@localhost', check_1: bytes = None, check_2: bytes = None, header=None, **kwargs):
        super().__init__(key, user, **kwargs)
        
        check        = Bytes.random(4)
        self.check_1 = check_1 or check
        self.check_2 = check_2 or check_1
        self.header  = header


from samson.encoding.openssh.general import generate_openssh_public_key_params
from samson.encoding.pem import PEMEncodable
from samson.encoding.general import PKIEncoding

class OpenSSHPublicBase(OpenSSHBase, PEMEncodable):
    DEFAULT_MARKER = None
    DEFAULT_PEM    = False
    USE_RFC_4716   = False
    ENCODING       = PKIEncoding.OpenSSH
    PRIVATE_CLS    = None


    @classmethod
    def parameterize_header(cls, key: object):
        return cls.SSH_PUBLIC_HEADER


    @classmethod
    def check(cls, buffer: bytes, **kwargs) -> bool:
        return cls.SSH_PUBLIC_HEADER in buffer and not cls.PRIVATE_CLS.check(buffer) and b'cert' not in buffer[:32]


    def encode(self, **kwargs) -> bytes:
        return self._actual_encode(self.user, encode_pem=False)


    def _actual_encode(self, user: bytes, **kwargs):
        public_key = self.build_pub()
        encoded    = generate_openssh_public_key_params(self.ENCODING, self.parameterize_header(public_key), public_key, user=user)
        return self.transport_encode(encoded, **kwargs)



class OpenSSH2PublicBase(OpenSSHPublicBase):
    DEFAULT_MARKER = 'SSH2 PUBLIC KEY'
    DEFAULT_PEM    = True
    USE_RFC_4716   = True
    ENCODING       = PKIEncoding.SSH2

    def encode(self, **kwargs) -> bytes:
        return self._actual_encode(None)
