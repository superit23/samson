from samson.auxiliary.serialization import Serializable
from samson.core.base_object import BaseObject
from samson.encoding.general import PKIEncoding
from samson.public_key.rsa import RSA
from samson.utilities.bytes import Bytes

#####
# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
#####

S = Serializable[4]

class SSHCertType(S.Enum[S.UInt32]):
    USER = 1
    HOST = 2


class SSHECDSASig(S):
    x: S.UInt
    y: S.UInt


class SSHSignature(S):
    algorithm: S.Bytes = b''
    signature: S.Bytes = b''


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
    valid_principals: S.Bytes = b''
    valid_after: S.UInt64 = 0
    valid_before: S.UInt64 = 0
    critical_options: S.Bytes = b''
    extensions: S.Opaque[S.GreedyList[SSHOption]] = []
    reserved: S.Bytes = b''
    signature_key: S.Bytes = b''
    signature: S.Opaque[SSHSignature] = b''


class RSAKey(S):
    e: S.UInt
    n: S.UInt


class SSHCertificate(S):
    cert_type: S.Bytes
    nonce: S.Bytes
    e: S.UInt
    n: S.UInt
    serial: S.UInt64
    type: S.UInt32
    key_id: S.Bytes
    valid_principals: S.Bytes
    valid_after: S.UInt64
    valid_before: S.UInt64
    critical_options: S.Bytes
    extensions: S.Opaque[S.GreedyList[SSHOption]]
    reserved: S.Bytes
    signature_key: S.Bytes
    signature: S.Opaque[SSHSignature]


class OpenSSHCertificate(BaseObject):
    ENCODING = PKIEncoding.OpenSSH_CERT
    HEADER   = None
    KEY_CLS  = None

    def __init__(self, key: object, nonce: bytes, data: SSHCertificateData) -> None:
        self.key   = key
        self.nonce = nonce
        self.data  = data


    @classmethod
    def check(cls, buffer: bytes):
        try:
            left_over, header = SSHCertificateHeader.deserialize(buffer)
            return header.cert_type == cls.HEADER
        except ValueError:
            return False
    

    @classmethod
    def decode(cls, buffer: bytes):
        left_over, header    = SSHCertificateHeader.deserialize(buffer)
        left_over, key_data  = cls.KEY_CLS.deserialize(left_over)
        left_over, cert_data = SSHCertificateData.deserialize(left_over)

        key = cls._extract_key(key_data)

        return cls(key=key, nonce=header.nonce, data=cert_data)


    @classmethod
    def _extract_key(cls, key):
        raise NotImplementedError
    
    @classmethod
    def _build_key(cls, key):
        raise NotImplementedError


    def encode(self):
        header   = SSHCertificateHeader(cert_type=self.HEADER, nonce=self.nonce)
        key_data = self._build_key(self.key)
        return Bytes(header.serialize() + key_data.serialize() + self.data.serialize())


class OpenSSHRSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-rsa-cert-v01@openssh.com'
    KEY_CLS = RSAKey

    @classmethod
    def _extract_key(cls, key):
        return RSA(n=key.n.val, e=key.e.val)

    @classmethod
    def _build_key(cls, key):
        return RSAKey(n=key.n, e=key.e)

