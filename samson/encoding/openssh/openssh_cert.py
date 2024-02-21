from samson.auxiliary.serialization import Serializable
from samson.core.base_object import BaseObject
from samson.encoding.general import PKIEncoding, PKIAutoParser, EncodingScheme
from samson.utilities.bytes import Bytes
from samson.encoding.openssh.openssh_ecdsa_key import SSH_INVERSE_CURVE_LOOKUP, SSH_CURVE_NAME_LOOKUP
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA512, SHA256
from copy import deepcopy

#####
# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
#####

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


class RSAKey(S):
    e: S.MPInt
    n: S.MPInt


class DSAKey(S):
    p: S.MPInt
    q: S.MPInt
    g: S.MPInt
    y: S.MPInt


class ECDSAKey(S):
    curve: S.Bytes
    public_key: S.Bytes


class EdDSAKey(S):
    pk: S.Bytes



SIG_CLS_LOOKUP = {
    'RSA': RSASSHSignature,
    'DSA': DSASSHSignature,
    'ECDSA': ECDSASSHSignature,
    'EdDSA': EdDSASSHSignature
}



class OpenSSHCertificate(BaseObject):
    ENCODING = PKIEncoding.OpenSSH_CERT
    HEADER   = None
    KEY_CLS  = SSHSignature

    def __init__(self, key: object, nonce: bytes=None, data: SSHCertificateData=None, signature_key=None, signature: SSHSignature=None) -> None:
        self.key   = key
        self.nonce = nonce or Bytes.random(32)
        self.data  = data or SSHCertificateData()
        self.signature_key = signature_key
        self.signature     = signature


    @staticmethod
    def _check_decode_b64(buffer):
        try:
            return EncodingScheme.BASE64.decode(buffer.split()[1])
        except:
            return buffer


    @classmethod
    def check(cls, buffer: bytes, **kwargs):
        try:
            left_over, header = SSHCertificateHeader.deserialize(cls._check_decode_b64(buffer))
            return header.cert_type == cls.HEADER
        except ValueError:
            return False


    @classmethod
    def decode(cls, buffer: bytes, **kwargs):
        buffer               = cls._check_decode_b64(buffer)
        left_over, header    = SSHCertificateHeader.deserialize(buffer)
        left_over, key_data  = cls.KEY_CLS.deserialize(left_over)
        left_over, cert_data = SSHCertificateData.deserialize(left_over)
        left_over, signature = S.Opaque[SSHSignature].deserialize(left_over)

        key           = cls._extract_key(key_data)
        signature_key = PKIAutoParser.import_key(cert_data.signature_key.val)

        return cls(key=key, nonce=header.nonce, data=cert_data, signature_key=signature_key, signature=signature.subcls_deserialize())


    @classmethod
    def _extract_key(cls, key):
        raise NotImplementedError

    @classmethod
    def _build_key(cls, key):
        raise NotImplementedError


    def encode(self, signing_key: 'EncodablePKI'=None, signing_alg=None, overwrite_signature_key: bool=False):
        # Sign it
        ssh_signature = self.signature
        ow_cert_data = None

        if not ssh_signature:
            # TODO: My god is this sloppy. I'm using like 3 different lookup methods and the metadata is so disparate
            # Don't have the time right now to clean this up
            signing_key = signing_key or self.key
            signing_alg = signing_alg or (signing_key.SIG_ALG_DEFAULT if hasattr(signing_key, "SIG_ALG_DEFAULT") else self.get_sig_alg_name(signing_key).encode('utf-8'))

            sig_cls = self.get_sig_cls(signing_key)

            # Overwrite internal cert_data.signature_key with signing_key if user overrides
            # This has to be done because the signing key is part of the signed blob
            if overwrite_signature_key:
                ow_cert_data = deepcopy(self.data)
                encoded_key = signing_key.export_public_key(PKIEncoding.OpenSSH).encode().split(b' ')[1]
                ow_cert_data.signature_key = S.Bytes(EncodingScheme.BASE64.decode(encoded_key))

            ssh_signature = sig_cls(
                algorithm=signing_alg,
                signature=sig_cls.sign(signing_alg, signing_key, self._build_body(ow_cert_data))
            )

        return Bytes(self._build_body(ow_cert_data) + S.Opaque[type(ssh_signature)](ssh_signature).serialize())


    def verify(self, signing_key: 'EncodablePKI'=None):
        signing_key = signing_key or self.signature_key.key
        signer      = self._get_signer(signing_key, self.signature.algorithm.val)
        return signer.verify(self._build_body(), self.signature.signature.val.get_sig())


    def _build_body(self, cert_data=None):
        header   = SSHCertificateHeader(cert_type=self.get_header(), nonce=self.nonce)
        key_data = self._build_key(self.key)

        return header.serialize() + key_data.serialize() + (cert_data or self.data).serialize()


    def _get_signer(self, signing_key, signing_alg):
        name = type(signing_key).__name__

        if name == 'RSA':
            if signing_alg == b'ssh-rsa':
                hash_obj = SHA1()
            elif signing_alg == b'rsa-sha2-256':
                hash_obj = SHA256()
            elif signing_alg == b'rsa-sha2-512':
                hash_obj = SHA512()
            else:
                raise ValueError(f'Unknown RSA signing algorithm {signing_alg.decode()}')

            from samson.protocols.pkcs1v15_rsa_signer import PKCS1v15RSASigner
            signer = PKCS1v15RSASigner(signing_key, hash_obj)
            return signer
        
        else:
            return signing_key

    @staticmethod
    def get_sig_alg_name(signing_key):
        name = type(signing_key).__name__

        if name == 'RSA':
            return 'ssh-rsa'

        elif name == 'DSA':
            return 'ssh-dss'

        elif name == 'ECDSA':
            curve_name = SSH_CURVE_NAME_LOOKUP[signing_key.G.curve].decode()
            return f'ecdsa-sha2-{curve_name}'

        elif name == 'EdDSA':
            return 'ssh-ed25519'
        
        else:
            raise ValueError(f'Key type {signing_key} not supported')


    @staticmethod
    def get_sig_cls(signing_key):
        name = type(signing_key).__name__
        try:
            return SIG_CLS_LOOKUP[name]
        except KeyError:
            raise ValueError(f'Key type {signing_key} not supported')


    @classmethod
    def get_header(cls):
        return cls.HEADER



class OpenSSHRSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-rsa-cert-v01@openssh.com'
    KEY_CLS = RSAKey

    @classmethod
    def _extract_key(cls, key: RSAKey):
        from samson.public_key.rsa import RSA
        return RSA(n=key.n.val, e=key.e.val)

    @classmethod
    def _build_key(cls, key):
        return RSAKey(n=key.n, e=key.e)



class OpenSSHECDSACertificate(OpenSSHCertificate):
    HEADERS = (
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com', 
        b'ecdsa-sha2-nistp384-cert-v01@openssh.com', 
        b'ecdsa-sha2-nistp521-cert-v01@openssh.com'
    )

    KEY_CLS = ECDSAKey

    @classmethod
    def check(cls, buffer: bytes, **kwargs):
        try:
            buffer = EncodingScheme.BASE64.decode(buffer.split()[1])
        except:
            pass

        try:
            left_over, header = SSHCertificateHeader.deserialize(buffer)
            return header.cert_type in cls.HEADERS
        except ValueError:
            return False


    @classmethod
    def _extract_key(cls, key):
        from samson.public_key.ecdsa import ECDSA
        curve = SSH_INVERSE_CURVE_LOOKUP[key.curve.val.decode()]
        return ECDSA(G=curve.G, d=1, Q=curve.decode_point(key.public_key.val))

    @classmethod
    def _build_key(cls, key: 'ECDSA'):
        return ECDSAKey(curve=SSH_CURVE_NAME_LOOKUP[key.G.curve], public_key=key.Q.serialize_uncompressed())


    def get_header(self):
        return f'ecdsa-sha2-{SSH_CURVE_NAME_LOOKUP[self.key.G.curve].decode()}-cert-v01@openssh.com'.encode('utf-8')


class OpenSSHDSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-dss-cert-v01@openssh.com'
    KEY_CLS = DSAKey

    @classmethod
    def _extract_key(cls, key: DSAKey):
        from samson.public_key.dsa import DSA
        return DSA(p=key.p.val, q=key.q.val, g=key.g.val, y=key.y.val)

    @classmethod
    def _build_key(cls, key: 'DSA'):
        return DSAKey(p=key.p, q=key.q, g=key.g, y=key.y)



class OpenSSHEdDSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-ed25519-cert-v01@openssh.com'
    KEY_CLS = EdDSAKey

    @classmethod
    def _extract_key(cls, key: EdDSAKey):
        from samson.public_key.eddsa import EdDSA, EdwardsCurve25519
        return EdDSA(curve=EdwardsCurve25519, A=key.pk.val, d=Bytes().zfill(1), a=1, clamp=False)

    @classmethod
    def _build_key(cls, key: 'EdDSA'):
        return EdDSAKey(pk=key.encode_point(key.A))

