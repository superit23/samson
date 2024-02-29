from samson.core.base_object import BaseObject
from samson.encoding.general import PKIEncoding, PKIAutoParser, EncodingScheme
from samson.encoding.openssh.core import *
from samson.utilities.bytes import Bytes
from samson.encoding.openssh.openssh_ecdsa_key import SSH_INVERSE_CURVE_LOOKUP, SSH_CURVE_NAME_LOOKUP
from samson.hashes.sha1 import SHA1
from samson.hashes.sha2 import SHA512, SHA256
from copy import deepcopy

#####
# https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
#####


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

    def __init__(self, key: object, nonce: bytes=None, data: SSHCertificateData=None, signature_key=None, signature: SSHSignature=None, user: bytes=None) -> None:
        self.key   = key
        self.nonce = nonce or Bytes.random(32)
        self.data  = data or SSHCertificateData()
        self.signature_key = signature_key
        self.signature     = signature
        self.user          = user or b''


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
        user                 = buffer.split()[2]
        buffer               = cls._check_decode_b64(buffer)
        left_over, header    = SSHCertificateHeader.deserialize(buffer)
        left_over, key_data  = cls.KEY_CLS.deserialize(left_over)
        left_over, cert_data = SSHCertificateData.deserialize(left_over)
        left_over, signature = S.Opaque[SSHSignature].deserialize(left_over)

        key           = cls._extract_key(key_data)
        signature_key = PKIAutoParser.import_key(cert_data.signature_key.val)

        return cls(key=key, nonce=header.nonce, data=cert_data, signature_key=signature_key, signature=signature.subcls_deserialize(), user=user)


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

        complete_cert = Bytes(self._build_body(ow_cert_data) + S.Opaque[type(ssh_signature)](ssh_signature).serialize())
        return b' '.join([self.get_header(), EncodingScheme.BASE64.encode(complete_cert), self.user])


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
    KEY_CLS = RSAPublicKey

    @classmethod
    def _extract_key(cls, key: RSAPublicKey):
        from samson.public_key.rsa import RSA
        return RSA(n=key.n.val, e=key.e.val)

    @classmethod
    def _build_key(cls, key):
        return RSAPublicKey(n=key.n, e=key.e)



class OpenSSHECDSACertificate(OpenSSHCertificate):
    HEADERS = (
        b'ecdsa-sha2-nistp256-cert-v01@openssh.com', 
        b'ecdsa-sha2-nistp384-cert-v01@openssh.com', 
        b'ecdsa-sha2-nistp521-cert-v01@openssh.com'
    )

    KEY_CLS = ECDSAPublicKey

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
        return ECDSAPublicKey(curve=SSH_CURVE_NAME_LOOKUP[key.G.curve], public_key=key.Q.serialize_uncompressed())


    def get_header(self):
        return f'ecdsa-sha2-{SSH_CURVE_NAME_LOOKUP[self.key.G.curve].decode()}-cert-v01@openssh.com'.encode('utf-8')


class OpenSSHDSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-dss-cert-v01@openssh.com'
    KEY_CLS = DSAPublicKey

    @classmethod
    def _extract_key(cls, key: DSAPublicKey):
        from samson.public_key.dsa import DSA
        return DSA(p=key.p.val, q=key.q.val, g=key.g.val, y=key.y.val, hash_obj=SHA1())

    @classmethod
    def _build_key(cls, key: 'DSA'):
        return DSAPublicKey(p=key.p, q=key.q, g=key.g, y=key.y)



class OpenSSHEdDSACertificate(OpenSSHCertificate):
    HEADER  = b'ssh-ed25519-cert-v01@openssh.com'
    KEY_CLS = EdDSAPublicKey

    @classmethod
    def _extract_key(cls, key: EdDSAPublicKey):
        from samson.public_key.eddsa import EdDSA, EdwardsCurve25519
        return EdDSA(curve=EdwardsCurve25519, A=key.pk.val, d=Bytes().zfill(1), a=1, clamp=False)

    @classmethod
    def _build_key(cls, key: 'EdDSA'):
        return EdDSAPublicKey(pk=key.encode_point(key.A))

