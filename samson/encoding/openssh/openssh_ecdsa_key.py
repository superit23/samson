from samson.encoding.openssh.core import ECDSAPrivateKey, ECDSAPublicKey, PrivateKey, PublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase
from samson.utilities.bytes import Bytes
from samson.math.algebra.curves.named import P192, P224, P256, P384, P521, GOD521
from samson.hashes.sha2 import SHA256, SHA384, SHA512
import math


SSH_CURVE_NAME_LOOKUP = {
    P192: b'nistp192',
    P224: b'nistp224',
    P256: b'nistp256',
    P384: b'nistp384',
    P521: b'nistp521',
    GOD521: b'nistp521'
}

SSH_INVERSE_CURVE_LOOKUP = {v.decode():k for k, v in SSH_CURVE_NAME_LOOKUP.items() if k != GOD521}

CURVE_HASH_LOOKUP = {
    P256: SHA256(),
    P384: SHA384(),
    P521: SHA512(),
    GOD521: SHA512()
}

def serialize_public_point(ecdsa_key: 'ECDSA'):
    curve = SSH_CURVE_NAME_LOOKUP[ecdsa_key.G.curve]
    zero_fill = math.ceil(ecdsa_key.G.curve.order().bit_length() / 8)
    x_y_bytes = b'\x04' + (Bytes(int(ecdsa_key.Q.x)).zfill(zero_fill) + Bytes(int(ecdsa_key.Q.y)).zfill(zero_fill))

    return curve, x_y_bytes



class OpenSSHECDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = ECDSAPrivateKey
    PUBLIC_DECODER    = ECDSAPublicKey
    SSH_PUBLIC_HEADER = b'ecdsa-'


    @classmethod
    def parameterize_header(cls, key: object):
        if type(key) is PublicKey:
            return b'ecdsa-sha2-' + key.key.val.curve.val
        else:
            return b'ecdsa-sha2-' + SSH_CURVE_NAME_LOOKUP[key.G.curve]


    @classmethod
    def _extract_key(cls, priv, pub):
        from samson.public_key.ecdsa import ECDSA

        curve, x_y_bytes, d = pub.curve.val, pub.public_key.val, priv.d.val if priv else 1
        curve = SSH_INVERSE_CURVE_LOOKUP[curve.decode()]

        ecdsa   = ECDSA(G=curve.G, hash_obj=CURVE_HASH_LOOKUP[curve], d=d)
        ecdsa.Q = curve(*ECDSA.decode_point(x_y_bytes))

        return ecdsa



class OpenSSHECDSAPrivateKey(OpenSSHECDSAKey):

    def _build_priv_key(self):
        return PrivateKey(
            self.parameterize_header(self.key),
            ECDSAPrivateKey(
                curve=SSH_CURVE_NAME_LOOKUP[self.key.G.curve],
                public_key=self.key.Q.serialize_uncompressed(),
                d=self.key.d
            )
        )

    @classmethod
    def _build_key(cls, key: 'ECDSA'):
        return PublicKey(cls.parameterize_header(key), ECDSAPublicKey(curve=SSH_CURVE_NAME_LOOKUP[key.G.curve], public_key=key.Q.serialize_uncompressed()))



class OpenSSHECDSAPublicKey(OpenSSHECDSAPrivateKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHECDSAPrivateKey


class SSH2ECDSAPublicKey(OpenSSHECDSAPublicKey, OpenSSH2PublicBase):
    pass
