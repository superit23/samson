from samson.encoding.openssh.core import EdDSAPrivateKey, EdDSAPublicKey, PrivateKey, PublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase

class OpenSSHEdDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = EdDSAPrivateKey
    PUBLIC_DECODER    = EdDSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-ed25519'


    @classmethod
    def _extract_key(cls, priv_key: EdDSAPrivateKey, pub_key: EdDSAPublicKey=None):
        from samson.public_key.eddsa import EdDSA, EdwardsCurve25519

        A, h  = pub_key.pk.val, priv_key.h.val if priv_key else 0
        eddsa = EdDSA(curve=EdwardsCurve25519, h=h, A=A, d=b'\x00', a=1, clamp=False)

        return eddsa



class OpenSSHEdDSAPrivateKey(OpenSSHEdDSAKey):

    def _build_priv_key(self):
        return PrivateKey(
            b'ssh-ed25519',
            EdDSAPrivateKey(
                pk=self.key.encode_point(self.key.A),
                h=self.key.h
            )
        )

    @classmethod
    def _build_key(cls, key: 'EdDSA'):
        return PublicKey(b'ssh-ed25519', EdDSAPublicKey(key.encode_point(key.A)))




class OpenSSHEdDSAPublicKey(OpenSSHEdDSAPrivateKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHEdDSAPrivateKey


class SSH2EdDSAPublicKey(OpenSSHEdDSAPublicKey, OpenSSH2PublicBase):
    pass
