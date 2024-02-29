from samson.encoding.openssh.core import DSAPrivateKey, DSAPublicKey, PrivateKey, PublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSHPublicBase, OpenSSH2PublicBase

class OpenSSHDSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = DSAPrivateKey
    PUBLIC_DECODER    = DSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-dss'


    @classmethod
    def _extract_key(cls, priv, pub):
        from samson.public_key.dsa import DSA
        from samson.hashes.sha1 import SHA1
        p, q, g, y, x = pub.p.val, pub.q.val, pub.g.val, pub.y.val, priv.x.val if priv else 1

        dsa = DSA(SHA1(), p=p, q=q, g=g, x=x)
        dsa.y = y

        return dsa



class OpenSSHDSAPrivateKey(OpenSSHDSAKey):

    def _build_priv_key(self):
        return PrivateKey(
            b'ssh-dss',
            DSAPrivateKey(
                p=self.key.p,
                q=self.key.q,
                g=self.key.g,
                y=self.key.y,
                x=self.key.x,
            )
        )


    @classmethod
    def _build_key(cls, key: 'DSA'):
        return PublicKey(b'ssh-dss', DSAPublicKey(key.p, key.q, key.g, key.y))



class OpenSSHDSAPublicKey(OpenSSHDSAPrivateKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHDSAPrivateKey


class SSH2DSAPublicKey(OpenSSHDSAPublicKey, OpenSSH2PublicBase):
    pass
