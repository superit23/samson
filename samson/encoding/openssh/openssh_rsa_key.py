from samson.math.general import mod_inv
from samson.encoding.openssh.core import RSAPrivateKey, RSAPublicKey, PrivateKey, PublicKey
from samson.encoding.openssh.openssh_base import OpenSSHPrivateBase, OpenSSH2PublicBase, OpenSSHPublicBase

class OpenSSHRSAKey(OpenSSHPrivateBase):
    PRIVATE_DECODER   = RSAPrivateKey
    PUBLIC_DECODER    = RSAPublicKey
    SSH_PUBLIC_HEADER = b'ssh-rsa'


    @classmethod
    def _extract_key(cls, priv, pub):
        from samson.public_key.rsa import RSA

        n, e, p, q = pub.n.val, pub.e.val, priv.p.val if priv else None, priv.q.val if priv else None

        rsa = RSA(n.bit_length(), n=n, p=p, q=q, e=e)

        return rsa



class OpenSSHRSAPrivateKey(OpenSSHRSAKey):

    def _build_priv_key(self):
        return PrivateKey(
            b'ssh-rsa',
            RSAPrivateKey(
                n=self.key.n,
                e=self.key.e,
                d=max(self.key.d, self.key.alt_d),
                q_mod_p=mod_inv(self.key.q, self.key.p),
                p=self.key.p,
                q=self.key.q
            )
        )

    @classmethod
    def _build_key(cls, key: 'RSA'):
        return PublicKey(b'ssh-rsa', RSAPublicKey(key.e, key.n))



class OpenSSHRSAPublicKey(OpenSSHRSAPrivateKey, OpenSSHPublicBase):
    PRIVATE_CLS = OpenSSHRSAPrivateKey


class SSH2RSAPublicKey(OpenSSHRSAPublicKey, OpenSSH2PublicBase):
    pass
