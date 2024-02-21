from enum import Enum, auto
from samson.utilities.bytes import Bytes
from samson.hashes.sha2 import SHA256
from samson.macs.hmac import HMAC
from samson.kdfs.hkdf import HKDF
from samson.math.general import random_int, mod_inv
from samson.protocols.opaque.rfc9380 import I2OSP, CreateContextString, OPRFMode, P256_XMD_SHA_256_SSWU_RO
from samson.protocols.opaque.messages import CustomLabel
from samson.protocols.opaque.exceptions import DeriveKeyPairError, InvalidInputError
from copy import copy


class KDF(Enum):
    HKDF_SHA256 = auto()

class Hash(Enum):
    SHA256 = auto()

class MAC(Enum):
    HMAC_SHA256 = auto()

class KSF(Enum):
    Identity = auto()

class OPRF(Enum):
    P256_SHA256 = auto()

class AKE(Enum):
    ThreeDH = auto()


class Primitive(object):
    @classmethod
    def select(cls, value):
        for klass in cls.__subclasses__():
            if klass.NAME == value:
                return klass
        
        raise ValueError(f"{value.name} is not a registered {cls.__name__} primitive")


class _KDF(Primitive):
    def Extract(self, salt, ikm):
        raise NotImplementedError

    def Expand(self, prk, info, L):
        raise NotImplementedError


class _Hash(Primitive):
    def __call__(self, msg):
        raise NotImplementedError


class SHA256Hash(_Hash):
    NAME = Hash.SHA256
    Nh   = 32

    def __init__(self) -> None:
        self.hash = SHA256()
    
    def __call__(self, msg):
        return self.hash.hash(msg)


class HKDFSHA256(_KDF):
    NAME = KDF.HKDF_SHA256
    Nx   = 32

    def __init__(self) -> None:
        self.hkdf = HKDF(SHA256(), 0)


    def Extract(self, salt, ikm):
        return self.hkdf.extract(salt, ikm)

    def Expand(self, prk, info, L):
        return self.hkdf.expand(prk, info, L)


class _KSF(Primitive):
    def __call__(self, key):
        raise NotImplementedError


class StretchIdentity(_KSF):
    NAME = KSF.Identity

    def __call__(self, key):
        return key


class _MAC(Primitive):
    def __call__(self, key, message):
        raise NotImplementedError


class HMACSHA256(_MAC):
    NAME = MAC.HMAC_SHA256
    Nm   = 32

    def __init__(self) -> None:
        self.hash = SHA256()

    def __call__(self, key, msg):
        return HMAC(key, self.hash).generate(msg)


class _OPRF(Primitive):
    Nn    = 32
    Nseed = 32

    def RandomScalar(self):
        raise NotImplementedError

    def Blind(self, input, blind=None):
        raise NotImplementedError

    def BlindEvaluate(self, skS, blindedElement):
        raise NotImplementedError

    def HashToScalar(self, x, DST=None):
        raise NotImplementedError

    def HashToGroup(self, x):
        raise NotImplementedError
    
    def ScalarInverse(self, s):
        raise NotImplementedError
    
    def Generator(self):
        raise NotImplementedError
    
    def Identity(self):
        raise NotImplementedError
    
    def ScalarMultGen(self, x):
        raise NotImplementedError

    def SerializeElement(self, e):
        raise NotImplementedError

    def DeserializeElement(self, b):
        raise NotImplementedError

    def Finalize(self, input, blind, evaluatedElement):
        raise NotImplementedError

    def DeriveKeyPair(self, seed, info):
        raise NotImplementedError


class P256SHA256(_OPRF):
    NAME = OPRF.P256_SHA256
    Noe  = 33
    Nok  = 32
    Npk  = 33
    Nsk  = 32

    def __init__(self) -> None:
        self.contextString        = CreateContextString(OPRFMode.OPRF, b'P256-SHA256')
        self.hash_to_scalar_suite = P256_XMD_SHA_256_SSWU_RO(DST=b'HashToScalar-' + self.contextString)
        self.hash_to_group_suite  = P256_XMD_SHA_256_SSWU_RO(DST=b'HashToGroup-' + self.contextString)


    def RandomScalar(self):
        return random_int(self.hash_to_group_suite.E.order())

    def Blind(self, input, blind=None):
        blind = blind or self.RandomScalar()
        inputElement = self.HashToGroup(input)

        if inputElement == self.Identity():
            raise InvalidInputError

        blindedElement = blind * inputElement

        return blind, blindedElement


    def BlindEvaluate(self, skS, blindedElement):
        evaluatedElement = skS * blindedElement
        return evaluatedElement


    def HashToScalar(self, x, DST=None):
        if DST:
            suite = copy(self.hash_to_scalar_suite)
            suite.encoding.hash_to_field.DST = DST
        else:
            suite = self.hash_to_scalar_suite

        return suite.encoding.hash_to_field(x, 1)[0][0]

    def HashToGroup(self, x):
        return self.hash_to_group_suite(x)
    
    def ScalarInverse(self, s):
        return mod_inv(s, self.hash_to_group_suite.E.order())
    
    def Generator(self):
        return self.hash_to_group_suite.E.G
    
    def Identity(self):
        return self.hash_to_group_suite.E.zero
    
    def ScalarMultGen(self, x):
        return self.Generator()*x

    def SerializeElement(self, e):
        return e.serialize_compressed()

    def DeserializeElement(self, b):
        return self.hash_to_group_suite.E.decode_point(b)

    def Finalize(self, input, blind, evaluatedElement):
        N = self.ScalarInverse(blind) * evaluatedElement
        unblindedElement = self.SerializeElement(N)

        hashInput = I2OSP(len(input), 2) + input + I2OSP(len(unblindedElement), 2) + unblindedElement + b"Finalize"
        return self.hash_to_scalar_suite.encoding.hash_to_field.expand_message.H.hash(hashInput)


    def DeriveKeyPair(self, seed, info):
        deriveInput = seed + I2OSP(len(info), 2) + info
        counter     = 0
        skS         = None

        suite = self.hash_to_scalar_suite
        htf   = suite.encoding.hash_to_field

        while not skS:
            if counter > 255:
                raise DeriveKeyPairError("DeriveKeyPair: counter failure")

            # NOTE: In the RFC (https://datatracker.ietf.org/doc/html/rfc9497#name-oprfp-256-sha-256), it DOES NOT use the field
            # order like RFC9380 does. It specifically says to use the GROUP order.
            skS = Bytes(htf.expand_message(deriveInput + I2OSP(counter, 1), b'DeriveKeyPair' + self.contextString, htf.L)).int() % suite.E.order()
            counter += 1
        
        pkS = self.ScalarMultGen(skS)

        return skS, pkS

    def DeriveDiffieHellmanKeyPair(self, seed):
        skS, pkS = self.DeriveKeyPair(seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")
        return skS, self.SerializeElement(pkS)


class _AKE(Primitive):
    def __init__(self, G, ciphersuite) -> None:
        self.G = G
        self.ciphersuite = ciphersuite
    
    def __hash__(self):
        return hash((self.G, self.ciphersuite.kdf))

    def DeriveDiffieHellmanKeyPair(self, seed):
        raise NotImplementedError

    def DiffieHellman(self, k, B):
        raise NotImplementedError


class ThreeDH(_AKE):
    NAME = AKE.ThreeDH

    def DiffieHellman(self, k, B):
        return self.G.SerializeElement(k*self.G.DeserializeElement(B))

    def ExpandLabel(self, Secret, Label, Context, Length):
        label = CustomLabel(length=Length, label=b'OPAQUE-' + Label, context=Context)
        return self.ciphersuite.Expand(Secret, bytes(label), Length)

    def DeriveSecret(self, Secret, Label, TranscriptHash):
        return self.ExpandLabel(Secret, Label, TranscriptHash, self.ciphersuite.Nx)

    def DeriveKeys(self, ikm, preamble):
        prk              = self.ciphersuite.Extract(b"", ikm)
        handshake_secret = self.DeriveSecret(prk, b"HandshakeSecret", self.ciphersuite.Hash(preamble))
        session_key      = self.DeriveSecret(prk, b"SessionKey", self.ciphersuite.Hash(preamble))
        Km2              = self.DeriveSecret(handshake_secret, b"ServerMAC", b"")
        Km3              = self.DeriveSecret(handshake_secret, b"ClientMAC", b"")
        return (Km2, Km3, session_key)



class OPAQUECiphersuite(object):
    def __init__(self, ake: _AKE, oprf: _OPRF, hash: _Hash, kdf: _KDF, ksf: _KSF, mac: _MAC) -> None:
        self.ake  = ake(oprf, self)
        self.oprf = oprf
        self.hash = hash
        self.kdf  = kdf
        self.ksf  = ksf
        self.mac  = mac

        self.Extract = kdf.Extract
        self.Expand  = kdf.Expand
        self.MAC     = mac
        self.Hash    = hash
        self.Stretch = ksf

        self.Npk   = oprf.Npk
        self.Nsk   = oprf.Nsk
        self.Nok   = oprf.Nok
        self.Noe   = oprf.Noe
        self.Nseed = oprf.Nseed
        self.Nn    = oprf.Nn
        self.Nm    = mac.Nm
        self.Nh    = hash.Nh
        self.Nx    = kdf.Nx


    def __repr__(self) -> str:
        return "_".join([prim.NAME.name.replace("_", "-") for prim in (self.oprf, self.kdf, self.mac, self.hash, self.ksf)])


    @staticmethod
    def select(ake: _AKE, oprf: OPRF, hash: Hash, kdf: KDF, ksf: KSF, mac: MAC):
        return OPAQUECiphersuite(
            ake=_AKE.select(ake),
            oprf=_OPRF.select(oprf)(),
            hash=_Hash.select(hash)(),
            kdf=_KDF.select(kdf)(),
            ksf=_KSF.select(ksf)(),
            mac=_MAC.select(mac)()
        )
