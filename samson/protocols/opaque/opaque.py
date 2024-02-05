from samson.auxiliary.serialization import Serializable
import math

S2 = Serializable[2]
Npk = 33 # 384
Nn  = 32 # TODO
Nm  = 32
Noe = 32
Nh  = 32
Nseed = 32

class CleartextCredentials(S2):
    server_public_key: S2.Bytes[Npk]
    server_identity: S2.Bytes
    client_identity: S2.Bytes


class Envelope(S2):
    nonce: S2.Bytes[Nn]
    auth_tag: S2.Bytes[Nm]


class RegistrationRequest(S2):
    evaluated_message: S2.Bytes[Noe]
    server_public_key: S2.Bytes[Npk]


class RegistrationRecord(S2):
    client_public_key: S2.Bytes[Npk]
    masking_key: S2.Bytes[Nh]
    

class AuthRequest(S2):
    client_nonce: S2.Bytes[Nn]
    client_public_keyshare: S2.Bytes[Npk]


class CredentialRequest(S2):
    blinded_message: S2.Bytes[Noe]


class KE1(S2):
    credential_request: CredentialRequest
    auth_request: AuthRequest


class AuthResponse(S2):
    server_nonce: S2.Bytes[Nn]
    server_public_keyshare: S2.Bytes[Npk]
    server_mac: S2.Bytes[Nm]


class CredentialResponse(S2):
    evaluated_message: S2.Bytes[Noe]
    masking_nonce: S2.Bytes[Nn]
    masked_response: S2.Bytes[Npk + Nn + Nm]


class KE2(S2):
    credential_response: CredentialResponse
    auth_response: AuthResponse


class KE3(S2):
    client_mac: S2.Bytes[Nm]


class CustomLabel(S2):
    length: S2.UInt16
    label: S2.Opaque[S2.Bytes] # TODO: This should be one byte not two
    context: S2.Bytes


def random(n):
    return bytes(Bytes.random(n))


def Extract(salt, ikm):
    return HKDF(SHA256(), 0).extract(salt, ikm)


def Expand(prk, info, L):
    return HKDF(SHA256(), 0).expand(prk, info, L)


def MAC(key, msg):
    return HMAC(SHA256(), key).generate(msg)


def concat(*args):
    return b''.join(args)


def I2OSP(a, length):
    return bytes(Bytes(a).zfill(length))


def OS2IP(b):
    return Bytes.wrap(b).int()


class HashToField(object):
    # https://datatracker.ietf.org/doc/html/rfc9380#name-hash_to_field-implementatio
    
    def __init__(self, DST, p, m, L, expand_message) -> None:
        self.DST = DST
        self.p   = p
        self.m   = m
        self.L   = L
        self.expand_message = expand_message
    

    def __call__(self, msg, count):
        len_in_bytes  = count * self.m * self.L
        uniform_bytes = self.expand_message(msg, self.DST, len_in_bytes)

        u_i = []
        for i in range(count):
            e_j  = []

            for j in range(self.m):
                elm_offset = self.L * (j + i * self.m)
                tv  = uniform_bytes[elm_offset:elm_offset+self.L]
                e_j.append(OS2IP(tv) % self.p)
            
            u_i.append(e_j)
        
        return u_i


class XMD(object):
    # https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd

    def __init__(self, H, b_in_bytes, s_in_bytes):
        self.H = H
        self.b_in_bytes = b_in_bytes
        self.s_in_bytes = s_in_bytes


    def __call__(self, msg, DST, len_in_bytes):
        ell = math.ceil(len_in_bytes / self.b_in_bytes)
        if ell > 255 or len_in_bytes > 65535 or len(DST) > 255:
            raise ValueError

        # Variables
        DST_prime = DST + I2OSP(len(DST), 1)
        Z_pad     = I2OSP(0, self.s_in_bytes)
        l_i_b_str = I2OSP(len_in_bytes, 2)
        msg_prime = Z_pad + msg + l_i_b_str + I2OSP(0, 1) + DST_prime

        # Build blocks
        b_0 = self.H.hash(msg_prime)
        b_1 = self.H.hash(b_0 + I2OSP(1, 1) + DST_prime)

        bis = [b_0, b_1]
        for i in range(2, ell+1):
            b_i = self.H.hash((Bytes.wrap(b_0) ^ Bytes.wrap(bis[i-1])) + I2OSP(i, 1) + DST_prime)
            bis.append(b_i)

        uniform_bytes = b''.join(bis[1:])
        return uniform_bytes[:len_in_bytes]


def sgn0_m_eq_1(x):
    return x % 2


class SWUMap(object):
    # https://datatracker.ietf.org/doc/html/rfc9380#name-simplified-shallue-van-de-w

    def __init__(self, E, Z=None) -> None:
        assert E.a*E.b
        self.E = E
        self.Z = E.ring(Z or self._find_z())
    

    def _find_z(self):
        xx  = Symbol('xx')
        F   = self.E.ring
        P   = F[xx]
        A,B = self.E.a, self.E.b
        g   = xx**3 + A*xx + B

        ctr = F.one
        while True:
            for Z_cand in (ctr, -ctr):
                if Z_cand.is_square():
                    continue
                if Z_cand == F(-1):
                    continue
                if (g - Z_cand).is_irreducible():
                    continue
                if (g(B / (Z_cand * A))).is_square():
                    return Z_cand

            ctr += 1
    

    def __call__(self, u):
        u = u[0]
        A = self.E.a
        B = self.E.b
        Z = self.Z

        tv1 = (Z**2 * u**4 + Z * u**2)**(self.E.ring.characteristic()-2)
        x1  = (-B / A) * (1 + tv1)

        if tv1 == 0:
            x1 = B / (Z * A)

        gx1 = x1**3 + A * x1 + B
        x2  = Z * u**2 * x1
        gx2 = x2**3 + A * x2 + B

        if gx1.is_square():
            x = x1
            y = gx1.sqrt()
        else:
            x = x2
            y = gx2.sqrt()
        
        if sgn0_m_eq_1(u) != sgn0_m_eq_1(y):
            y = -y

        return self.E(x,y)


class EncodeToCurve(object):
    def __init__(self, hash_to_field, map_to_curve, cofactor):
        self.hash_to_field = hash_to_field
        self.map_to_curve  = map_to_curve
        self.cofactor      = cofactor
    

    def __call__(self, msg):
        u = self.hash_to_field(msg, 1)
        Q = self.map_to_curve(u[0])
        return Q*self.cofactor



class HashToCurve(object):
    def __init__(self, hash_to_field, map_to_curve, cofactor):
        self.hash_to_field = hash_to_field
        self.map_to_curve  = map_to_curve
        self.cofactor      = cofactor
    

    def __call__(self, msg):
        u  = self.hash_to_field(msg, 2)
        print("u", u)
        Q0 = self.map_to_curve(u[0])
        Q1 = self.map_to_curve(u[1])
        return (Q0+Q1)*self.cofactor


class HashToCurveCiphersuite(object):
    def __init__(self, DST, E, k, L, f, h_eff, expand_message, encoding_cls) -> None:
        self.E = E
        self.k = k

        hash_to_field = HashToField(
            DST=DST,
            p=self.E.ring.characteristic(),
            m=int(math.log(self.E.ring.order(), self.E.ring.characteristic())),
            L=L,
            expand_message=expand_message
        )

        self.encoding = encoding_cls(hash_to_field, f, h_eff)
    

    def __call__(self, msg):
        return self.encoding(msg)




def P256_XMD_SHA_256_SSWU_RO(DST):
    return HashToCurveCiphersuite(
        DST=DST,
        E=P256,
        k=128,
        L=48,
        f=SWUMap(P256, Z=-10),
        h_eff=1,
        expand_message=XMD(SHA256(), 256 // 8, 256 // 4),
        encoding_cls=HashToCurve
    )



def HashToScalar(G, )


def DeriveKeyPair(seed, info):
    deriveInput = seed + Bytes(len(info)).zfill(2) + info
    counter = 0
    skS     = None

    while not skS:
        if counter > 255:
            raise DeriveKeyPairError

        skS = G.HashToScalar(deriveInput + Bytes(counter), DST=b"DeriveKeyPair" + contextString)
        pkS = G.ScalarMultGen(skS)
        counter += 1

    return skS, pkS

def CreateCleartextCredentials(server_public_key, client_public_key, server_identity=None, client_identity=None):
    return CleartextCredentials(
        server_public_key=server_public_key,
        client_public_key=client_public_key,
        server_identity=server_identity or server_public_key,
        client_identity=client_identity or client_public_key
    )


def Store(randomized_password, server_public_key, server_identity=None, client_identity=None):
    envelope_nonce = random(Nn)
    masking_key    = Expand(randomized_password, b"MaskingKey", Nh)
    auth_key       = Expand(randomized_password, concat(envelope_nonce, b"AuthKey"), Nh)
    export_key     = Expand(randomized_password, concat(envelope_nonce, b"ExportKey"), Nh)
    seed           = Expand(randomized_password, concat(envelope_nonce, b"PrivateKey"), Nseed)

    (_, client_public_key) = DeriveDiffieHellmanKeyPair(seed)

    cleartext_credentials = CreateCleartextCredentials(
        server_public_key,
        client_public_key,
        server_identity,
        client_identity
    )
    auth_tag = MAC(auth_key, concat(envelope_nonce, cleartext_credentials))

    Create Envelope envelope with (envelope_nonce, auth_tag)
    return (envelope, client_public_key, masking_key, export_key)