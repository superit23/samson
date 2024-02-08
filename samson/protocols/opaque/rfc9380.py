from samson.math.algebra.curves.named import P256
from samson.math.symbols import Symbol
from samson.hashes.sha2 import SHA256
from samson.utilities.bytes import Bytes
from enum import Enum
import math

class OPRFMode(Enum):
    OPRF  = 0
    VOPRF = 1
    POPRF = 2


def concat(*args):
    return b''.join([bytes(a) for a in args])


def I2OSP(a, length):
    return bytes(Bytes(a).zfill(length))


def OS2IP(b):
    return Bytes.wrap(b).int()


def CreateContextString(mode: OPRFMode, identifier):
    return b"OPRFV1-" + I2OSP(mode.value, 1) + b"-" + identifier


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

