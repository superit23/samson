from samson.all import *

N = 1009 * 1201
B = 40


class Diamond(BaseObject):
    """The main diamond-shaped commutative diagram we are working in."""

    def __init__(self, f, g, m, N):
        assert f(m) % N == 0
        assert g(m) % N == 0
        self.left = Order(f)
        self.right = Order(g)
        self.bottom = ZZ/ZZ(N)
        self.m = m
        self.N = N

    def le(self, f):
        return f(self.left.symbol*1)

    def re(self, f):
        return f(self.right.symbol*1)

    def lp(self, a):
        return self.bottom(a.polynomial()(self.m))

    def rp(self, a):
        return self.bottom(a.polynomial()(self.m))


    @staticmethod
    def build(N: int, d: int):
        x    = Symbol('x')
        base = math.floor(N**(1/d))
        _    = ZZ[x]
        f    = int_to_poly(N, base).change_ring(ZZ)

        assert f.LC() == 1
        return Diamond(x - base, f, base, N)


class FactorBasis(BaseObject):
    def __init__(self, facs) -> None:
        self.facs = facs


    @staticmethod
    def build(B: int, K: Order):
        facs = {}
        for p in primes(2):
            if p > B:
                break

            facs[p] = K(p).factor()
        
        return FactorBasis(facs)
