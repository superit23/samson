from samson.math.symbols import Symbol
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import kth_root, primes, int_to_poly, gcd, random_int_between, lcm
from samson.utilities.exceptions import NoSolutionException
from samson.math.factorization.general import factor, trial_division
from samson.math.matrix import Matrix
from samson.math.algebra.rings.order import Order
from samson.core.base_object import BaseObject
from functools import lru_cache

x = Symbol('x')
P = ZZ[x]


class SNFSDlogCache(BaseObject):
    def __init__(self, g, q, d, S, A, vG, p, rfb, afb_l) -> None:
        self.g   = g
        self.q   = q
        self.d   = d
        self.S   = S
        self.A   = A
        self.vG  = vG
        self.p   = p
        self.rfb = rfb
        self.afb_l = afb_l
    

    def log(self, y):
        R, vY = find_smooth_representative(self.g, self.p, self.rfb, self.afb_l, self.d, y)
        vY    = -vY.change_ring(ZZ/ZZ(self.q))
        X     = self.A.LUsolve(vY.T)
        x     = (-X[0][0] * self.S - R)
        return int(x)



def find_params(p, max_d=4000, max_r=30, max_sparsity=3):
    k = 1
    best_f = 0
    for d in primes(0, max_d):
        q = kth_root(p, k*d)-1
        if q < 2:
            break

        f = int_to_poly(p, q).change_ring(ZZ)
        if (max(f) < max_r and f.coeffs.sparsity <= max_sparsity and f.is_irreducible()):
            k *= d
            best_f = f

    if best_f.coeffs.sparsity > max_sparsity:
        raise NoSolutionException

    m = kth_root(p, k)-1
    return best_f, best_f.symbol - m, m


def create_rational_factor_bases(B, m):
    res = []
    for q in primes(0, B):
        res.append((m % q, q))
    return res


def create_algebraic_factor_bases(f, B, d):
    res = []
    for q in primes(0, B):
        roots = []
        for i in range(q):
            if f(i) % q == 0:
                res.append((i, q))
            if len(roots) >= d:
                break
        if len(roots) >= d:
            res.append(*roots)
    return res


def compute_schirokauermap_exp(f, q):
    z = Symbol('z')
    Q = (ZZ/ZZ(q))[z]
    return lcm([q**i.degree() - 1 for i in Q(f).factor()])


def create_vector3(a, b, f, q, sigma, d):
    R   = ZZ/ZZ(q**2)
    m   = Matrix([[a, -f[0]*b], [b, a-b]], R)
    sm  = (m**sigma) * Matrix([[1,0]], R).T - Matrix([[1,0]], R).T
    res = []
    for i in range(d):
        res.append(int(sm[i][0]) // q)
    return res



def create_rat_exp_vec(x, prime_base, facs):
    vec = []
    vec.append(1 if x < 0 else 0)
    for q in prime_base:
        vec.append(facs.factors.get(q, 0))
    return vec



def create_alg_exp_vec(a, b, facs, algebraic_factor_bases):
    vec = []
    for root, prime in algebraic_factor_bases:
        elem = 0
        factor_p = facs.factors.get(prime, None)
        if factor_p:
            if (a % prime) == ((-b * root) % prime):
                elem = factor_p
        vec.append(elem)
    return vec



class FactorBase(BaseObject):
    def __init__(self, base) -> None:
        self.base = base
    

    def __len__(self):
        return len(self.base)
    

    @lru_cache()
    def ideals(self):
        return [r[1] for r in self.base]


    @lru_cache()
    def factor(self, n):
        return trial_division(n, prime_base=self.ideals())


    def is_smooth(self, n):
        return self.factor(n).recombine() == n


    def sieve(self):
        B = self.base[-1][0]
        for r,p in self.base:
            for a in range(1, B*2):
                for b in range(-B//2, B):
                    if a % p == (-b*r) % p and gcd(a,b) == 1:
                        yield a, b


class RationalFactorBase(FactorBase):
    @staticmethod
    def create(B, m):
        return RationalFactorBase(create_rational_factor_bases(B, m))

    def create_exp_vector(self, n):
        return create_rat_exp_vec(n, self.ideals(), self.factor(n))


class AlgebraicFactorBase(FactorBase):
    @staticmethod
    def create(f1, B, d):
        return AlgebraicFactorBase(create_algebraic_factor_bases(f1, B, d))

    def create_exp_vector(self, a, b, n):
        return create_alg_exp_vec(a, b, self.factor(n), self.base)


def find_smooth_representative(g, p, rfb, afb_l, d, mul_mod):
    while True:
        S = random_int_between(2, p-1)
        G = int(pow(g, S, p)*mul_mod) % p

        if rfb.is_smooth(G):
            v1 = rfb.create_exp_vector(G)
            v2 = [0] * afb_l
            v3 = [0] * d
            vG = Matrix([v1 + v2 + v3])
            if (all(e == 0 for e in vG[0]) or sum(e for e in vG[0]) <= 3):
                continue
            return S, vG





def snfs(p, q, g, y, max_d, B):
    # Find parameters and build factor bases
    f1, f2, m = find_params(p, max_d=max_d)
    d         = f1.degree()
    rfb       = RationalFactorBase.create(B, m)
    afb       = AlgebraicFactorBase.create(f1, B, d)
    sigma     = compute_schirokauermap_exp(f1, q)

    A_rows  = []
    max_row = len(rfb) + len(afb) + 2

    O = Order(f1)
    z = O.symbol


    # Sieve
    rational_sieve  = set(rfb.sieve())
    algebraic_sieve = set(afb.sieve())

    candidates = algebraic_sieve.intersection(rational_sieve)

    for a,b in candidates:
        c1, c2  = a + b*m, abs(int(O(a + z*b).norm()))

        if rfb.is_smooth(c1) and afb.is_smooth(c2):
            v1 = rfb.create_exp_vector(c1)
            v2 = afb.create_exp_vector(a, b, c2)
            v3 = create_vector3(a, b, f1, q, sigma, d)

            if (all(e == 0 for e in v1) or sum(e for e in v1) <= 1):
                continue
            if (all(e == 0 for e in v2) or sum(e for e in v2) <= 1):
                continue

            A_rows.append(v1 + v2 + v3)
            if len(A_rows) >= max_row:
                break



    S, vG = find_smooth_representative(g, p, rfb, len(afb), d, 1)

    A_rows.insert(0, vG[0])
    A = Matrix(A_rows, ZZ/ZZ(q)).T


    # Cache our computations and do the linear algebra
    dlog_cache = SNFSDlogCache(g=g, q=q, d=d, S=S, A=A, vG=vG, p=p, rfb=rfb, afb_l=len(afb))
    result = dlog_cache.log(y)

    if pow(g, result, p) == y:
        return result, dlog_cache
    else:
        raise NoSolutionException("Whoopsie poopsie")

