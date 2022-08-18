import math
from functools import lru_cache

from samson.auxiliary.lazy_loader import LazyLoader
@lru_cache()
def get_math_gen():
    return LazyLoader('_math_gen', globals(), 'samson.math.general')

@lru_cache()
def get_factor_gen():
    return LazyLoader('_factor_gen', globals(), 'samson.math.factorization.general')

@lru_cache()
def get_real_gen():
    return LazyLoader('_real_gen', globals(), 'samson.math.algebra.fields.real_field')


class Complexity(object):
    def __init__(self, repr, estimator):
        self.repr = repr
        self.estimate = estimator

    def __repr__(self):
        return self.repr


class LComplexity(Complexity):
    def __init__(self, a, c):
        self.repr = f'L_n[{a}, {c}]'
        self.estimate = lambda n: int(get_math_gen().estimate_L_complexity(a, c, n))


def add_complexity(complexity):
    def wrapper(func):
        func.complexity = complexity
        return func

    return wrapper


def _ph_estimator(g: 'RingElement', n: int=None, factors: dict=None):
    if not n:
        n = g.order()

    if not factors:
        factors = get_factor_gen().factor(n)

    total = 1
    for p, e in factors.items():
        total *= get_math_gen().kth_root(p, 2)*e

    return total // 2


def _nist_gnfs_estimator(L: int):
    RR   = get_real_gen().RealField(100)
    ln2  = RR(2).log()
    Lln2 = RR(L).log(2)*ln2
    return int(RR(2)**((1.923*(Lln2*RR(Lln2).log()**2)**(1/3) - 4.69)/ln2))


class KnownComplexities(object):
    LOG    = Complexity(repr='O(log n)', estimator=lambda n: n.bit_length())
    LINEAR = Complexity(repr='O(n)', estimator=lambda n: n)
    QUAD   = Complexity(repr='O(n^2)', estimator=lambda n: n**2)
    CUBIC  = Complexity(repr='O(n^3)', estimator=lambda n: n**3)
    GNFS   = LComplexity(1/3, (64/9)**(1/3))
    SNFS   = LComplexity(1/3, (32/9)**(1/3))
    IC     = LComplexity(1/2, math.sqrt(2))
    PH     = Complexity(repr='O(e√p)', estimator=_ph_estimator)
    LLL    = Complexity(repr='O(n^4 log B)', estimator=lambda rows, columns: rows**4 * columns.bit_length()) # https://arxiv.org/abs/1006.1661#:~:text=Its%20average%20complexity%20is%20shown,approximations%20of%20LLL%20are%20proposed.
    GRAM   = Complexity(repr='O(2nk^2)', estimator=lambda rows, columns: 2*rows*columns**2) # https://stackoverflow.com/questions/27986225/computational-complexity-of-gram-schmidt-orthogonalization-algorithm
    SIQS   = Complexity(repr='O(exp(sqrt(log n log log n)))', estimator=lambda n: round(math.e**(math.sqrt(math.log(n) * math.log(math.log(n)))))) # https://www.rieselprime.de/ziki/Self-initializing_quadratic_sieve#Complexity
    NIST_GNFS = Complexity(repr='(1.923 * ∛[L*ln(2)*ln(L*ln(2))²] - 4.69) / ln(2)', estimator=_nist_gnfs_estimator) # https://crypto.stackexchange.com/questions/8687/security-strength-of-rsa-in-relation-with-the-modulus-size
