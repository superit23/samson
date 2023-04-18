from samson.core.base_object import BaseObject
from samson.utilities.general import rand_bytes
from samson.utilities.exceptions import NotInvertibleException, ProbabilisticFailureException, SearchspaceExhaustedException, NoSolutionException
from samson.auxiliary.complexity import add_complexity, KnownComplexities
from samson.utilities.runtime import RUNTIME
from functools import reduce
from typing import Tuple, List
from types import FunctionType
from copy import deepcopy, copy
from enum import Enum
import math

# Resolve circular dependencies while reducing function-level imports
from samson.auxiliary.lazy_loader import LazyLoader

@RUNTIME.global_cache()
def lazy_import(local_name, fqn):
    return LazyLoader(local_name, globals(), fqn)

_integer_ring  = lazy_import('_integer_ring', 'samson.math.algebra.rings.integer_ring')
_real_field    = lazy_import('_real_field', 'samson.math.algebra.fields.real_field')
_complex_field = lazy_import('_complex_field', 'samson.math.algebra.fields.complex_field')
_poly          = lazy_import('_poly', 'samson.math.polynomial')
_mat           = lazy_import('_mat', 'samson.math.matrix')
_dense         = lazy_import('_dense', 'samson.math.dense_vector')
_factor_gen    = lazy_import('_factor_gen', 'samson.math.factorization.general')
_factors       = lazy_import('_factors', 'samson.math.factorization.factors')
_ell_curve     = lazy_import('_ell_curve', 'samson.math.algebra.curves.weierstrass_curve')
_symbols       = lazy_import('_symbols', 'samson.math.symbols')


def int_to_poly(integer: int, modulus: int=2) -> 'Polynomial':
    """
    Encodes an `integer` as a polynomial.

    Parameters:
        integer (int): Integer to encode.
        modulus (int): Modulus to reduce the integer over.

    Returns:
        Polynomial: Polynomial representation.

    Examples:
        >>> from samson.math.general import int_to_poly
        >>> int_to_poly(100)
        <Polynomial: x^6 + x^5 + x^2, coeff_ring=ZZ/(ZZ(2))>

        >>> int_to_poly(128, 3)
        <Polynomial: x^4 + x^3 + (2)*x^2 + 2, coeff_ring=ZZ/(ZZ(3))>

    """
    Polynomial = _poly.Polynomial
    ZZ = _integer_ring.ZZ
    base_coeffs = []

    # Use != to handle negative numbers
    while integer != 0 and integer != -1:
        integer, r = divmod(integer, modulus)
        base_coeffs.append(r)

    return Polynomial(base_coeffs, ZZ/ZZ(modulus))


def poly_to_int(poly: 'Polynomial') -> int:
    """
    Encodes an polynomial as a integer.

    Parameters:
        poly (Polynomial): Polynomial to encode.

    Returns:
        int: Integer representation.

    Examples:
        >>> from samson.math.general import int_to_poly, poly_to_int
        >>> poly_to_int(int_to_poly(100))
        100

        >>> poly_to_int(int_to_poly(100, 3))
        100

    """
    modulus = poly.coeff_ring.order()
    value   = 0
    for idx, coeff in poly.coeffs:
        value += int(coeff) * modulus**idx

    return value


def frobenius_monomial_base(poly: 'Polynomial') -> List['Polynomial']:
    """
    Generates a list of monomials of x**(i*p) % g for range(`poly`.degrees()). Used with Frobenius map.

    Parameters:
        poly (Polynomial): Polynomial to generate bases for.

    Returns:
        List[Polynomial]: List of monomial bases mod g.

    References:
        https://github.com/sympy/sympy/blob/d1301c58be7ee4cd12fd28f1c5cd0b26322ed277/sympy/polys/galoistools.py
    """
    oo = _symbols.oo

    n = poly.degree()
    if n == 0:
        return []

    P = poly.ring
    q = poly.coeff_ring.order() if poly.coeff_ring.order() != oo else poly.coeff_ring.characteristic()
    bases = [None]*n
    bases[0] = P.one

    if q < n:
        for i in range(1, n):
            bases[i] = (bases[i-1] << q) % poly

    elif n > 1:
        R = P/poly
        x = P.symbol
        bases[1] = R(x)**q

        for i in range(2, n):
            bases[i] = bases[i-1] * bases[1]

        # Peel off the quotient ring
        for i in range(1, n):
            bases[i] = bases[i].val

    return bases


def frobenius_map(f: 'Polynomial', g: 'Polynomial', bases: List['Polynomial']=None) -> 'Polynomial':
    """
    Computes `f`**p % `g` using the Frobenius map.

    Parameters:
        f           (Polynomial): Base.
        g           (Polynomial): Modulus.
        bases (List[Polynomial]): Frobenius monomial bases. Will generate if not provided.

    Returns:
        Polynomial: `f`**p % `g`

    References:
        https://en.wikipedia.org/wiki/Finite_field#Frobenius_automorphism_and_Galois_theory
    """
    if not bases:
        bases = frobenius_monomial_base(g)

    dg = g.degree()
    df = f.degree()
    P  = f.ring

    if df >= dg:
        f %= g
        df = f.degree()

    if not f:
        return f

    sf = P([f.coeffs[0]])

    for i in range(1, df+1):
        sf += bases[i] * P([f.coeffs[i]])

    return sf


def gcd(*args) -> 'RingElement':
    """
    Iteratively computes the greatest common divisor.

    Parameters:
        a (RingElement): First element.
        b (RingElement): Second element.

    Returns:
        RingElement: GCD of `a` and `b`.

    Examples:
        >>> from samson.math.general import gcd
        >>> gcd(256, 640)
        128

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> gcd(P(x**2), P(x**5))
        <Polynomial: x^2, coeff_ring=F_(2^8)>

    """
    total = args[0]
    if type(total) is int:
        def _gcd(a,b):
            while b:
                a, b = b, a % b
            
            if a < 0:
                a = -a
            return a
    else:
        def _gcd(a,b):
            return a.gcd(b)

    for arg in args[1:]:
        total = _gcd(total, arg)

    return total


def xgcd(a: 'RingElement', b: 'RingElement') -> Tuple['RingElement', 'RingElement', 'RingElement']:
    """
    Extended Euclidean algorithm form of GCD.
    `a`x + `b`y = gcd(`a`, `b`)

    Parameters:
        a (RingElement): First integer.
        b (RingElement): Second integer.

    Returns:
        Tuple[RingElement, RingElement, RingElement]: Formatted as (GCD, x, y).

    Examples:
        >>> from samson.math.general import xgcd
        >>> xgcd(10, 5)
        (5, 0, 1)

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> xgcd(P(x**2), P(x**5))
        (<Polynomial: x^2, coeff_ring=F_(2^8)>, <Polynomial: 1, coeff_ring=F_(2^8)>, <Polynomial: F_(2^8)(ZZ(0)), coeff_ring=F_(2^8)>)

    References:
        https://anh.cs.luc.edu/331/notes/xgcd.pdf
    """
    ZZ = _integer_ring.ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        b = ZZ(b)

    R = a.ring

    # Generic xgcd
    prevx, x = R.one, R.zero; prevy, y = R.zero, R.one
    while b:
        q = a // b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b

    g, s, t = a, prevx, prevy

    # Normalize if possible
    if g.is_invertible() and s:
        s_g = s // g
        if s_g:
            g, s, t = g // g, s_g, t // g


    if peel_ring:
        g = g.val
        s = s.val
        t = t.val

    return g, s, t


def lcm(*args) -> 'RingElement':
    """
    Calculates the least common multiple of `a` and `b`.

    Parameters:
        a (RingElement): First integer.
        b (RingElement): Second integer.

    Returns:
        RingElement: Least common multiple.

    Examples:
        >>> from samson.math.general import lcm
        >>> lcm(2, 5)
        10

        >>> from samson.math.algebra.all import FF
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = FF(2, 8)[x]
        >>> lcm(P(x**2 + 5), P(x-6))
        <Polynomial: x^3 + x, coeff_ring=F_(2^8)>

    """
    def _lcm(a, b):
        return a // gcd(a, b) * b


    # Handle lists for convenience
    if len(args) == 1 and type(args[0]) is list:
        args = args[0]

    total = args[0]
    for arg in args[1:]:
        total = _lcm(total, arg)

    return total


def xlcm(a: 'RingElement', b: 'RingElement') -> Tuple['RingElement', 'RingElement', 'RingElement']:
    """
    Extended least common multiple. Finds the LCM and two integers `n` and `m` such that
    `l` == `n`*`m` and gcd(`n`, `m`) == 1.

    Parameters:
        a (RingElement): First element.
        b (RingElement): Second element.

    Returns:
        (RingElement, RingElement, RingElement): Formatted as (LCM, `n`, `m`).

    References:
        https://github.com/sagemath/sage/blob/fbca269f627bf6a8bc6f0a611ed7e26260ebc994/src/sage/arith/misc.py#L1835
    """
    g = gcd(a, b)
    l = (a*b) // g
    g = gcd(a, b // g)

    # Remove all common factors from a
    while g != 1:
        a //= g
        g   = gcd(a, g)

    return l, a, l // a


@RUNTIME.global_cache()
def mod_inv(a: 'RingElement', n: 'RingElement') -> 'RingElement':
    """
    Calculates the modular inverse.

    Parameters:
        a (RingElement): Element to invert.
        n (RingElement): Modulus.

    Returns:
        RingElement: Modular inverse of `a` over `n`.

    Examples:
        >>> from samson.math.general import mod_inv
        >>> mod_inv(5, 11)
        9

    References:
        https://en.wikipedia.org/wiki/Euclidean_algorithm#Linear_Diophantine_equations
        https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    if hasattr(a, 'mod_inv'):
        return a.mod_inv(n)

    ZZ = _integer_ring.ZZ

    # For convenience
    peel_ring = False
    if type(a) is int:
        peel_ring = True
        a = ZZ(a)
        n = ZZ(n)

    _, x, _ = xgcd(a, n)
    R = a.ring

    if (a * x) % n != R.one:
        raise NotInvertibleException(f"{a} is not invertible over {n}", parameters={'a': a, 'x': x, 'n': n})

    if x < R.zero:
        x = x + n

    if peel_ring:
        x = x.val

    return x


@add_complexity(KnownComplexities.LOG)
def square_and_mul(g: 'RingElement', u: int, s: 'RingElement'=None) -> 'RingElement':
    """
    Computes `s` = `g` ^ `u` over arbitrary rings.

    Parameters:
        g (RingElement): Base.
        u         (int): Exponent.
        s (RingElement): The 'one' value of the ring.

    Returns:
        RingElement: `g` ^ `u` within its ring.

    Examples:
        >>> from samson.math.general import mod_inv
        >>> square_and_mul(5, 10, 1)
        9765625

        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> square_and_mul(P(x+5), 6)
        <Polynomial: x^6 + (30)*x^5 + (121)*x^4 + (87)*x^3 + (104)*x^2 + (81)*x + 4, coeff_ring=ZZ/(ZZ(127))>

    """
    invert = False
    if u < 0:
        invert = True
        u = -u

    s = s or g.ring.one
    while u != 0:
        if u & 1:
            s = (g * s)
        u >>= 1
        g = (g * g)

    if invert:
        s = ~s

    return s


@add_complexity(KnownComplexities.LOG)
def fast_mul(a: 'RingElement', b: int, s: 'RingElement'=None) -> 'RingElement':
    """
    Computes `s` = `a` * `b` over arbitrary rings.

    Parameters:
        a (RingElement): Element `a`.
        b         (int): Multiplier.
        s (RingElement): The 'zero' value of the ring.

    Returns:
        RingElement: `a` * `b` within its ring.

    Examples:
        >>> from samson.math.general import fast_mul
        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> P = (ZZ/ZZ(127))[x]
        >>> fast_mul(P(x+5), 5)
        <Polynomial: (5)*x + 25, coeff_ring=ZZ/(ZZ(127))>

    """
    s = s if s is not None else a.ring.zero
    if b < 0:
        b = -b
        a = -a

    c = b
    d = a
    while b != 0:
        if b & 1:
            s = (a + s)
        b >>= 1
        if b:
            a = (a + a)

    if c and hasattr(d, 'order_cache') and d.order_cache and not d.order_cache % c:
        s.order_cache = d.order_cache // c
    return s



def kth_root(n: int, k: int) -> int:
    """
    Calculates the `k`-th integer root of `n`.

    Parameters:
        n (int): Integer.
        k (int): Root (e.g. 2).

    Returns:
        int: `k`-th integer root of `n

    Examples:
        >>> from samson.math.general import kth_root
        >>> kth_root(1000, 3)
        10

        >>> kth_root(129, 7)
        3

    References:
        https://stackoverflow.com/questions/23621833/is-cube-root-integer
        https://github.com/sympy/sympy/blob/c0bfc81f3ffee97c6d6732ac5e5ccf399e5ab3e2/sympy/core/power.py#L84
        https://en.wikipedia.org/wiki/Newton%27s_method
    """
    negate = False
    if n < 0:
        if k % 2:
            negate = True
            n = -n
        else:
            raise NoSolutionException("Even degree roots do not exist for negative integers")

    # Estimate the root using floating point exponentiation
    # This typically is within 1e-10 of the actual root for large integers
    try:
        guess = round(n**(1/k))

    except OverflowError:
        # If we overflow the float's precision, we can use a bit of math
        # to calculate it at a lower precision and shift it.
        # This still tends to be highly accurate
        e = math.log2(n)/k
        if e > 53:
            shift = int(e - 53)
            guess = int(2.0**(e - shift) + 1) << shift
        else:
            guess = int(2.0**e)


    # Newton's method is more likely to screw up small numbers than converge
    if guess > 2**50:
        # Use Newton's method to rapidly converge on the root
        rprev, root, k_1 = -1, guess, k-1
        while root > 2:
            approx = root**k_1
            rprev, root = root, (k_1*root + n//approx) // k
            if abs(root - rprev) < 2:
                break
    else:
        root = guess



    t = root**k
    if t == n:
        return root * (negate*-2+1)

    # If we're very close, then try incrementing/decrementing
    diff = n-t
    try:
        if abs(diff)/n < 0.1:
            if diff > 0:
                while t < n:
                    root += 1
                    t     = root**k
            else:
                while t > n:
                    root -= 1
                    t     = root**k

            return (root + (t < n)) * (negate*-2+1)
    except OverflowError:
        pass


    # If we're still not there, use binary search to comb through the rest of the space
    ub = root
    lb = 0

    while lb < ub:
        guess = (lb + ub) // 2
        if pow(guess, k) < n:
            lb = guess + 1
        else:
            ub = guess

    return (lb + (lb**k < n)) * (negate*-2+1)


def kth_root_qq(n: int, k: int, precision: int=32) -> 'FractionFieldElement':
    """
    Calculates the `k`-th rational root of `n` to `precision` bits of precision.

    Parameters:
        n      (int/QQ): Integer.
        k         (int): Root (e.g. 2).
        precision (int): Bits of precision.

    Returns:
        FractionFieldElement: `k`-th rational root of `n

    Examples:
        >>> from samson.math.general import kth_root_qq
        >>> kth_root_qq(2, 2, 32)
        <FractionFieldElement: numerator=759250125, denominator=536870912, field=Frac(ZZ)>

        >>> diff = abs(float(kth_root_qq(2, 2, 32)) - 2**(0.5))

        >>> diff < 1/2**32
        True

        >>> diff < 1/2**64
        False

    References:
        https://stackoverflow.com/a/39802349
    """
    from samson.math.all import QQ

    n  = QQ(n)
    lb = QQ.zero
    ub = n
    precision = QQ((1, 2**precision))

    while True:
        mid = (lb+ub)/2
        mid_k = mid**k

        if abs(mid_k-n) < precision:
            return mid
        elif mid_k < n:
            lb = mid
        else:
            ub = mid


def brent_cycle_detection(f: FunctionType, x0: object) -> Tuple[int, int]:
    """
    Brent's cycle detection algorithm.

    Parameters:
        f    (func): Function to find cycles in.
        x0 (object): Initial argument

    Returns:
        Tuple[int, int]: Formatted as (loop length, `x0` offset).

    References:
        https://en.wikipedia.org/wiki/Cycle_detection
    """
    power    = lam = 1
    tortoise = x0
    hare     = f(x0)

    while tortoise != hare:
        if power == lam:
            tortoise = hare
            power   *= 2
            lam      = 0

        hare = f(hare)
        lam += 1


    tortoise = hare = x0
    for _ in range(lam):
        hare = f(hare)

    mu = 0
    while tortoise != hare:
        tortoise = f(tortoise)
        hare     = f(hare)
        mu      += 1
 
    return lam, mu


@add_complexity(KnownComplexities.LINEAR)
def crt(residues: List['QuotientElement'], auto_correct: bool=True) -> Tuple['RingElement', 'RingElement']:
    """
    Performs the Chinese Remainder Theorem and returns the computed `x` and modulus.

    Parameters:
        residues (List[QuotientElement]): Residues of `x` as QuotientElements or tuples.
        auto_correct              (bool): Whether or not to automatically remove redundancy.

    Returns:
        (RingElement, RingElement): Formatted as (computed `x`, modulus).

    Examples:
        >>> from samson.math.general import crt
        >>> from samson.math.algebra.all import ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')

        >>> n = 17
        >>> residues = [(17 % mod, mod) for mod in [2, 3, 5]]
        >>> crt(residues)
        (17, 30)

        >>> n = 17
        >>> residues = [(ZZ/ZZ(mod))(17) for mod in [2, 3, 5]]
        >>> crt(residues)
        (<IntegerElement: val=17, ring=ZZ>, <IntegerElement: val=30, ring=ZZ>)

        >>> P = (ZZ/ZZ(2))[x]
        >>> moduli = [P(x + 1), P(x**2 + x + 1), P(x**3 + x + 1)]
        >>> n = P[17]
        >>> residues = [(P/mod)(n) for mod in moduli]
        >>> crt(residues)
        (<Polynomial: x^4 + 1, coeff_ring=ZZ/(ZZ(2))>, <Polynomial: x^6 + x^4 + x + 1, coeff_ring=ZZ/(ZZ(2))>)

    """
    ZZ = _integer_ring.ZZ

    # Auto promote
    peel_ring = False
    if type(residues[0]) is tuple:
        if type(residues[0][0]) is int:
            ring = ZZ
            peel_ring = True
        else:
            ring = residues[0][0].ring

        residues = [(ring/ring(mod))(res) for res, mod in residues]


    # Remove redundancies
    if auto_correct:
        _tmp_res = [(res.val, res.ring.quotient) for res in residues]
        ring     = _tmp_res[0][0].ring

        x, Nx = _tmp_res[0]
        for r, n in _tmp_res[1:]:
            n_total = lcm(Nx, n)
            new_res = []

            n2p = n_total // Nx
            n1p = n_total // n

            if ring.one in [n1p, n2p]:
                if n > Nx:
                    x, Nx = r, n
            else:
                new_res.append((ring/n2p)(r))
                new_res.append((ring/n1p)(x))

                x, Nx = _crt(new_res)
    else:
        x, Nx = _crt(residues)

    if peel_ring:
        x, Nx = x.val, Nx.val

    return x, Nx



def _crt(residues: List['RingElement']) -> Tuple['RingElement', 'RingElement']:
    x    = residues[0].val
    Nx   = residues[0].ring.quotient

    for i in range(1, len(residues)):
        modulus = residues[i].ring.quotient
        x  = (mod_inv(Nx, modulus) * (residues[i].val - x)) * Nx + x
        Nx = Nx * modulus

    x = x % Nx

    return x, Nx


def crt_lll(residues: List['QuotientElement'], remove_redundant: bool=True) -> 'QuotientElement':
    """
    Imitates the Chinese Remainder Theorem using LLL and returns the computed `x`.
    Unlike CRT, this does not require the moduli be coprime. However, this method only
    returns a representative since the solution isn't unique.

    Parameters:
        residues (List[QuotientElement]): Residues of `x` as QuotientElements.
        remove_redundant          (bool): Whether or not to remove redundant subgroups to minimize the result.

    Returns:
        QuotientElement: Computed `x` over composite modulus.

    Examples:
        >>> from samson.math.general import crt_lll
        >>> from samson.math.all import ZZ
        >>> x = 684250860
        >>> rings = [ZZ/ZZ(quotient) for quotient in [229, 246, 93, 22, 408]]
        >>> crt_lll([r(x) for r in rings])
        <QuotientElement: val=684250860, ring=ZZ/(ZZ(1306272792))>

    References:
        https://grocid.net/2016/08/11/solving-problems-with-lattice-reduction/
    """
    from samson.math.algebra.fields.fraction_field import FractionField as Frac
    import operator
    Matrix = _mat.Matrix

    R = residues[0].ring.ring
    Q = Frac(R)

    # Remove redundant subgroups to minimize result
    if remove_redundant:
        reduc_func = lcm
    else:
        reduc_func = operator.mul

    # Calculate composite modulus
    L = reduce(reduc_func, [r.ring.quotient for r in residues])

    # Build the problem matrix
    r_len = len(residues)

    A = Matrix([
        [Q.one for r in residues] + [Q((R.one, L)), Q.zero],
        *[[Q.zero]*idx + [Q(r.ring.quotient)] + [Q.zero]*(1+r_len-idx) for idx, r in enumerate(residues)],
        [Q.zero for r in residues] + [Q.one, Q.zero],
        [Q(-r.val) for r in residues] + [Q.zero, L]
    ], Q)


    B = A.LLL(0.99)

    return (R/R(L))((B[-1, -2] * L).numerator)


class ResidueSymbol(Enum):
    EXISTS = 1
    DOES_NOT_EXIST = -1
    IS_ZERO = 0


def legendre(a: int, p: int) -> ResidueSymbol:
    """
    Calculates the Legendre symbol of `a` mod `p`. Nonzero quadratic residues mod `p` return 1 and nonzero, non-quadratic residues return -1. Zero returns 0.

    Parameters:
        a (int): Possible quadatric residue.
        p (int): Modulus.

    Returns:
        ResidueSymbol: Legendre symbol.

    Examples:
        >>> from samson.math.general import legendre
        >>> legendre(4, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> legendre(5, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

    """
    assert is_prime(p)
    result = pow(a, (p - 1) // 2, p)
    if result == p-1:
        result = -1

    return ResidueSymbol(result)


def generalized_eulers_criterion(a: int, k: int, p: int, factors: dict=None) -> ResidueSymbol:
    """
    Determines if `a` is a `k`-th root over `p`.

    Parameters:
        a        (int): Possible `k`-th residue.
        k        (int): Root to take.
        p        (int): Modulus.
        factors (dict): Factors of `p`.

    Returns:
        ResidueSymbol: Legendre symbol (basically).

    Examples:
        >>> from samson.math.general import generalized_eulers_criterion
        >>> generalized_eulers_criterion(4, 2, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> generalized_eulers_criterion(5, 2, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

        >>> generalized_eulers_criterion(4, 3, 11)
        <ResidueSymbol.EXISTS: 1>

    References:
        "A Generalization of Euler’s Criterion to Composite Moduli" (https://arxiv.org/pdf/1507.00098.pdf)
    """
    if p in [2, 4] or is_prime(p) or _factor_gen.is_perfect_power(p)[0] or (not p % 2 and _factor_gen.is_perfect_power(p // 2)[0]):
        t = totient(p, factors=factors)
        result = pow(a, t // gcd(k, t), p)
        if result > 1:
            result = -1

        return ResidueSymbol(result)
    else:
        raise ValueError(f"Unacceptable modulus {p} for Euler's criterion")



def kronecker_symbol(a: int, n: int, factors: 'Factors'=None) -> ResidueSymbol:
    """
    
    References:
        https://en.wikipedia.org/wiki/Kronecker_symbol
    """
    if n < 0:
        u = -1
    else:
        u = 1

    if not factors:
        factors = _factor_gen.factor(n // u)

    symbol = u
    for p, e in factors.items():
        if p == 2:
            if not a % 2:
                s = 0
            elif a % 8 in [1, 7]:
                s = 1
            else:
                s = -1

            symbol *= s
        else:
            symbol *= legendre(a, p).value**e

    return ResidueSymbol(symbol)



def tonelli(n: int, p: int) -> int:
    """
    Performs the Tonelli-Shanks algorithm for calculating the square root of `n` mod `p`.

    Parameters:
        n (int): Integer.
        p (int): Modulus.

    Returns:
        int: Square root of `n` mod `p`.

    Examples:
        >>> from samson.math.general import tonelli
        >>> tonelli(4, 7)
        2

        >>> tonelli(2, 7)
        4

    References:
        https://crypto.stackexchange.com/questions/22919/explanation-of-each-of-the-parameters-used-in-ecc
        https://www.geeksforgeeks.org/find-square-root-modulo-p-set-2-shanks-tonelli-algorithm/
        https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    """
    leg = legendre(n, p)
    if leg == ResidueSymbol.IS_ZERO:
        return 0

    elif leg == ResidueSymbol.DOES_NOT_EXIST:
        raise NoSolutionException()

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(n, (p + 1) // 4, p)

    for z in range(2, p):
        if legendre(z, p) == ResidueSymbol.DOES_NOT_EXIST:
            break

    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)

    m  = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p

        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break

            t2 = (t2 * t2) % p

        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return r



def tonelli_q(a: int, p: int, q: int) -> int:
    """
    Performs the Tonelli-Shanks algorithm for calculating the `q`th-root of `a` mod `p`.

    Parameters:
        a (int): Integer.
        p (int): Modulus.
        q (int): Root to take.

    Returns:
        int: `q`th-root of `a` mod `p`.

    Examples:
        >>> from samson.math.general import tonelli_q
        >>> tonelli_q(4, 7, 2)
        2

        >>> tonelli_q(2, 7, 2)
        4

        >>> tonelli_q(8, 67, 3)
        58

        >>> 58**3 % 67
        8

    References:
        "On Taking Roots in Finite Fields" (https://www.cs.cmu.edu/~glmiller/Publications/AMM77.pdf)
    """
    # Step 1 & 2
    gec = generalized_eulers_criterion(a, q, p)

    if gec == ResidueSymbol.IS_ZERO:
        return 0

    elif gec == ResidueSymbol.DOES_NOT_EXIST:
        raise NoSolutionException()


    # Step 3
    for g in range(2, p):
        if generalized_eulers_criterion(g, q, p) == ResidueSymbol.DOES_NOT_EXIST:
            break

    # Step 4
    p_1 = p - 1
    k   = 0

    # The algorithm only works if q | p-1
    assert p_1 % q == 0

    n = q
    div = gcd(q, p-1)
    while div != 1 and div != n:
        n   = n // div
        div = gcd(n, p-1)


    if p_1 % n == 0:
        k = 1
        p_1 //= n

    N, N_prime = divmod(p_1, n)

    # Step 5
    l = 1

    while True:
        # Step 6
        for j in range(k):
            if pow(a, q**j*(q*N+N_prime), p) == 1:
                break

        # Step 7
        if j == 0:
            # Step 8
            return pow(a, mod_inv(n, n*N+N_prime), p) * mod_inv(l, p)
        else:
            for lamb in range(1, n):
                if gcd(lamb, n) == 1:
                    if (pow(a, pow(2, j-1)*pow(2, N+N_prime), p) * pow(g, lamb*pow(2, k-1)*(2*N+N_prime), p)) % p == 1:
                        break

            a = (a * pow(g, pow(2, (k-j  )*lamb), p)) % p
            l = (l * pow(g, pow(2, (k-j-1)*lamb), p)) % p


@add_complexity(KnownComplexities.CUBIC)
def gaussian_elimination(system_matrix: 'Matrix', rhs: 'Matrix') -> 'Matrix':
    """
    Solves `Ax = b` for `x` where `A` is `system_matrix` and `b` is `rhs`.

    Parameters:
        system_matrix (Matrix): The `A` matrix.
        rhs           (Matrix): The right-hand side matrix.

    Returns:
        Matrix: The `x` matrix.

    Examples:
        >>> from samson.math.all import QQ
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.general import gaussian_elimination
        >>> a = Matrix([[3, 2,-4], [2, 3, 3], [5, -3, 1]], coeff_ring=QQ)
        >>> b = Matrix([[3], [15], [14]], coeff_ring=QQ)
        >>> c = gaussian_elimination(a, b)
        >>> a*c == b
        True

    References:
        https://rosettacode.org/wiki/Gaussian_elimination#Python
    """
    Matrix = _mat.Matrix

    A = deepcopy(system_matrix).row_join(rhs)

    n = A.num_rows
    m = A.num_cols
    R = A.coeff_ring
    l = min(n,m)

    # Forward elimination
    # for i in range(n):
    for i in range(l):
        # Find pivot
        k = max(range(i, n), key=lambda r: max(A[r][i], -A[r][i]))

        if not A[k, i]:
            continue

        # Swap rows
        A[i], A[k] = A[k], A[i]

        # Reduce rows
        scalar = ~A[i, i]
        # for j in range(i+1, n):
        for j in range(i+1, l):
            A[j] = [A[j, k] - A[i, k] * A[j, i] * scalar for k in range(m)]


    # Back substitution
    # This works with any size matrix
    rhs_cols = m - rhs.num_cols
    # for i in reversed(range(n)):
    for i in reversed(range(l)):
        # for j in range(i + 1, n):
        for j in range(i + 1, l):
            t = A[i, j]
            for k in range(rhs_cols, m):
                A[i, k] -= t*A[j, k]

        if not A[i, i]:
            continue

        t = ~A[i, i]

        for j in range(rhs_cols, m):
            A[i, j] *= t

    return Matrix(A[:, rhs_cols:m], coeff_ring=R, ring=A.ring)


@add_complexity(KnownComplexities.GRAM)
def gram_schmidt(matrix: 'Matrix', full: bool=False, A_star: 'Matrix'=None, mu: 'Matrix'=None) -> Tuple['Matrix', 'Matrix']:
    """
    Performs Gram-Schmidt orthonormalization.

    Parameters:
        matrix (Matrix): Matrix of row vectors.
        full     (bool): Whether or not to include zero vectors.
        A_star (Matrix): Previous `Q` matrix truncated to required

    Returns:
        Tuple[Matrix, Matrix]: Formatted as (orthonormalized row vectors, transform matrix).

    Examples:
        >>> from samson.math.all import QQ
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.general import gram_schmidt
        >>> out, _ = gram_schmidt(Matrix([[3,1],[2,2]], QQ))
        >>> [[float(out[r][c]) for c in range(out.num_cols)] for r in range(out.num_rows)]
        [[3.0, 1.0], [-0.4, 1.2]]

    References:
        https://github.com/sagemath/sage/blob/854f9764d14236110b8d7f7b35a7d52017e044f8/src/sage/modules/misc.py
        https://github.com/sagemath/sage/blob/1d465c7e3c82110d39034f3ca7d9d120f435511e/src/sage/matrix/matrix2.pyx

    """
    Matrix = _mat.Matrix
    DenseVector = _dense.DenseVector

    R = matrix.coeff_ring
    n = matrix.num_rows
    A = matrix

    if A_star:
        A_star = [DenseVector(row) for row in A_star]
    else:
        A_star = []

    if mu:
        mu = deepcopy(mu)
    else:
        mu = Matrix([[R.zero for _ in range(n)] for _ in range(n)])

    # Number of non-zero rows
    nnz = len(A_star)
    zeroes = []

    # Orthogonalization
    for j in range(len(A_star), n):
        ortho = A[j]

        for k in range(nnz):
            mu[j,k] = A_star[k].dot(A[j]) / A_star[k].sdot()
            ortho  -= A_star[k]*mu[j,k]

        if ortho.sdot() != R.zero:
            A_star.append(ortho)
            mu[j, nnz] = R.one
            nnz += 1
        else:
            zeroes.append(j+len(zeroes))


    # Manipulating result matrices with zero vectors
    if full:
        zero = [DenseVector([R.zero for _ in range(n-len(zeroes))])]
        for j in zeroes:
            A_star = A_star[:j] + zero + A_star[j:]

    else:
        mu = Matrix([row for row in mu.T if any(row)]).T

    Q = Matrix([v.values for v in A_star])
    return Q, mu


@add_complexity(KnownComplexities.LLL)
def lll(in_basis: 'Matrix', delta: float=0.75) -> 'Matrix':
    """
    Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

    Parameters:
        in_basis (Matrix): Matrix representing the original basis.
        delta     (float): Minimum optimality of the reduced basis.

    Returns:
        Matrix: Reduced basis.

    Examples:
        >>> from samson.math.general import lll
        >>> from samson.math.matrix import Matrix
        >>> from samson.math.all import QQ
        >>> m = Matrix([[1, 2, 3, 4], [5, 6, 7, 8]], QQ)
        >>> lll(m)
        <Matrix: coeff_ring=Frac(ZZ), num_rows=2, num_cols=4, 
            0  1  2  3
        0 [ 3, 2, 1, 0]
        1 [-2, 0, 2, 4]>

    References:
        https://github.com/orisano/olll/blob/master/olll.py
        https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm
    """
    from samson.math.all import QQ
    Matrix = _mat.Matrix

    # Prepare ring and basis
    if type(in_basis.coeff_ring).__name__ != 'FractionField':
        from samson.math.algebra.fields.fraction_field import FractionField
        R = FractionField(in_basis.coeff_ring)
        in_basis = Matrix([[R(elem) for elem in row] for row in in_basis.rows], coeff_ring=R)

    R     = in_basis.coeff_ring
    basis = deepcopy(in_basis)
    n     = len(basis)

    ortho, _mu = gram_schmidt(in_basis)


    # Prepare parameters
    delta = QQ(delta)
    d_num = int(delta.numerator)
    d_den = int(delta.denominator)
    half  = R((R.ring.one, R.ring.one*2))


    def mu_ij(i, j):
        return ortho[j].proj_coeff(basis[i])

    # Perform LLL
    k = 1
    while k < n:
        for j in reversed(range(k)):
            mu_kj = mu_ij(k, j)

            if abs(mu_kj) > half:
                scalar    = round(mu_kj)
                basis[k] -= basis[j] * scalar


        # Prepare only needed vectors
        # 'o_k' needs to be specially handled since 'gram_schmidt' can remove vectors
        M_k  = ortho[k, :] if len(ortho) >= k+1 else Matrix([[R.zero * in_basis.num_cols]])
        M_k1 = ortho[k-1, :]
        O    = (M_k1 * M_k1.T)[0,0]

        # This should be ring-agnostic
        if (M_k * M_k.T)[0,0] * d_den >= O*d_num - d_den * mu_ij(k, k-1)**2 * O:
            k += 1

        else:
            basis[k], basis[k-1] = copy(basis[k-1]), copy(basis[k])

            # Update ortho
            o = ortho[k] + ortho[k-1].project(basis[k-1])
            p = ortho[k-1] - o.project(basis[k])
            ortho[k-1], ortho[k] = o, p

            k = max(k-1, 1)

    return basis


def generate_superincreasing_seq(length: int, max_diff: int, starting: int=0) -> List[int]:
    """
    Generates a superincreasing sequence.

    Parameters:
        length   (int): Number of elements to generate.
        max_diff (int): Maximum difference between the sum of all elements before and the next element.
        starting (int): Minimum starting integer.

    Returns:
        List[int]: List of the superincreasing sequence.

    Examples:
        >>> from samson.math.general import generate_superincreasing_seq
        >>> generate_superincreasing_seq(10, 2)
        [...]

    """
    seq = []

    last_sum = starting
    for _ in range(length):
        delta = int.from_bytes(rand_bytes(math.ceil(math.log(max_diff, 256))), 'big') % max_diff
        seq.append(last_sum + delta)
        last_sum = sum(seq)

    return seq



def find_coprime(p: int, search_range: List[int]) -> int:
    """
    Attempts to find an integer coprime to `p`.

    Parameters:
        p                  (int): Integer to find coprime for.
        search_range (List[int]): Range to look in.
    
    Returns:
        int: Integer coprime to `p`.
    
    Examples:
        >>> from samson.math.general import find_coprime
        >>> find_coprime(10, range(500, 1000))
        501

    """
    for i in search_range:
        if gcd(p, i) == 1:
            return i



def random_int(n: int) -> int:
    """
    Finds a unbiased, uniformly-random integer between 0 and `n`-1.

    Parameters:
        n (int): Upper bound.

    Returns:
        int: Random integer.

    Example:
        >>> from samson.math.general import random_int
        >>> random_int(1000) < 1000
        True

    """
    n_bits = math.ceil(math.log2(n))

    # This is required for very specific cases where the floating point precision causes a floor such that
    # 2**n_bits < n, which causes an infinite loop
    n_bits += 2**n_bits < n

    byte_length = math.ceil(n_bits / 8)
    max_bit = 2**n_bits
    q = max_bit // n
    max_num = n * q - 1

    while True:
        attempt = int.from_bytes(rand_bytes(byte_length), 'big') % max_bit
        if attempt <= max_num:
            return attempt % n


def random_int_between(a: int, b :int) -> int:
    """
    Finds a unbiased, uniformly-random integer between `a` and `b`-1 (i.e. "[`a`, `b`)").

    Parameters:
        a (int): Lower bound.
        b (int): Upper bound.

    Returns:
        int: Random integer.

    Example:
        >>> from samson.math.general import random_int_between
        >>> n = random_int_between(500, 1000)
        >>> n >= 500 and n < 1000
        True

    """
    return a + random_int(b - a)


def find_prime(bits: int, ensure_halfway: bool=True) -> int:
    """
    Finds a prime of `bits` bits.

    Parameters:
        bits            (int): Bit length of prime.
        ensure_halfway (bool): Ensures the prime is at least halfway into the bitspace to prevent multiplications being one bit short (e.g. 256-bit int * 256-bit int = 511-bit int).

    Returns:
        int: Random prime number.

    Examples:
        >>> from samson.math.general import find_prime
        >>> find_prime(512) < 2**512
        True

    """
    rand_num  = random_int(2**bits)
    rand_num |= 2**(bits - 1)

    if ensure_halfway:
        rand_num |= 2**(bits - 2)

    return next_prime(rand_num)



def next_prime(start_int: int, step: int=2) -> int:
    """
    Finds the next prime.

    Parameters:
        start_int (int): Integer to start search at.
        step      (int): Distance to step forward.

    Returns:
        int: Prime.

    Examples:
        >>> from samson.math.general import next_prime
        >>> next_prime(8)
        11

        >>> next_prime(11+1)
        13

    """
    if start_int < 2:
        return 2

    start_int |= 1
    while not is_prime(start_int):
        start_int += step
        

    return start_int


def primes(start: int, stop: int=None) -> list:
    """
    Generates primes between `start` and `stop`.

    Parameters:
        start (int): Number to start at (inclusive).
        stop  (int): Number to stop at (exclusive).

    Returns:
        list: Primes within the range.
    """
    p = start
    if p < 3:
        yield 2
        p = 2

    while True:
        p = next_prime(p)
        if stop and p >= stop:
            break
        yield p
        p += 2


def _berlekamp_massey_gf2(output_list: List[int]) -> 'Polynomial':
    """
    Performs the Berlekamp-Massey algorithm to find the shortest LFSR for a binary output sequence.

    Parameters:
        output_list (List[int]): Output of LFSR.

    Returns:
        Polynomial: Polyomial that represents the shortest LFSR.

    Examples:
        >>> from samson.prngs.flfsr import FLFSR
        >>> from samson.math.general import berlekamp_massey
        >>> from samson.math.all import Polynomial, ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> _ = (ZZ/ZZ(2))[x]
        >>> lfsr = FLFSR(3, x**25 + x**20 + x**12 + x**8  + 1)
        >>> outputs = [lfsr.generate() for _ in range(50)]
        >>> berlekamp_massey(outputs)
        <Polynomial: x^25 + x^17 + x^13 + x^5 + 1, coeff_ring=ZZ/(ZZ(2))>

    References:
        https://en.wikipedia.org/wiki/Berlekamp%E2%80%93Massey_algorithm
    """
    Polynomial = _poly.Polynomial
    ZZ = _integer_ring.ZZ

    n = len(output_list)
    b = [1] + [0] * (n - 1)
    c = [1] + [0] * (n - 1)

    L = 0
    m = -1

    i  = 0
    while i < n:
        out_vec = output_list[i - L:i][::-1]
        c_vec = c[1:L+i]
        d = output_list[i] + sum([s_x * c_x for s_x, c_x in zip(out_vec, c_vec)]) % 2

        if d == 1:
            t = deepcopy(c)
            p = [0] * n
            for j in range(L):
                if b[j] == 1:
                    p[j + i - m] = 1

            c = [(c_x + p_x) % 2 for c_x, p_x in zip(c, p)]

            if L <= i / 2:
                L = i + 1 - L
                m = i
                b = t

        i += 1

    return Polynomial(c[:L + 1][::-1], coeff_ring=ZZ/ZZ(2))




def berlekamp_massey(output_list: List[int], F: 'Ring'=None):
    """
    Performs the Berlekamp-Massey algorithm to find the shortest linear recurrence.

    Parameters:
        output_list (List[int]): Output of recurrence.

    Returns:
        Polynomial: Polyomial that represents the shortest linear recurrence.

    Examples:
        >>> from samson.prngs.flfsr import FLFSR
        >>> from samson.math.general import berlekamp_massey
        >>> from samson.math.all import Polynomial, ZZ
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> _ = (ZZ/ZZ(2))[x]
        >>> lfsr = FLFSR(3, x**25 + x**20 + x**12 + x**8  + 1)
        >>> outputs = [lfsr.generate() for _ in range(50)]
        >>> berlekamp_massey(outputs)
        <Polynomial: x^25 + x^17 + x^13 + x^5 + 1, coeff_ring=ZZ/(ZZ(2))>

    References:
        https://arxiv.org/pdf/2211.11721.pdf
    """
    ZZ = _integer_ring.ZZ
    Symbol = _symbols.Symbol

    if F == ZZ/ZZ(2):
        return _berlekamp_massey_gf2(output_list)


    x = Symbol('x')
    P = F[x]

    a = [F(o) for o in output_list]
    n = len(a) // 2
    m = 2*n - 1
    R0 = x**(2*n)
    R1 = P([a[m-i] for i in range(m+1)])
    V0 = P.zero
    V1 = P.one

    while n <= R1.degree():
        Q, R = divmod(R0, R1)
        V = V0 - Q*V1
        V0 = V1
        V1 = V
        R0 = R1
        R1 = R
    
    return V1.monic()



def is_power_of_two(n: int) -> bool:
    """
    Determines if `n` is a power of two.

    Parameters:
        n (int): Integer.

    Returns:
        bool: Whether or not `n` is a power of two.

    Examples:
        >>> from samson.math.general import is_power_of_two
        >>> is_power_of_two(7)
        False

        >>> is_power_of_two(8)
        True

    """
    return n != 0 and (n & (n - 1) == 0)


def totient(n: int, factors: dict=None) -> int:
    """
    Calculates Euler's totient of `n`. The totient is the number of elements coprime to `n` that are less than `n`.

    Parameters:
        n        (int): Number to find the totient of.
        factors (dict): Factors of `n`.

    Returns:
        int: Totient of `n`.
    """
    if not factors:
        factors = _factor_gen.factor(n)

    t = 1
    for p, e in factors.items():
        t *= (p-1) * p**(e-1)

    return t



def hasse_frobenius_trace_interval(p: int) -> Tuple[int, int]:
    """
    Finds the interval relative to `p` in which the Frobenius trace must reside according to Hasse's theorem.

    Parameters:
        p (int): Prime of the underlying field of the elliptic curve.

    Returns:
        (int, int): Start and end ranges of the interval relative to `p`.

    Examples:
        >>> from samson.math.general import hasse_frobenius_trace_interval
        >>> hasse_frobenius_trace_interval(53)
        (-16, 17)

    """
    l = 2 * math.ceil(math.sqrt(p))
    return (-l , l + 1)


def sieve_of_eratosthenes(n: int) -> list:
    """
    Finds all primes up to `n`.
 
    Parameters:
        n (int): Limit.

    Returns:
        list: List of prime numbers.

    Examples:
        >>> from samson.math.general import sieve_of_eratosthenes
        >>> list(sieve_of_eratosthenes(100))
        [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    References:
        https://stackoverflow.com/questions/2068372/fastest-way-to-list-all-primes-below-n/3035188#3035188
    """
    n, correction = n-n%6+6, 2-(n%6>1)
    sieve = [True] * (n//3)
    for i in range(1,int(n**0.5)//3+1):
      if sieve[i]:
        k=3*i+1|1
        sieve[      k*k//3      ::2*k] = [False] * ((n//6-k*k//6-1)//k+1)
        sieve[k*(k-2*(i&1)+4)//3::2*k] = [False] * ((n//6-k*(k-2*(i&1)+4)//6-1)//k+1)
    return [2,3] + [3*i+1|1 for i in range(1,n//3-correction) if sieve[i]]


SIEVE_BASE = set(sieve_of_eratosthenes(2**20))

def sieve_of_eratosthenes_lazy(n: int, chunk_size: int=1024, prime_base: set=None) -> list:
    """
    Finds all primes up to `n`.
 
    Parameters:
        n          (int): Limit.
        chunk_size (int): Size of internal lists.
        prime_base (set): Initial set of primes to sieve against.

    Returns:
        generator: Generator of prime numbers.

    Examples:
        >>> from samson.math.general import sieve_of_eratosthenes
        >>> list(sieve_of_eratosthenes(100))
        [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]

    """
    n_2 = n // 2
    k   = kth_root(n, 2)

    # Allow preloading, but remove 2 since it's intrinsically removed
    if not prime_base:
        prime_base = SIEVE_BASE.difference({2})

    # Generate what's in prime_base first
    for p in {2}.union(prime_base):
        if p < n:
            yield p
        else:
            return

    # Chunk the space, but don't redo a chunk the prime_base fully covers
    for chunk in range(len(list(prime_base)) // chunk_size, math.ceil(n_2 / chunk_size)):
        true_idx  = chunk * chunk_size
        true_size = min(n_2 - true_idx, chunk_size)

        # Remove 1
        A = [true_idx != 0] + [True] * (true_size-1)

        # Remove all indices based on prime base
        for p in prime_base:
            for j in range(p - true_idx*2 % (p*2), true_size*2, p*2):
                if j < 0:
                    continue
                A[j//2] = False


        # Mark off multiples of new primes
        # Don't need to if true_idx > k
        if true_idx < k:
            for i in range(2 if not true_idx else 0, true_size, 2):
                true_i = i+true_idx*2+1

                if true_size > (true_i // 2) and A[true_i//2]:
                    for j in range(true_i**2 // 2, true_size, true_i):
                        A[j] = False

        # Add to prime base
        new_primes = {(idx + true_idx)*2+1 for idx, is_prime in enumerate(A) if is_prime}
        for p in new_primes:
            yield p

        prime_base = prime_base.union(new_primes)



def primes_product(n: int, blacklist: list=None) -> list:
    """
    Returns a list of small primes whose product is greater than or equal to `n`.

    Parameters:
        n          (int): Product to find.
        blacklist (list): Primes to skip.

    Returns:
        list: List of primes.

    Examples:
        >>> from samson.math.general import primes_product
        >>> primes_product(100, [2])
        [7, 5, 3]

    """
    total     = 1
    primes    = []
    blacklist = blacklist if blacklist else []

    for prime in sieve_of_eratosthenes(n.bit_length()*2+1):
        if total >= n:

            # We might be able to remove some of the large primes
            primes.reverse()
            needed_primes = []
            for prime in primes:
                if total // prime >= n:
                    total //= prime
                else:
                    needed_primes.append(prime)

            return needed_primes

        if prime not in blacklist:
            primes.append(prime)
            total *= prime



def find_representative(quotient_element: 'QuotientElement', valid_range: range) -> int:
    """
    Finds the representative element of `quotient_element` within `valid_range`.

    Parameters:
        quotient_element (QuotientElement): Element to search for.
        valid_range                (range): Range to search in.

    Returns:
        int: Representative element.

    Examples:
        >>> from samson.math.all import *
        >>> find_representative((ZZ/ZZ(11))(3), range(11, 22))
        14

    """
    if type(quotient_element) is tuple:
        remainder, modulus = quotient_element
    else:
        remainder = int(quotient_element)
        modulus   = int(quotient_element.ring.quotient)

    if type(valid_range) is range:
        start, end = valid_range.start, valid_range.stop
    else:
        start, end = valid_range

    if (end-start) > modulus:
        raise ValueError("Solution not unique")

    q, r = divmod(valid_range[0], modulus)
    shifted_start, shifted_end = (r, r + (end-start))

    if shifted_start < remainder < shifted_end:
        return q * modulus + remainder

    elif shifted_start < (remainder + modulus) < shifted_end:
        return (q+1) * modulus + remainder

    else:
        raise ValueError("No solution")



def __fast_double_elliptic_frobenius(T, curve, point):
    p_x, p_y = point.x, point.y
    Q = p_y.numerator.ring
    P = Q.ring.poly_ring
    g = Q.quotient.x_poly
    monomials = frobenius_monomial_base(g)

    Z  = Q(curve.defining_polynomial())**((curve.p-1)//2)
    Yq = Z*p_y

    def frobenius(f):
        num = frobenius_map(f.numerator.val.x_poly, g, bases=monomials)
        den = frobenius_map(f.denominator.val.x_poly, g, bases=monomials)
        return T((num, den))

    def compose(f, h):
        num = Q(P(f.numerator.val.x_poly.modular_composition(h.numerator.val.x_poly, g)))
        den = Q(P(f.denominator.val.x_poly.modular_composition(h.denominator.val.x_poly, g)))
        return T((num, den))

    Xq  = frobenius(p_x)
    Xq2 = frobenius(Xq)
    Yq2 = Yq * compose(T(Z), Xq)

    return point.__class__(x=Xq, y=Yq, curve=point.curve), point.__class__(x=Xq2, y=Yq2, curve=point.curve)



def frobenius_trace_mod_l(curve: 'EllipticCurve', l: int) -> 'QuotientElement':
    """
    Finds the Frobenius trace modulo `l` for faster computation.

    Parameters:
        curve (EllipticCurve): Elliptic curve.
        l               (int): Prime modulus.

    Returns:
        QuotientElement: Modular residue of the Frobenius trace.

    References:
        "Fast algorithms for computing the eigenvalue in the Schoof-Elkies-Atkin algorithm" (https://hal.inria.fr/inria-00001009/document)
    """
    EllipticCurve = _ell_curve.EllipticCurve
    from samson.math.algebra.fields.fraction_field import FractionField as Frac
    from samson.math.algebra.curves.sea import elkies_trace_mod_l
    try:
        if not is_prime(l):
            raise NoSolutionException

        return elkies_trace_mod_l(curve, l)

    except NoSolutionException:
        ZZ = _integer_ring.ZZ

        torsion_quotient_ring = ZZ/ZZ(l)
        psi = curve.division_poly(l)
        psi.x_poly.cache_div(psi.x_poly.degree()*2)

        # Build symbolic torsion group
        R = psi.ring
        S = R/psi
        T = Frac(S, simplify=False)
        sym_curve = EllipticCurve(a=T([curve.a]), b=T([curve.b]), ring=T, check_singularity=False)

        x = R.poly_ring.symbol

        p_x = T(R((x, 0)))
        p_y = T(R((0, 1)))

        point = sym_curve(p_x, p_y, verify=False)

        # Generate symbolic points
        if l < 40:
            p1, p2 = __fast_double_elliptic_frobenius(T, curve, point)
        else:
            F  = sym_curve.frobenius_endomorphism()
            p1 = F(point)
            p2 = F(p1)

        determinant = (curve.p % l) * point

        point_sum = determinant + p2

        # Find trace residue
        if point_sum == sym_curve.POINT_AT_INFINITY:
            return torsion_quotient_ring(0)


        trace_point = p1
        for candidate in range(1, (l + 1) // 2):
            if point_sum.x == trace_point.x:
                if point_sum.y == trace_point.y:
                    return torsion_quotient_ring(candidate)
                else:
                    return torsion_quotient_ring(-candidate)
            else:
                trace_point += p1

        raise ArithmeticError("No trace candidate satisfied the Frobenius equation")



def frobenius_trace(curve: 'EllipticCurve') -> int:
    """
    Calculates the Frobenius trace of the `curve`.

    Parameters:
        curve (EllipticCurve): Elliptic curve.

    Returns:
        int: Frobenius trace.

    Examples:
        >>> from samson.math.general import frobenius_trace
        >>> from samson.math.algebra.all import *

        >>> ring = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> frobenius_trace(curve)
        -3

    """
    Symbol = _symbols.Symbol
    ZZ = _integer_ring.ZZ

    search_range      = hasse_frobenius_trace_interval(curve.p)
    torsion_primes    = primes_product(search_range[1] - search_range[0], [curve.ring.characteristic()])
    trace_congruences = []

    # Handle 2 separately to prevent multivariate poly arithmetic
    if 2 in torsion_primes:
        x = Symbol('x')
        _ = curve.ring[x]

        defining_poly = curve.defining_polynomial()
        bases         = frobenius_monomial_base(defining_poly)
        rational_char = bases[1]
        rational_char = frobenius_map(rational_char, defining_poly, bases=bases)

        if gcd(rational_char - x, defining_poly).degree() == 0:
            trace_congruences.append((ZZ/ZZ(2))(1))
        else:
            trace_congruences.append((ZZ/ZZ(2))(0))

        torsion_primes.remove(2)


    for l in torsion_primes:
        trace_congruences.append(frobenius_trace_mod_l(curve, l))

    n, mod = crt(trace_congruences)
    return find_representative((ZZ/ZZ(mod))(n), range(*search_range))


def schoofs_algorithm(curve: 'EllipticCurve') -> int:
    """
    Performs Schoof's algorithm to count the number of points on an elliptic curve.

    Parameters:
        curve (EllipticCurve): Elliptic curve to find cardinality of.

    Returns:
        int: Curve cardinality.

    Examples:
        >>> from samson.math.general import schoofs_algorithm
        >>> from samson.math.algebra.all import *

        >>> ring = ZZ/ZZ(53)
        >>> curve = WeierstrassCurve(a=50, b=7, ring=ring, base_tuple=(34, 25))
        >>> schoofs_algorithm(curve)
        57

    """
    return curve.p + 1 - frobenius_trace(curve)



class ProofMethod(Enum):
    EXHAUSTIVE     = 0
    ECPP           = 1
    LUCAS_LEHMER   = 2
    MILLER_RABIN   = 3
    LUCAS_SEQUENCE = 4
    PRATT          = 5
    POCKLINGTON    = 6


class PrimalityCertficate(BaseObject):
    def __init__(self, n: int, is_prime: bool, method: ProofMethod, proof: dict=None) -> None:
        self.n        = n
        self.is_prime = is_prime
        self.method   = method
        self.proof    = proof


    def __bool__(self):
        return self.is_prime


def miller_rabin(n: int, k: int=64, bases: list=None) -> bool:
    """
    Probabilistic primality test. Each iteration has a 1/4 false positive rate.

    Parameters:
        n (int): Number to determine if probably prime.
        k (int): Number of iterations to run.

    Returns:
        bool: Whether `n` is probably prime.

    Examples:
        >>> from samson.math.general import miller_rabin
        >>> miller_rabin(127)
        True

        >>> bool(miller_rabin(6))
        False

    References:
        https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test#Miller%E2%80%93Rabin_test
    """
    n_1 = n - 1
    d   = n_1
    r   = 0

    while not d % 2 and d:
        r += 1
        d //= 2

    if not bases:
        def generator():
            for _ in range(k):
                yield random_int_between(2, n_1)

        bases = generator()


    certificate = PrimalityCertficate(n=n, is_prime=False, method=ProofMethod.MILLER_RABIN)

    for a in bases:
        x = pow(a, d, n)
        if x == 1 or x == n_1:
            continue

        found = False
        for _ in range(r-1):
            x = pow(x, 2, n)
            if x == n_1:
                found = True
                break

        if not found:
            certificate.proof = {'witness': a}
            return certificate

    return True


_FB_LARGE_MOD = 3989930175
def is_square(n: int, heuristic_only: bool=False) -> bool:
    """
    Determines if `n` is a square using "fenderbender" tests first.

    Parameters:
        n               (int): Number to test.
        heuristic_only (bool): Whether or not to only use heuristic tests and not validate.

    Returns:
        bool: Whether or not `n` is a square.

    Examples:
        >>> from samson.math.general import is_square
        >>> p = 18431211066281663581
        >>> is_square(p**2)
        True

        >>> is_square(6)
        False

    References:
        https://mersenneforum.org/showpost.php?p=110896
    """
    if n in [0, 1]:
        return True

    m = n % 128
    if ((m*0x8bc40d7d) & (m*0xa1e2f5d1) & 0x14020a):
        return False

    n_mod = n % _FB_LARGE_MOD

    m = n_mod % 63
    if ((m*0x3d491df7) & (m*0xc824a9f9) & 0x10f14008):
        return False

    m = n_mod % 25
    if ((m*0x1929fc1b) & (m*0x4c9ea3b2) & 0x51001005):
         return False

    if heuristic_only:
        return n % 10 not in {2,3,7,8}

    return kth_root(n, 2)**2 == n


def jacobi_symbol(n: int, k: int) -> ResidueSymbol:
    """
    Generalization of the Legendre symbol.

    Parameters:
        n (int): Possible quadatric residue.
        k (int): Modulus (must be odd).

    Returns:
        ResidueSymbol: Jacobi symbol.

    Examples:
        >>> from samson.math.general import jacobi_symbol
        >>> jacobi_symbol(4, 7)
        <ResidueSymbol.EXISTS: 1>

        >>> jacobi_symbol(5, 7)
        <ResidueSymbol.DOES_NOT_EXIST: -1>

    References:
        https://en.wikipedia.org/wiki/Jacobi_symbol
    """
    assert k > 0 and k % 2 == 1
    n %= k
    t = 1

    while n != 0:
        while n % 2 == 0:
            n //= 2
            r = k % 8

            if r in [3, 5]:
                t = -t

        n, k = k, n
        if n % 4 == 3 and k % 4 == 3:
            t = -t

        n %= k

    if k == 1:
        return ResidueSymbol(t)
    else:
        return ResidueSymbol(0)


def generate_lucas_selfridge_parameters(n: int) -> Tuple[int, int, int]:
    """
    Generates the Selfridge parameters to use in Lucas strong pseudoprime testing.

    Parameters:
        n (int): Possible prime.

    Returns:
        Tuple[int, int, int]: Selfridge parameters.
    """
    D = 5
    while True:
        g = gcd(abs(D), n)
        if g > 1 and g != n:
            return (0, 0, g)

        if jacobi_symbol(D, n) == ResidueSymbol.DOES_NOT_EXIST:
            break

        if D > 0:
            D = -D - 2
        else:
            D = -D + 2

    return (D, 1, (1-D) // 4)


def generate_lucas_sequence(n: int, P: int, Q: int, k: int) -> Tuple[int, int, int]:
    """
    Generates a Lucas sequence. Used internally for the Lucas primality test.

    References:
        https://docs.sympy.org/latest/_modules/sympy/ntheory/primetest.html#isprime
    """
    D = P**2 - 4*Q

    assert n > 1
    assert k >= 0
    assert D != 0

    if k == 0:
        return (0, 2, Q)

    U  = 1
    V  = P
    Qk = Q
    b  = k.bit_length()

    while b > 1:
        U = U*V % n
        V = (V*V - 2*Qk) % n
        Qk *= Qk
        b  -= 1

        if (k >> (b - 1)) & 1:
            U, V = U*P + V, V*P + U*D

            if U & 1:
                U += n

            if V & 1:
                V += n

            U >>= 1
            V >>= 1
            Qk *= Q

        Qk %= n

    return (U % n, V % n, Qk)


def is_strong_lucas_pseudoprime(n: int) -> bool:
    """
    Determines if `n` is at least a strong Lucas pseudoprime.

    Parameters:
        n (int): Integer to test.

    Returns:
        bool: Whether or not `n` is at least a strong Lucas pseudoprime.

    Examples:
        >>> from samson.math.general import is_strong_lucas_pseudoprime
        >>> is_strong_lucas_pseudoprime(299360470275914662072095298694855259241)
        True

        >>> is_strong_lucas_pseudoprime(128)
        False

    """
    certificate = PrimalityCertficate(n=n, is_prime=False, method=ProofMethod.LUCAS_SEQUENCE)

    if n == 2:
        return True

    if n < 2 or n % 2 == 0 or is_square(n):
        return False

    D, P, Q = generate_lucas_selfridge_parameters(n)
    if D == 0:
        certificate.proof = {'divisor': Q}
        return certificate

    s    = 0
    q, r = divmod(n+1, 2)
    k    = q
    while q and not r:
        k    = q
        s   += 1
        q, r = divmod(q, 2)

    U, V, Qk = generate_lucas_sequence(n, P, Q, k)
    if U == 0 or V == 0:
        return True

    for _ in range(s):
        V = (V**2 - 2*Qk) % n

        if V == 0:
            return True

        Qk = pow(Qk, 2, n)

    certificate.proof = {'witness': (P, Q)}
    return certificate


PRIMES_UNDER_1000 = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997}
EXHAUSTIVE_PRIMALITY_PROOF_LIMIT = 35

def exhaustive_primality_proof(N: int) -> bool:
    """
    Proves whether or not `N` is prime by exhaustively testing for divisors.

    Parameters:
        N (int): Integer to test.

    Returns:
        bool: Whether or not `N` is prime.
    """
    certificate = PrimalityCertficate(n=N, is_prime=True, method=ProofMethod.EXHAUSTIVE)

    if N in PRIMES_UNDER_1000:
        return certificate

    for p in sieve_of_eratosthenes(kth_root(N+1, 2)):
        if not N % p:
            certificate.is_prime = False
            certificate.proof    = {'divisor': p}
            return certificate

    return certificate


def generate_pocklington_prime(n: int):
    if n < EXHAUSTIVE_PRIMALITY_PROOF_LIMIT:
        p = find_prime(n)
        return p, is_prime(p, True)

    ZZ   = _integer_ring.ZZ
    base = 2*3*5*7
    p1_s = n // 2
    p2_s = (n-1) - p1_s - base.bit_length()

    if n >= 64:
        p1, p1p = generate_pocklington_prime(p1_s)

    while True:
        if n < 64:
            p1, p1p = generate_pocklington_prime(p1_s)
        p2 = find_prime(p2_s)

        r = p1*base
        h = p2

        # Pad with 2's to get desired bit length
        add_twos = n - (r*h).bit_length()
        r *= 2**add_twos
        
        p = r*h+1

        if is_prime(p):
            R = (ZZ/ZZ(p)).mul_group()
            R._order_factor_cache = _factors.Factors({2:1+add_twos, 3:1, 5:1, 7:1, p1: 1, p2: 1})

            g = R.find_gen()

            if g*(r*h) == R.one and r >= h:
                return p, PrimalityCertficate(n=p, is_prime=True, method=ProofMethod.POCKLINGTON, proof={"g": g, "factors": R._order_factor_cache, "p1p": p1p})


def ecpp(N: int, recursive: bool=True) -> bool:
    """
    Uses Atkin-Morain Elliptic curve primality proving to prove whether or not `N` is prime.

    Parameters:
        N          (int): Integer to test.
        recursive (bool): Whether or not to recursively test all used primes.

    Returns:
        bool: Whether or not `N` is prime.

    References:
        https://en.wikipedia.org/wiki/Elliptic_curve_primality#Atkin%E2%80%93Morain_elliptic_curve_primality_test_(ECPP)
    """
    EllipticCurve = _ell_curve.EllipticCurve
    ZZ = _integer_ring.ZZ
    factor = _factor_gen.factor

    class_one_Ds = [-3, -4, -7, -8, -11, -12, -16, -19, -27, -28, -43, -67, -163]
    R = ZZ/ZZ(N)

    certificate = PrimalityCertficate(n=N, is_prime=False, method=ProofMethod.ECPP)

    for d in class_one_Ds:
        if gcd(N, -d) == 1 and R(d).is_square():
            try:
                E = EllipticCurve.generate_curve_with_D(d, R)

                try:
                    Eo = E.order()
                except SearchspaceExhaustedException:
                    from samson.math.algebra.curves.util import EllipticCurveCardAlg
                    if N.bit_length() > 48:
                        raise RuntimeError(f'ECPP point counting fell back to bruteforce, but {N} ({N.bit_length()}) is too large')

                    Eo = E.cardinality(EllipticCurveCardAlg.BRUTE_FORCE)

                # Find a divisor above the bound
                bound    = (kth_root(N, 4)+1)**2
                m_facs   = factor(Eo)#, user_stop_func=lambda n, facs: facs.recombine() > bound)
                divisors = list(m_facs.divisors())
                divisors.sort()

                for d in divisors[1:]:
                    if d > bound:
                        break


                if d == Eo and is_prime(d):
                    continue

                # We do this because it only uses trial division internally
                d_facs = m_facs/(m_facs/d)
                P = E.find_gen()
                if P.order() < d:
                    continue

                proof = {'P': P, 'd': d, 'p_proofs': []}

                for p, e in d_facs.items():
                    p_proof = is_prime(p, True)
                    proof['p_proofs'].append(p_proof)

                    if recursive and not p_proof:
                        raise RuntimeError(f'Unexpected ECPP error. {p} is not a prime, so factorization has failed')

                    if not P*p**e:
                        certificate.proof = proof
                        return certificate


                certificate.proof    = proof
                certificate.is_prime = True
                return certificate

            except NoSolutionException:
                pass
            except NotInvertibleException as e:
                res = gcd(e.parameters['a'], N)
                certificate.proof = {'divisor': res}
                return certificate

    raise RuntimeError(f'No suitable discriminant found for ECPP over {N}')


def lucas_lehmer_test(n: int) -> bool:
    """
    Provably determines whether a Mersenne number `n` is prime.

    Parameters:
        n (int): Mersenne number to test.

    Returns:
        bool: Whether or not `n` is prime.

    References:
        https://en.wikipedia.org/wiki/Lucas%E2%80%93Lehmer_primality_test
    """
    assert is_power_of_two(n+1)

    certificate = PrimalityCertficate(n=n, is_prime=False, method=ProofMethod.LUCAS_LEHMER)

    k = n.bit_length()
    k_proof = is_prime(k, prove=True)

    certificate.proof = {'k_proof': k_proof}
    if not k_proof:
        return certificate

    if n == 3:
        certificate.is_prime = True
        return certificate

    s = 4
    for _ in range(k-2):
        s = ((s*s)-2) % n

    certificate.is_prime = s == 0
    return certificate



def __find_small_divisor(n: int) -> int:
    certificate = PrimalityCertficate(n=n, is_prime=False, method=ProofMethod.EXHAUSTIVE)

    if n in PRIMES_UNDER_1000:
        certificate.is_prime = True
        return certificate

    for prime in PRIMES_UNDER_1000:
        if (n % prime) == 0:
            certificate.proof = {'divisor': prime}
            return certificate


def pratt(n: int) -> PrimalityCertficate:
    """
    Proves whether or not `n` is prime. Note, this is quite slow for composites.

    Parameters:
        n (int): Number to test.

    Returns:
        PrimalityCertficate: Proof of whether or not `n` is prime.
    """
    ZZ = _integer_ring.ZZ
    n1_facs = _factor_gen.factor(n-1)
    R  = ZZ/ZZ(n)
    Rm = R.mul_group()
    g  = Rm.find_gen()

    certificate = PrimalityCertficate(n=n, is_prime=g.order() == n-1, method=ProofMethod.PRATT, proof={'g': g, 'factors': {p:is_prime(p, True) for p in n1_facs}})

    return certificate



def is_prime(n: int, prove: bool=False) -> bool:
    """
    Determines if `n` is probably prime using the Baillie-PSW primality test if `prove` is False.
    Otherwise, a combination of ECPP, Lucas-Lehmer, Pratt, and exhaustive testing is used.

    Parameters:
        n      (int): Positive integer.
        prove (bool): Whether or not to prove `n` is prime.

    Returns:
        bool: Whether or not `n` is probably prime.

    Examples:
        >>> from samson.math.general import is_prime, find_prime
        >>> is_prime(7)
        <PrimalityCertficate: n=7, is_prime=True, method=ProofMethod.LUCAS_LEHMER, proof={'k_proof': <PrimalityCertficate: n=3, is_prime=True, method=ProofMethod.LUCAS_LEHMER, proof={'k_proof': <PrimalityCertficate: n=2, is_prime=True, method=ProofMethod.EXHAUSTIVE, proof=None>}>}>

        >>> bool(is_prime(15))
        False

        >>> bool(is_prime(find_prime(32)))
        True

    References:
        https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test
    """
    if n < 2:
        return False

    if is_power_of_two(n+1):
        return lucas_lehmer_test(n)

    if prove:
        if n.bit_length() < EXHAUSTIVE_PRIMALITY_PROOF_LIMIT:
            return exhaustive_primality_proof(n)

        else:
            # Attempt to prove composite (fast)
            proof = is_prime(n, prove=False)
            if not proof:
                return proof


            # Speed found in testing. Pratt may be even faster with msieve installed
            if n.bit_length() < 111:
                return pratt(n)
            else:
                try:
                    return ecpp(n)
                except RuntimeError:
                    return pratt(n)

    else:
        proof = __find_small_divisor(n)
        if proof is not None:
            return proof

        mill = miller_rabin(n, bases=[2])
        if not mill:
            return mill

        return is_strong_lucas_pseudoprime(n)


def is_primitive_root(a: int, p: int) -> bool:
    """
    Returns whether or not `a` is a primitive root in ZZ/ZZ(p)*.
    `a` is a primitive root of `p` if `a` is the smallest integer such that `a`'s order is the order of the ring.

    Parameters:
        a (int): Possible primitive root.
        p (int): Modulus.

    Returns:
        bool: Whether or not `a` is a primitive root.

    Examples:
        >>> from samson.math.general import is_primitive_root
        >>> is_primitive_root(3, 10)
        True

        >>> is_primitive_root(9, 10)
        False

        >>> is_primitive_root(45, 2)
        True

        >>> is_primitive_root(208, 3)
        False

        >>> is_primitive_root(120, 173)
        True

    """
    ZZ = _integer_ring.ZZ

    Z_star = (ZZ/ZZ(p)).mul_group()
    a_star = Z_star(a)

    return gcd(a, p) == 1 and a_star*Z_star.order() == Z_star.one and a_star.order() == Z_star.order()



def product(elem_list: List['RingElement'], return_tree: bool=False) -> 'RingElement':
    """
    Calculates the product of all elements in `elem_list`.

    Parameters:
        elem_list   (list): List of RingElements.
        return_tree (bool): Whether or not to return the intermediate tree results.

    Returns:
        RingElement: Product of all RingElements.

    Examples:
        >>> from samson.math.general import product
        >>> from samson.math.all import ZZ
        >>> product([ZZ(1), ZZ(2), ZZ(3)])
        <IntegerElement: val=6, ring=ZZ>

        >>> product([ZZ(1), ZZ(2), ZZ(3)], True)
        [[<IntegerElement: val=1, ring=ZZ>, <IntegerElement: val=2, ring=ZZ>, <IntegerElement: val=3, ring=ZZ>, <IntegerElement: val=1, ring=ZZ>], [<IntegerElement: val=2, ring=ZZ>, <IntegerElement: val=3, ring=ZZ>], [<IntegerElement: val=6, ring=ZZ>]]

    References:
        https://facthacks.cr.yp.to/product.html
    """
    X = list(elem_list)
    if len(X) == 0: return 1
    X_type = type(X[0])

    tree = [X]
    one  = 1 if X_type is int else X[0].ring.one

    while len(X) > 1:
        if len(X) % 2:
            X.append(one)

        X = [X_type.__mul__(*X[i*2:(i+1)*2]) for i in range(len(X) // 2)]

        if return_tree:
            tree.append(X)

    return tree if return_tree else X[0]



def batch_gcd(elem_list: List['RingElement']) -> List['RingElement']:
    """
    Calculates the greatest common divisors of any two elements in `elem_list`.

    Parameters:
        elem_list (List[RingElement]): List of RingElements.

    Returns:
        List[RingElement]: Greatest common divisors of any two elements.

    Examples:
        >>> from samson.math.general import batch_gcd
        >>> batch_gcd([1909, 2923, 291, 205, 989, 62, 451, 1943, 1079, 2419])
        [1909, 1, 1, 41, 23, 1, 41, 1, 83, 41]

    References:
        https://facthacks.cr.yp.to/batchgcd.html
    """
    prods = product(elem_list, True)
    R = prods.pop()
    while prods:
        elem_list = prods.pop()
        R         = [R[i // 2] % elem_list[i]**2 for i in range(len(elem_list))]

    return [gcd(r // n, n) for r, n in zip(R, elem_list)]



def smoothness(n: int, factors: dict=None, **factor_kwargs) -> float:
    """
    Calculates the smoothness of an integer `n` as a ratio of the number of non-trivial factors to the number of bits.
    Thus, primes are 0% smooth and 2**n is 100% smooth.

    Parameters:
        n        (int): Integer to analyze.
        factors (dict): Factors of `n`.

    Returns:
        float: Smoothness ratio.

    Examples:
        >>> from samson.math.general import smoothness, is_prime
        >>> p = 211
        >>> assert is_prime(p)
        >>> smoothness(p)
        0.0

        >>> smoothness(p-1)
        0.5185212203629948

    """
    if not factors:
        if not factor_kwargs:
            factor_kwargs = {"use_rho": False}

        factors = _factor_gen.factor(n, **factor_kwargs)

    # 'factors' will return {n: 1} if `n` is prime
    # Just early-out since there will be zero non-trivials anyway
    if n in factors:
        return 0.0

    return (sum(factors.values())) / math.log(n, 2)



def is_safe_prime(p: int) -> bool:
    """
    Determines if `p` is a safe prime.

    Parameters:
        p (int): Prime to analyze.

    Returns:
        bool: Whether `p` is a safe prime.

    Examples:
        >>> from samson.math.general import is_safe_prime
        >>> from samson.protocols.diffie_hellman import DiffieHellman
        >>> is_safe_prime(DiffieHellman.MODP_2048)
        True

    """
    q, r = divmod(p-1, 2)
    return not r and is_prime(q) and is_prime(p)


def is_sophie_germain_prime(p: int) -> bool:
    """
    Determines if `p` is a Sophie Germain prime.

    Parameters:
        p (int): Prime to analyze.

    Returns:
        bool: Whether `p` is a Sophie Germain prime.

    Examples:
        >>> from samson.math.general import is_sophie_germain_prime
        >>> from samson.protocols.diffie_hellman import DiffieHellman
        >>> is_sophie_germain_prime((DiffieHellman.MODP_2048-1)//2)
        True

    """
    return is_prime(2*p+1)


def is_carmichael_number(n: int, factors: dict=None) -> bool:
    """
    Determines if `n` is a Carmichael number. A Carmichael number is a composite number that
    passes the Fermat primality test for all bases coprime to it.

    Parameters:
        n        (int): Integer.
        factors (dict): Factors of `n`.

    Returns:
        bool: Whether or not `n` is a Carmichael number.

    References:
        https://en.wikipedia.org/wiki/Carmichael_number#Korselt's_criterion
    """
    factors = factors or _factor_gen.factor(n, reraise_interrupt=True)


    if max(factors.values()) > 1 or len(factors) == 1:
        return False

    return not any((n-1) % (p-1) for p in factors)



def find_carmichael_number(min_bits: int=None, k: int=None) -> int:
    """
    Finds a Carmichael number with a size of `min_bits` or initialized with `k`.

    Parameters:
        min_bits (int): Minimum size of number to find.
        k        (int): Looping multiplier.

    References:
        https://en.wikipedia.org/wiki/Carmichael_number#Discovery
    """
    if min_bits:
        if min_bits < 11:
            min_bits = 11

        # Take into account `k` three times and 6*12*18 is 11 bits
        k = 2**((min_bits-11)//3)

    while True:
        a = 6*k+1
        b = 12*k+1
        c = 18*k+1

        if (a*b*c).bit_length() >= min_bits and all(is_prime(elem) for elem in [a, b, c]):
            return a*b*c, (a, b, c)

        k += 1



def carmichael_function(n: int, factors: dict=None) -> int:
    """
    Finds the smallest positive integer `m` such that `a^m = 1 (mod n)`.

    Parameters:
        n        (int): Modulus.
        factors (dict): Factors of `n`.

    Returns:
        int: The least universal exponent.

    References:
        https://en.wikipedia.org/wiki/Carmichael_function
    """
    if not factors:
        factors = _factor_gen.factor(n)

    result = 1
    for p, e in factors.items():
        a = totient(0, {p: e})
        if p == 2 and e > 2:
            a //= 2

        result = lcm(result, a)

    return result


def coppersmiths(N: int, f: 'Polynomial', beta: float=1, epsilon: float=None, X: int=None, m: int=None, t: int=None) -> list:
    """
    Finds small roots of a polynomial in `ZZ`/`ZZ`(`N`) using Coppersmith's method.

    Parameters:
        N         (int): Modulus.
        f  (Polynomial): Polynomial to find roots of.
        beta    (float): Tweaks the size of the roots we look for in the polynomial. (Roots mod `b`, where `b` > `N`^`beta`)
        epsilon (float): Tweaks the size of the matrix.
        X         (int): Absolute bound for roots.
        m         (int): Tweaks number of columns.
        t         (int): Tweaks number of rows.

    Returns:
        list: List of small roots in Zn[x].

    References:
        https://github.com/sagemath/sage/blob/develop/src/sage/rings/polynomial/polynomial_modn_dense_ntl.pyx#L401
        "Finding Small Solutions to Small Degree Polynomials" (http://cr.yp.to/bib/2001/coppersmith.pdf)
    """
    ZZ = _integer_ring.ZZ
    Matrix = _mat.Matrix

    d = f.degree()
    x = f.symbol

    if not epsilon:
        epsilon = beta/8


    m = m or math.ceil(max(beta**2/(d*epsilon), 7*beta/d))
    t = t or int(d*m * (1/beta - 1))

    if not X:
        X = math.ceil(0.5 * N**(beta**2/d - epsilon))

    g = [x**j * N**(m-i) * f**i for i in range(m) for j in range(d)]
    g.extend([x**i * f**m for i in range(t)])

    # Build the problem matrix
    B = Matrix.fill(ZZ.zero, len(g), d*m + max(d, t))
    for i in range(len(g)):
        for j in range(g[i].degree()+1):
            B[i,j] = (g[i].coeffs[j]*X**j)


    # Solve the problem matrix
    B = Matrix(B, ZZ).LLL()
    k = sum([x**i*ZZ(B[0, i] // X**i) for i in range(B.num_cols)])

    R     = k.roots()
    Zn    = ZZ/ZZ(N)
    roots = set(Zn(r) for r in R if abs(r) <= X)
    Nb    = N**beta
    return [root for root in roots if gcd(N, root) >= Nb]


def __get_log_precision(n: int):
    RR = _real_field.RR
    RealField = _real_field.RealField

    # Determine required precision
    z     = RR(n)
    prec  = z.log()*z
    prec  = prec.log(10).ceil()
    prec *= RR(10).log(2)
    prec  = int(prec)+5

    return RealField(prec)


def prime_number_theorem(n: int, use_heuristic: bool=False) -> int:
    """
    Approximates the number of primes less than `n`.

    Parameters:
        n              (int): Maximum bound.
        use_heuristic (bool): Whether to use the fast heuristic.

    Returns:
        int: Approximate number of primes less than `n`.

    References:
        https://en.wikipedia.org/wiki/Prime_number_theorem
    """
    # The simple version is generally more accurate for `n` < 3000 (empirically)
    if n < 3000 or use_heuristic:
        return n // math.floor(math.log(n))
    else:
        RR = __get_log_precision(n)
        return int(round(RR(n).li(offset=True)))


pnt = prime_number_theorem


def approximate_nth_prime(n: int) -> int:
    """
    Approximates the `n`-th prime using the prime number theorem.

    Parameters:
        n (int): Which prime to approxmiate.

    Returns:
        int: Approximation of the prime.

    References:
        https://en.wikipedia.org/wiki/Prime_number_theorem#Approximations_for_the_nth_prime_number
    """
    RR_high = __get_log_precision(n)
    n       = RR_high(n)
    logn    = n.log()
    llogn   = logn.log()

    b = logn + llogn - 1 + (llogn-2)/logn - (llogn**2-6*llogn+11)/(2*logn**2)
    return int(round(n*b))


def estimate_L_complexity(a, c, n):
    return math.e**(c*math.log(n)**a * (math.log(math.log(n)))**(1-a))


def __base_math_func(name, *args):
    y = args[0]
    if type(y) in (int, float):
        return getattr(math, name)(*args)
    else:
        return getattr(y, name)(*args[1:])
    


def log(y: 'RingElement', base: 'RingElement') -> int:
    """
    Computes the logarithm of `y` to `base`.

    Parameters:
        base (RingElement): Base.

    Returns:
        int: `x` such that `base`^`x` == `y`.
    """
    return __base_math_func('log', y, base)


def ceil(x):
    return __base_math_func('ceil', x)

def log1p(x):
    return __base_math_func('log1p', x)

def sin(x):
    return __base_math_func('sin', x)

def cos(x):
    return __base_math_func('cos', x)

def tan(x):
    return __base_math_func('tan', x)

def floor(x):
    return __base_math_func('floor', x)

def exp(x):
    return __base_math_func('exp', x)

def log10(x):
    return __base_math_func('log10', x)


def find_smooth_close_to(n: int, max_j: int=5, primes: list=None) -> int:
    # 'mod' flips between 1 and -1 so we add and subtract
    curr_facs = 1
    mod       = 1

    for prime in (primes or PRIMES_UNDER_1000):
        if curr_facs*prime > n:
            break

        # Figure out where we need to jump to to be divisible
        r = (mod*n) % prime
        j = -(mod_inv(curr_facs, prime)*r) % prime

        if j <= max_j:
            n   += mod*curr_facs*j
            mod *= -1
            curr_facs *= prime

    return n


def cornacchias_algorithm(d: int, p: int, all_sols: bool=False, **root_kwargs) -> Tuple[int, int]:
    """
    Solves the Diophantine equation `x`^2 + `d`*`y`^2 = `p`.

    Parameters:
        d         (int): `d` parameter.
        p         (int): `p` parameter.
        all_sols (bool): Whether or not to return all (primitive) solutions.

    Returns:
        Tuple[int, int]: Formatted as (`x`, `y`).

    Examples:
        >>> from samson.math.general import cornacchias_algorithm
        >>> d, p = 3, 52
        >>> x, y = cornacchias_algorithm(d, p)
        >>> x, y
        (5, 3)

        >>> x**2 + d*y**2 == p
        True

    References:
        https://en.wikipedia.org/wiki/Cornacchia%27s_algorithm
    """
    ZZ = _integer_ring.ZZ
    d  = int(d)

    R    = ZZ/ZZ(p)
    D    = R(-d)
    sols = []

    if D.is_square():
        for root in D.kth_root(2, True, **root_kwargs):
            t     = int(root)
            bound = kth_root(p, 2)
            n     = p

            while t >= bound:
                n, t = t, n % t

            result = ZZ(p-t**2)/d
            if result in ZZ and result.is_square():
                sol = (t, int(result.kth_root(2)))

                if all_sols:
                    sols.append(sol)
                else:
                    return sol

    if sols:
        return set(sols)
    else:
        raise NoSolutionException()


def binary_quadratic_forms(D: int) -> List[Tuple[int]]:
    """
    Returns the list of primitive binary quadratic forms satisfying `a`*`x`^2 + `b`*`x`*`y` + `c`*`y`^2 (i.e. `b`^2 - 4`a``c` = -`D`).

    Parameters:
        D (int): Discriminant.

    Returns:
        List[Tuple[int]]: List of primitives BQFs satsifying the equation for D.

    References:
        https://crypto.stanford.edu/pbc/notes/ep/hilbert.html
    """
    D    = abs(D)
    B    = int((D/3)**(1/2))
    bqfs = []
    b    = D % 2

    while b <= B:
        t = (b**2 + D) // 4
        a = max(b, 1)

        while a**2 <= t:
            c = t // a
            if not t % a and gcd(c, a, b) == 1:
                if not (a == b or a**2 == t or b == 0):
                    bqfs.append((a, -b, c))
                bqfs.append((a, b, c))
            a += 1

        b += 2

    return bqfs


@RUNTIME.global_cache()
def hilbert_class_polynomial(D: int) -> 'Polynomial':
    """
    Generates the Hilbert class polynomial for discriminant `D`.

    Parameters:
        D (int): Discriminant.

    Returns:
        Polynomial: Hilbert class polynomial.

    Examples:
        >>> from samson.math.general import hilbert_class_polynomial
        >>> hilbert_class_polynomial(3)
        <Polynomial: y, coeff_ring=ZZ>

        >>> hilbert_class_polynomial(7)
        <Polynomial: y + 3375, coeff_ring=ZZ>

        >>> hilbert_class_polynomial(31)
        <Polynomial: y^3 + (39491307)*y^2 + (-58682638134)*y + 1566028350940383, coeff_ring=ZZ>

    References:
        https://github.com/sagemath/sage/blob/master/src/sage/schemes/elliptic_curves/cm.py
    """
    ZZ = _integer_ring.ZZ
    RR = _complex_field.CC(0).real().ring
    Symbol = _symbols.Symbol

    if D < 0:
        D = -D

    if not -D % 4 in [0, 1]:
        raise ValueError(f'{-D} is not a discriminant')

    # Calculate required precision
    bqfs  = binary_quadratic_forms(D)
    h     = len(bqfs)
    c1    = 3.05682737291380
    c2    = sum([1/RR(qf[0]) for qf in bqfs], RR(0))
    prec  = c2*RR(3.142)*RR(D).sqrt() + h*c1
    prec *= 1.45
    prec += 10
    prec  = prec.ceil()

    C2 = _complex_field.ComplexField(int(prec))

    def j_func(tau):
        return C2(C2.ctx.kleinj(tau.val)*1728)


    x = Symbol('x')
    R = C2[x]
    P = R(1)

    dsqrt = C2(-D).sqrt()

    for qf in bqfs:
        a,b,_ = qf
        P    *= x - j_func((-b + dsqrt)/(2*a))


    Q = ZZ[Symbol('y')]
    return Q([round(c.real()) for c in P])



def newton_method_sizes(prec: int) -> List[int]:
    """
    Generates a precision ladder for Netwon's method.

    Parameters:
        prec (int): Desired final precision.

    Returns:
        List[int]: Optimized precision ladder.
    """
    output = []
    while prec > 1:
        output.append(prec)
        prec = (prec + 1) >> 1

    output.append(1)
    output.reverse()

    return output



def batch_inv(elements: List['RingElement']) -> List['RingElement']:
    """
    Efficiently inverts a list of elements using a single inversion (cost 3m + I).

    Parameters:
        elements (List[RingElement]): Elements to invert.

    Returns:
        List[RingElement]: List of inverted elements.

    References:
        https://math.mit.edu/classes/18.783/2015/LectureNotes8.pdf
    """
    if not elements:
        return []

    R = elements[0].ring
    B = [R.one]
    for a in elements:
        B.append(B[-1]*a)

    gamma = ~B[-1]

    invs = []
    for i in reversed(range(1, len(elements)+1)):
        invs.append(B[i-1]*gamma)
        gamma *= elements[i-1]

    return invs[::-1]



def batch_neg(elements: List['RingElement']) -> List['RingElement']:
    """
    Efficiently inverts a list of elements using a single negation.

    Parameters:
        elements (List[RingElement]): Elements to negate.

    Returns:
        List[RingElement]: List of negated elements.

    References:
        https://math.mit.edu/classes/18.783/2015/LectureNotes8.pdf
    """
    if not elements:
        return []

    R = elements[0].ring
    B = [R.zero]
    for a in elements:
        B.append(B[-1]+a)

    gamma = -B[-1]

    negs = []
    for i in reversed(range(1, len(elements)+1)):
        negs.append(B[i-1]+gamma)
        gamma += elements[i-1]

    return negs[::-1]



def cyclotomic_polynomial(n: int) -> 'Polynomial':
    """
    Generates the `n`-th cyclotomic polynomial

    Parameters:
        n (int): Which polynomial to generate.

    Returns:
        Polynomial: `n`-th cyclotomic polynomial.

    References:
        https://en.wikipedia.org/wiki/Cyclotomic_polynomial
        https://planetmath.org/examplesofcyclotomicpolynomials
        "Algorithms for computing cyclotomic polynomials" (http://www.cecm.sfu.ca/CAG/abstracts/AndrewSlides.pdf)
    """
    x      = _symbols.Symbol('x')
    facs   = _factor_gen.factor(n)
    t      = totient(n, facs)
    P      = _integer_ring.ZZ[[x]]
    P.prec = max(t+1, 2)

    square_free = _factor_gen.factor(product(facs))

    # Shortcuts
    if n == 1:
        return (x - 1).val

    elif is_prime(n):
        return P([1 for _ in range(n)]).val

    # Perfect power
    elif facs.is_perfect_power():
        k = facs.largest_root()
        p = facs.kth_root(k).recombine()
        C = cyclotomic_polynomial(p)
        return C.map_coeffs(lambda i, c: (i*p**(k-1), c))

    # 2*p (this is faster than `cyclotomic_polynomial(d // 2)(-x)`)
    elif not n % 2 and (facs // 2).is_perfect_power() and n != 4:
        C = cyclotomic_polynomial(n // 2)
        return C.map_coeffs(lambda i, c: (i, ((i % 2)*-2+1)*c))

    # This algorithm only works if it has NO repeated factors
    elif square_free == facs:
        D = t // 2

        a = [1] + [0]*D
        for comb in {_factor_gen.factor(1)}.union(set(square_free.all_combinations())):
            d = comb.recombine()
            if (square_free // comb).mobius() == 1:
                for i in range(D, d-1, -1):
                    a[i] -= a[i-d]
            else:
                for i in range(d, D+1):
                    a[i] += a[i-d]


        # Cyclotomic polys are palindromic!
        c = P(a)
        c = c.val
        x = c.symbol
        x.top_ring = None
        return ((c[::-1] << D) + c) - (c[D]*x**D)

    else:
        C = cyclotomic_polynomial(square_free.recombine())
        squares = (facs/square_free).recombine()
        return C.map_coeffs(lambda i, c: (i*squares, c))


def fwht(vector: list):
    """
    https://en.wikipedia.org/wiki/Fast_Walsh%E2%80%93Hadamard_transform
    """
    padding_len = 2**math.ceil(math.log2(len(vector)))-len(vector)
    vec_copy = copy(vector) + [0]*padding_len

    h = 1
    while h < len(vec_copy):
        for i in range(0, len(vec_copy), h*2):
            for j in range(i, i+h):
                x = vec_copy[j]
                y = vec_copy[j+h]
                
                vec_copy[j]   = x+y
                vec_copy[j+h] = x-y
            
        h *= 2
    
    return vec_copy



def _fs_4k2(n):
    assert n % 4 == 2
    from samson.math.algebra.rings.order import QuadraticField
    ZZ = _integer_ring.ZZ

    k = kth_root(n // 2, 2)

    while True:
        a = random_int(k) | 1
        b = random_int(k)

        if b % 2:
            b += 1
        
        p = n - a**2 - b**2

        if is_prime(p):
            break


    R = ZZ/ZZ(p)
    m = R(-1).sqrt()

    ZZI = QuadraticField(-1)
    x = ZZI(int(m) + ZZI.symbol)

    if x.norm() != p:
        for fac in x.factor():
            if fac.norm() == p:
                x = fac
                break


    c,d = int(x.val.val[0]), int(x.val.val[1])

    assert a**2 + b**2 + c**2 + d**2 == n

    return a,b,c,d



def sum_of_k_squares(n: int, k: int, max_attempts: int=10000) -> List[int]:
    """
    Probablistic algorithm that finds `n` as a sum of `k` squares.

    Parameters:
        n            (int): Number to find.
        k            (int): Number of squares.
        max_attempts (int): Maximum number of attempts before throwing.

    Returns:
        List[int]: `n` decomposed to `k` squares.
    """
    s = [max(kth_root(n // 4, 2), 1)]*k

    assert n > -1

    for _ in range(max_attempts):
        result = sum([e**2 for e in s])
        i      = random_int(k)
        diff   = kth_root(abs(result-n), 2)

        if result == n:
            return s
        elif result > n:
            while not s[i]:
                i = random_int(k)
            
            s[i] -= min(diff, s[i])
        else:
            s[i] += diff


    raise ProbabilisticFailureException


def four_squares(n: int) -> Tuple[int, int, int, int]:
    """
    Probablistic algorithm that finds `n` as a sum of four squares.

    Parameters:
        n (int): Number to find.

    Returns:
        List[int]: `n` decomposed to four squares.

    References:
        https://mathoverflow.net/questions/259152/efficient-method-to-write-number-as-a-sum-of-four-squares#:~:text=Wikipedia%20states%20that%20there%20randomized%20polynomial-time%20algorithms%20for,in%20expected%20running%20time%20O%20%28log%202%20n%29.
    """
    try:
        return tuple(sum_of_k_squares(n, 4))

    except ProbabilisticFailureException:
        if n % 4 == 2:
            return _fs_4k2(n)

        elif n % 2 == 1:
            a,b,c,d = _fs_4k2(2*n)

            # Ensure a,b and c,d have same signs
            if a % 2 != b % 2:
                if a % 2 != c % 2:
                    a, c = c, a
                else:
                    a, d = d, a

            return (a+b) // 2, (a-b) // 2, (c+d) // 2, (c-d) // 2

        else:
            res = four_squares(n // 4)
            return [r*2 for r in res]


def fibonacci_number(n: int, R: 'Ring'=None) -> int:
    if n < 0:
        return (1 - 2*((n-1) % 2))*fibonacci_number(-n)

    ZZ = R or _integer_ring.ZZ
    A  = _mat.Matrix([[ZZ(1), ZZ(1)], [ZZ(1), ZZ(0)]])
    return int((A**n)[0, 1])


def lucas_number(n :int) -> int:
    if not n:
        return 2
    return fibonacci_number(n-1) + fibonacci_number(n+1)


def fibonacci_polynomial(n: int) -> "Polynomial":
    """
    References:
        https://en.wikipedia.org/wiki/Fibonacci_polynomials
        https://www.nayuki.io/page/fast-fibonacci-algorithms
    """
    if n < 0:
        return (1 - 2*((n-1) % 2))*fibonacci_polynomial(-n)

    ZZ =_integer_ring.ZZ
    x  = _symbols.Symbol('x')
    P  = ZZ[x]
    
    A = _mat.Matrix([[P(x), P(1)], [P(1), P(0)]])
    return (A**n)[0, 1]



def lucas_polynomial(n: int) -> "Polynomial":
    """
    References:
        https://en.wikipedia.org/wiki/Fibonacci_polynomials
    """
    return fibonacci_polynomial(2*n) // fibonacci_polynomial(n)



FIB_TABLE = {0: 0,
 1: 2,
 2: 3,
 3: 4,
 5: 5,
 8: 6,
 13: 7,
 21: 8,
 34: 9,
 55: 10,
 89: 11,
 144: 12,
 233: 13,
 377: 14,
 610: 15,
 987: 16,
 1597: 17,
 2584: 18,
 4181: 19,
 6765: 20,
 10946: 21,
 17711: 22,
 28657: 23,
 46368: 24,
 75025: 25,
 121393: 26,
 196418: 27,
 317811: 28,
 514229: 29}


def estimate_fibonacci_index(n: int) -> int:
    """
    Estimates index of `n` as a Fibonacci number.

    Parameters:
        n (int): Fibonacci number.

    Returns:
        int: Estimated index of Fibonacci number. Empirically tested to be accurate to at least 50e6.
        However, the error increases very slowly, so this number is probably much higher (20e6 -> 0.3286061, 30e6 -> 0.329047117, 50e6 -> 0.32992916).
        A naive calculation of the estimated error shows that this function should be accurate up to ~1.55e9.

    Example:
        >>> for test_range in [range(3, 50000), range(50000, 3000000, 100000), range(3000000, 9000000, 400000), range(9000000, 20000000, 1000000)]:
        >>>     for j in test_range:
        >>>         a = fibonacci_number(j)
        >>>         b = estimate_fibonacci_index(a)
        >>>         assert b == j

    """
    b = n.bit_length()

    if n in FIB_TABLE:
        return FIB_TABLE[n]


    if b < 39:
        return math.floor(math.log2(n)/0.67 + 0.65)

    elif b < 937:
        return math.ceil(math.log2(n)/0.6939 + 1)
    
    elif b < 19439:
        return math.ceil(math.log2(n)/0.69425 + 1)
    
    elif b < 555394:
        return math.ceil(math.log2(n)/0.694241856 + 1)

    # log2 of the golden ratio
    return math.ceil(math.log2(n)/0.6942419136 + 1)



def find_fibonacci_index(n :int, ensure_fib: bool=True) -> int:
    """
    References:
        https://www.ritambhara.in/checking-if-a-number-is-fibonacci/#:~:text=Another%20method%20(Quick%20one)%20to,49%20which%20is%207*7
    """
    if ensure_fib and not detect_fibonacci(n):
        raise ValueError(f'{n} is not a Fibonacci number')

    i = estimate_fibonacci_index(n)

    # This is our highest known good for the estimation function
    if i < 50_000_000:
        return i

    # Note that fib(2) == 1, so we use this to detect mod 2
    mod2 = 1-is_square(5*n**2+4)

    initial_clamp = [1]

    # Look for small divisors
    for p in primes(3, 10):
        if not n % fibonacci_number(p):
            initial_clamp.append(p)

    # Clamp `i` to found congruence
    clamp    = product(initial_clamp)
    r, clamp = crt([(0, clamp), (mod2, 2)])

    i -= (i-r) % clamp

    # Search downwards
    a = fibonacci_number(i)
    while a != n:
        i -= clamp
        a  = fibonacci_number(i)
    
    return i
