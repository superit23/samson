from samson.math.factorization.factors import Factors
from samson.math.general import kth_root, sieve_of_eratosthenes, random_int_between, gcd
from samson.utilities.exceptions import ProbabilisticFailureException
from tqdm import tqdm
import math

ECM_BOUNDS = (
    50,
    67,
    83,
    100,
    117,
    133
)


def compute_bounds(log_n: int):
    """
    Computes B1 and B2 bounds for target factor. Note this is in log2 relative to the target and not log10 absolute.
    Computed by taking generic ECM bounds (e.g. 10^30, 10^40, etc), converting to log2, and dividing by 2
    """
    if log_n <= 50: 
        B1, B2 = 2000, 147396
    elif log_n <= 67: 
        B1, B2 = 11000, 1873422
    elif log_n <= 83: 
        B1, B2 = 50000, 12746592
    elif log_n <= 100: 
        B1, B2 = 250000, 128992510
    elif log_n <= 117: 
        B1, B2 = 1000000, 1045563762
    elif log_n <= 133:
        B1, B2 = 3000000, 5706890290
    else: 
        raise ValueError("Integer too large for ECM implementation")
    return B1, B2



def point_add(px, pz, qx, qz, rx, rz, n):
	u = (px-pz) * (qx+qz)
	v = (px+pz) * (qx-qz)
	upv, umv = u+v, u-v

	x = rz * upv * upv
	z = rx * umv * umv
	return x % n, z % n


def point_double(px, pz, n, a24):
	u, v   = px+pz, px-pz
	u2, v2 = u*u, v*v

	t = u2 - v2
	x = (u2 * v2) 
	z = t * (v2 + a24*t)
	return x % n, z % n



def scalar_multiply(k, px, pz, n, a24):
	sk     = bin(k)[3:]
	qx, qz = px, pz
	rx, rz = point_double(px, pz, n, a24)

	for b in sk:
		if b == '1':
			qx, qz = point_add(rx, rz, qx, qz, px, pz, n)
			rx, rz = point_double(rx, rz, n, a24)
		else:
			rx, rz = point_add(qx, qz, rx, rz, px, pz, n)
			qx, qz = point_double(qx, qz, n, a24)	

	return qx, qz


_B2_SIEVE_CACHE = {}
_K_CACHE        = {}

def ecm(n: int, max_curves: int=10000, max_sigma: int=2**63, target_size: int=None, visual: bool=False) -> Factors:
    """
    Uses Lenstra's Elliptic Curve Method to probabilistically find a factor of `n`.

    Parameters:
        n           (int): Integer to factor.
        max_curves  (int): Maximum number of curves to attempt.
        max_sigma   (int): Maximum curve parameter bound.
        target_size (int): Size of factor to target in bits (defaults to half of total bitlength).
        visual     (bool): Whether or not to show progress bar.

    Returns:
        int: Factor of `n`.

    Examples:
        >>> from samson.math.factorization.general import ecm
        >>> ecm(26515460203326943826)
        2

    References:
        https://github.com/nishanth17/factor
    """
    target_size = target_size or math.log2(n)/2

    # If no target size, target half in case of semi-prime
    B1, B2 = compute_bounds(target_size)

    if B2 in _B2_SIEVE_CACHE:
        prime_base = _B2_SIEVE_CACHE[B2]
    else:
        prime_base = sieve_of_eratosthenes(B2)
        _B2_SIEVE_CACHE[B2] = prime_base

    # Initial B1-powersmooth exponent
    if B1 in _K_CACHE:
        k, l = _K_CACHE[B1]
    else:
        k = 1
        l = 0
        for p in prime_base:
            if p > B1:
                break

            l += 1
            k *= p**int(math.log(B1, p))
        
        _K_CACHE[B1] = k, l

    # Initialize variables
    def R(a):
        return a % n

    D    = kth_root(B2, 2)
    S    = [0] * (2*(D+1))
    beta = [0] * (D+1)

    iterator = range(max_curves)

    if visual:
        iterator = tqdm(iterator, unit='curve', desc=f"ECM ({math.ceil(target_size)}-bit target)")

    for _ in iterator:
        # Generate random curve
        sigma = random_int_between(6, max_sigma)
        u     = R(sigma**2 - 5)
        v     = R(sigma*4)
        vmu   = v-u
        A     = R(vmu**3) * 3*u+v // (4*u**3*v - 2)
        A24   = R(A+2) // 4

        # Stage 1
        px, pz = R(u**3 // v**3), 1
        qx, qz = scalar_multiply(k, px, pz, n, A24)

        g = gcd(qz, n)

        if 1 < g < n:
            return g


        # Stage 2
        S[1], S[2] = point_double(qx, qz, n, A24)
        S[3], S[4] = point_double(S[1], S[2], n, A24)
        beta[1]    = R(S[1] * S[2])
        beta[2]    = R(S[3] * S[4])

        for d in range(3, D+1):
            d2 = 2 * d
            S[d2-1], S[d2] = point_add(S[d2-3], S[d2-2], S[1], S[2], S[d2-5], S[d2-4], n)
            beta[d] = R(S[d2-1] * S[d2])

        g, B = 1, B1 - 1

        rx, rz  = scalar_multiply(B, qx, qz, n, A24)
        tx, tz  = scalar_multiply(B - 2*D, qx, qz, n, A24)
        q, step = l, 2*D

        for r in range(B, B2, step):
            alpha, limit = rx * rz, r + step
            while q < len(prime_base) and prime_base[q] <= limit:
                d  = (prime_base[q] - r) // 2
                f  = (rx - S[2*d-1]) * (rz + S[2*d]) - alpha + beta[d]
                g  = R(g*f)
                q += 1

            trx, trz = rx, rz
            rx, rz   = point_add(rx, rz, S[2*D-1], S[2*D], tx, tz, n)
            tx, tz   = trx, trz

        g = gcd(n, g)

        if 1 < g < n:
            if visual:
                iterator.close()
                del iterator
            return g

    if visual:
        iterator.close()
        del iterator
    raise ProbabilisticFailureException("Factor not found")
