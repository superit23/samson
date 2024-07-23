from samson.math.factorization.siqs import BMatrix
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.dense_vector import DenseVector
from samson.math.matrix import Matrix
from samson.math.algebra.fields.gf2 import GF2
from samson.utilities.runtime import RUNTIME
from samson.utilities.manipulation import reverse_bits
from samson.utilities.bytes import Bytes
import math

import logging
log = logging.getLogger(__name__)

gf128 = GF2(128)
R     = ZZ/ZZ(2)

def get_ns_vec(K, i):
    result = DenseVector([R.zero]*K.num_cols, R)
    for r,c in zip(K.rows, bin(i)[2:].zfill(len(K.rows))):
        if int(c):
            result += DenseVector(r)
    
    return result


def gf2_to_vec(a, size=128):
    return [R(int(b)) for b in bin(int(a))[2:].zfill(size)[::-1]]


def vec_to_gf2(v):
    return gf128(int(''.join([str(int(b)) for b in list(v)[::-1]]), 2))


def build_mc(c):
    M = Matrix([gf2_to_vec(c * (2**i)) for i in range(128)], R)
    return BMatrix.from_native_matrix(M.T)


def build_ms():
    M = Matrix([gf2_to_vec(gf128(2**i)**2) for i in range(128)], R)
    return BMatrix.from_native_matrix(M.T)


def calculate_ad(coeffs, forged_coeffs, Mss):
    Ad = BMatrix.from_native_matrix(Matrix.fill(R.zero, 128, 128))
    for i, (c, c_p) in enumerate(zip(coeffs, forged_coeffs)):
        Ad += calculate_ad_one_col(c, c_p, i, Mss)
    
    return Ad


def calculate_ad_one_col(coeff, forged_coeff, col, Mss):
    res = build_mc(coeff - forged_coeff) * Mss[col]
    return res


def make_dependency_mat(coeffs, forged_coeffs, X, Mss, tag_len):
    m = (len(coeffs)-1) * 128

    # The less rows, the better probability for the oracle
    # However, we get less info too
    num_rows = min(128, m // X.num_cols, tag_len-8)

    Ad = calculate_ad(coeffs, forged_coeffs, Mss)
    result = []

    for col, forged_coeff in enumerate(forged_coeffs):
        col_ad = Ad + calculate_ad_one_col(coeffs[col], forged_coeff, col, Mss)

        for b in range(128):
            bit_ad = col_ad + calculate_ad_one_col(coeffs[col], forged_coeff + gf128(2**b), col, Mss)
            bit_ad = (bit_ad * X).to_native_matrix()
            result.append([elem for row in bit_ad.rows[:num_rows] for elem in row])

    return Matrix(result).T


def adjust_forged(forged_coeffs, N, i):
    vec = get_ns_vec(N, i)
    res = []
    for i, c in enumerate(forged_coeffs):
        res.append(c + vec_to_gf2(vec[128*i:128*(i+1)]))

    return res


def adjust_ciphertext(adjusted_coeffs, ct_chunks):
    adj_ct   = [Bytes(elem_to_int(a)).zfill(16) for a in adjusted_coeffs]
    adjusted = []

    num_coeffs = int(math.log2(len(ct_chunks)))
    coeffs_idx = [2**num_coeffs - (2**i-1) for i in range(1, num_coeffs+1)]

    for i, c in enumerate(ct_chunks):
        if i in coeffs_idx:
            adjusted.append(adj_ct[coeffs_idx.index(i)])
        else:
            adjusted.append(c)

    return b''.join(adjusted)


def fast_kernel(T):
    return BMatrix.from_native_matrix(T).right_kernel()


def calculate_error_poly(coeffs, forged_coeffs, h):
    total = 0

    for i, (c, c_p) in enumerate(zip(coeffs, forged_coeffs)):
        total += (c - c_p)*h**(2**(i+1))
    
    return total


def int_to_elem(n):
    return gf128(reverse_bits(n, 128))

def elem_to_int(e):
    return reverse_bits(int(e), 128)

def prune_rows(ad, ad_adj, sel_range):
    return Matrix([ad[r] for r in sel_range if any(ad_adj[r])], ring=ad.ring)


class GCMTruncatedMACAttack(object):
    def __init__(self, oracle) -> None:
        self.oracle = oracle


    @RUNTIME.report
    def execute(self, nonce: bytes, ciphertext: bytes, tag: bytes):
        # Prepare ciphertext for conversion
        tag_len    = len(tag)*8
        ct_chunks  = ciphertext.chunk(16)
        num_coeffs = int(math.log2(len(ct_chunks)))
        c2         = [ct_chunks[2**num_coeffs - (2**i-1)] for i in range(1, num_coeffs+1)]

        Ms  = build_ms()
        Mss = [Ms**i for i in range(1,num_coeffs+1)]

        # Initialize the main variables
        coeffs = [int_to_elem(c.int()) for c in c2]
        X      = BMatrix.from_native_matrix(Matrix.identity(128, R))
        K      = None

        # Initialize progress indicators
        oracle_iters = RUNTIME.report_progress(None, desc="Oracle calls")
        progress     = RUNTIME.report_progress(None, total=128, desc="Authentication key bits")

        try:
            while not K or K.num_rows < 127:
                forged_coeffs = [gf128.random() for _ in range(len(coeffs))]

                # Linear algebra
                T = make_dependency_mat(coeffs, forged_coeffs, X, Mss, tag_len)
                N = fast_kernel(T).to_native_matrix()

                log.debug(f"X {len(X.rows)} x {X.num_cols}")
                log.debug(f"T built {T.num_rows} x {T.num_cols}")
                log.debug(f"N found {N.num_rows} x {N.num_cols}")

                # Online portion; attempt forgeries
                for i in range(1, 2**len(N)):
                    adjusted = adjust_forged(forged_coeffs, N, i)
                    adj_ct   = adjust_ciphertext(adjusted, ct_chunks)

                    oracle_iters.update(1)

                    if self.oracle(nonce, adj_ct + tag):
                        break

                # Prepare and integrate new information
                new_Ad = calculate_ad(coeffs, adjusted, Mss)
                adj_Ad = (new_Ad * X).to_native_matrix()
                new_Ad = new_Ad.to_native_matrix()

                new_rows = prune_rows(new_Ad, adj_Ad, range(tag_len // 2, tag_len))
                progress.update(len(new_rows))

                if K:
                    K = K.col_join(new_rows)
                else:
                    K = new_rows

                X = fast_kernel(K).T

        except KeyboardInterrupt:
            return K
        

        return [reverse_bits(r, 128) for r in X.T.rows]
