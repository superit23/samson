from samson.math.factorization.siqs import BMatrix, ge_f2_nullspace, solve_row
gf128 = GF(2, 128)
R     = ZZ/ZZ(2)

def b_mat_to_mat(b_mat):
    rows = []
    for row in b_mat.rows:
        rows.append([int(b) for b in bin(row)[2:].zfill(b_mat.num_cols)[::-1]])
    
    return Matrix(rows, R)


def mat_to_bmat(mat):
    return BMatrix([int("".join(([str(int(c)) for c in r[::-1]])), 2) for r in mat.rows], mat.num_cols)


def get_ns_vec(K, i):
    result = DenseVector([R.zero]*K.num_cols, R)
    for r,c in zip(K.rows, bin(i)[2:].zfill(len(K.rows))):
        if int(c):
            result += DenseVector(r)
    
    return result


def reverse_int(i, bits):
    return int(bin(int(i))[2:].zfill(bits)[::-1], 2)


def gf2_to_vec(a, size=128):
    return [R(int(b)) for b in bin(int(a))[2:].zfill(size)[::-1]]


def vec_to_gf2(v):
    return gf128(int(''.join([str(int(b)) for b in list(v)[::-1]]), 2))


def build_mc(c):
    M = Matrix([gf2_to_vec(c * (2**i)) for i in range(128)], R)
    return M.T


def build_ms():
    M = Matrix([gf2_to_vec(gf128(2**i)**2) for i in range(128)], R)
    return M.T


def build_mc2(c):
    return mat_to_bmat(build_mc(c))


def build_ms2():
    return mat_to_bmat(build_ms())


def calculate_ad(coeffs, forged_coeffs):
    Ad = mat_to_bmat(Matrix.fill(R.zero, 128, 128))
    for i, (c, c_p) in enumerate(zip(coeffs, forged_coeffs)):
        Ad += calculate_ad_one_col(c, c_p, i)
    
    return Ad


def calculate_ad_one_col(coeff, forged_coeff, col):
    res = build_mc2(coeff - forged_coeff) * Mss[col]
    return res


def make_dependency_mat(coeffs, forged_coeffs, X):
    # m = min(len(coeffs) * 128 // X.num_rows, (n-1))*X.num_rows
    m = (len(coeffs)-1) * 128
    num_rows = min(128, m // X.num_cols)
    # num_rows = 128

    X_b = mat_to_bmat(X.T)
    Ad  = calculate_ad(coeffs, forged_coeffs)
    result = []

    for col, forged_coeff in enumerate(forged_coeffs):
        col_ad = Ad + calculate_ad_one_col(coeffs[col], forged_coeff, col)

        for b in range(128):
            # bit_ad = col_ad + calculate_ad_one_col(coeffs[col], forged_coeff + gf128(2**b), col) * X.T
            bit_ad = col_ad + calculate_ad_one_col(coeffs[col], forged_coeff + gf128(2**b), col)
            bit_ad = b_mat_to_mat(bit_ad * X_b)
            # result.append([elem for row in bit_ad.rows[:n-1] for elem in row])#row[:X.num_rows]])
            result.append([elem for row in bit_ad.rows[:num_rows] for elem in row[:X.num_cols]])

    return Matrix(result).T


def adjust_forged(forged_coeffs, N, i):
    vec = get_ns_vec(N, i)
    res = []
    for i, c in enumerate(forged_coeffs):
        res.append(c + vec_to_gf2(vec[128*i:128*(i+1)]))

    return res


# def adjust_forged(forged_coeffs, N, i):
#     vec = get_ns_vec(N, i)
#     res = []
#     for i, c in enumerate(forged_coeffs[::-1]):
#         res.append(c + vec_to_gf2(vec[128*i:128*(i+1)].values[::-1]))
    
#     return res[::-1]


def adjust_ciphertext(adjusted_forged, ct_chunks):
    forged_chunks = [Bytes(int(c)) for c in adjusted_forged]
    result = []

    for i, chunk in enumerate(ct_chunks):
        if is_power_of_two(i) and i > 1:
            result.append(forged_chunks[int(log2(i))-1])
        else:
            result.append(chunk)
    
    return sum(result[::-1])


def oracle(nonce, ciphertext):
    try:
        gcm.decrypt(nonce, ciphertext)
        return True
    except InvalidMACException:
        return False



def find_collision(ct_chunks, forged_coeffs, N):
    for i in range(2**len(N)):
        if not i % 100:
            print("idx", i)

        adjusted = adjust_forged(forged_coeffs, N, i)

        if oracle(nonce, adjust_ciphertext(adjusted, ct_chunks) + tag):
            yield i, adjusted


def b_mat_nullspace(b_mat):
    sols, marks, M = ge_f2_nullspace(b_mat)

    N = []
    for sol in sols:
        row = solve_row(sol, M, marks)
        N.append(sum(1 << i for i in row))
    
    return BMatrix(N, b_mat.num_cols)


def fast_kernel(T):
    return b_mat_to_mat(b_mat_nullspace(mat_to_bmat(T)))


def calculate_error_poly(coeffs, forged_coeffs, h):
    total = 0

    for i, (c, c_p) in enumerate(zip(coeffs, forged_coeffs)):
        total += (c - c_p)*h**(2**(i+1))
    
    return total


def int_to_elem(n):
    return gf128(reverse_bits(n, 128))


def test_bmat_trans():
    M = MatrixRing(R, 128)
    for _ in tqdm(range(500)):
        a = M.random()
        b = M.random()
        a1 = mat_to_bmat(a)
        b1 = mat_to_bmat(b)
        assert a == b_mat_to_mat(a1)
        assert b == b_mat_to_mat(b1)

        assert mat_to_bmat(a*b) == a1*b1
        assert a*b == b_mat_to_mat(a1*b1)


def prune_rows(ad, ad_adj, sel_range):
    return Matrix([ad[r] for r in sel_range if any(ad_adj[r])], ring=ad.ring)


rij   = Rijndael(Bytes().zfill(16))
t_len = 1
gcm   = GCM(rij, tag_length=t_len)
nonce = Bytes([0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b])
n = 16
plaintext = stretch_key(Bytes(b'plain'), 2**13)
ciphertext = gcm.encrypt(nonce, plaintext)
ct  = ciphertext[:-t_len]
tag = ciphertext[-t_len:]
h   = int_to_elem(gcm.H)

ct_chunks  = ct.chunk(16)
num_coeffs = int(math.log2(len(ct_chunks)))
c2 = [ct_chunks[2**num_coeffs - (2**i-1)] for i in range(1, num_coeffs+1)]

Ms  = build_ms2()
Mss = [Ms**i for i in range(1,n+1)]

# Test linear algebra
a = gf128.random()
b = gf128.random()
c = build_mc(a)*Matrix([gf2_to_vec(b)]).T
assert vec_to_gf2(c.T[0]) == a*b

c = b_mat_to_mat(Ms)*Matrix([gf2_to_vec(a)]).T
assert vec_to_gf2(c.T[0]) == a**2


coeffs = [int_to_elem(c.int()) for c in c2]
X      = Matrix.identity(128, R)
found  = 0
K      = None

while not K or K.num_rows < 127:
    forged_coeffs = [gf128.random() for _ in range(len(coeffs))]

    T = make_dependency_mat(coeffs, forged_coeffs, X)
    print("T built")
    N = fast_kernel(T)
    print("N found")

    j = 0
    for i in range(1, 2**len(N)):
        adjusted = adjust_forged(forged_coeffs, N, i)
        err = int(calculate_error_poly(coeffs, adjusted, h))
        if not err % 2**(0+4):
            j += 1
            if not j % 100:
                print(j, i)
        
        if not err % 2**(0+16):
            print(f"Found good! {hex(err)}")
            break


    new_Ad = calculate_ad(coeffs, adjusted)
    adj_Ad = b_mat_to_mat(new_Ad * mat_to_bmat(X.T))
    new_Ad = b_mat_to_mat(new_Ad)

    if K:
        K = K.col_join(prune_rows(new_Ad, adj_Ad, range(0+8, 0+16)))
    else:
        K = prune_rows(new_Ad, adj_Ad, range(0+8, 0+16))

    X      = fast_kernel(K)
    found += 8

    print(K.num_rows, K.num_cols)
