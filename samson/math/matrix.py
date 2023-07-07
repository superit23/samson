from samson.math.dense_vector import DenseVector
from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.general import gaussian_elimination, lll, gram_schmidt, is_power_of_two
from samson.utilities.exceptions import NoSolutionException
from samson.utilities.runtime import RUNTIME
from shutil import get_terminal_size
from types import FunctionType
from copy import deepcopy

import re
COLOR_RE = re.compile('\x1b\[[0-9;]*m')

def decolor(elem_str):
    elem_str = elem_str.replace('\x1b[0m', '')
    return COLOR_RE.sub('', elem_str)

# Python's string interpolation doesn't like newlines...
NEWLINE = "\n"

class Matrix(RingElement):
    def __init__(self, rows: list, coeff_ring: Ring=None, ring: Ring=None):
        """
        Parameters:
            rows       (list): List of lists representing matrix rows.
            coeff_ring (Ring): Ring elements will be in.
            ring       (Ring): Parent ring.
        """
        is_coerced      = hasattr(rows[0][0], 'ring')
        self.coeff_ring = coeff_ring or (rows[0][0].ring if is_coerced else ZZ)
        row_lens        = [len(row) for row in rows]

        if not max(row_lens) == min(row_lens):
            raise ValueError("Row lengths must be equal")

        c_len = row_lens[0]
        r_len = len(rows)
        rows  = [[self.coeff_ring.coerce(rows[r][c]) for c in range(c_len)] for r in range(r_len)]

        self.rows = rows

        if not ring:
            from samson.math.algebra.rings.matrix_ring import MatrixRing
            ring = MatrixRing(size=r_len, ring=self.coeff_ring)

        self.ring = ring


    def shorthand(self, tinyhand: bool=False) -> str:
        if tinyhand:
            str_meth = lambda elem: elem.tinyhand()
        else:
            str_meth = lambda elem: elem.shorthand()


        term_max_size = get_terminal_size().columns - 10
        row_strs      = []

        col_adjusts = []
        for row in self.T.rows:
            max_elem_size = max([len(decolor(str_meth(elem))) for elem in row])
            col_adjusts.append(min(max_elem_size, term_max_size))
        
        max_row_str = len(str(len(self.rows)))

        row_strs.append(" "*(1+max_row_str) + ' '.join([str(idx).rjust(col_adj+1) for idx, col_adj in enumerate(col_adjusts)]))

        for ridx, row in enumerate(self.rows):
            row_strs.append(f"{str(ridx).rjust(max_row_str)} [" + ", ".join([str_meth(elem).rjust(col_adjusts[idx]) for idx, elem in enumerate(row)]) + "]")
        
        return "".join([NEWLINE + row_str for row_str in row_strs])


    def tinyhand(self) -> str:
        return self.shorthand(True)


    @property
    def __raw__(self):
        return RUNTIME.default_short_printer(self)


    def __reprdir__(self):
        return ['coeff_ring', 'num_rows', 'num_cols', '__raw__']


    @property
    def num_rows(self) -> int:
        return len(self.rows)


    @property
    def num_cols(self) -> int:
        return len(self.rows[0])


    @property
    def cols(self) -> list:
        return self.T.rows


    def transpose(self) -> 'Matrix':
        """
        Transposes the `Matrix` i.e. flips it along its diagonal.

        Returns:
            Matrix: Transposed `Matrix`.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2,3],[4,5,6],[7,8,9]], ZZ).transpose()
            <Matrix: coeff_ring=ZZ, num_rows=3, num_cols=3, 
               0  1  2
            0 [1, 4, 7]
            1 [2, 5, 8]
            2 [3, 6, 9]>

        """
        return Matrix([[self.rows[r][c] for r in range(self.num_rows)] for c in range(self.num_cols)], coeff_ring=self.coeff_ring, ring=self.ring)


    @property
    def T(self) -> 'Matrix':
        return self.transpose()


    def is_square(self) -> bool:
        """
        Determines whether the `Matrix` is square i.e. the number of columns equals the number of rows.

        Returns:
            bool: Whether the `Matrix` is square.
        """
        return self.num_cols == self.num_rows


    @staticmethod
    def identity(size: int, coeff_ring: Ring=None, ring: Ring=None) -> 'Matrix':
        """
        Creates the identity `Matrix` of `size`.

        Parameters:
            size        (int): Number of rows/columns.
            coeff_ring (Ring): Ring elements will be in.
            ring       (Ring): Parent ring.

        Returns:
            Matrix: Identity matrix.
        """
        return Matrix([[coeff_ring.one if r == c else coeff_ring.zero for r in range(size)] for c in range(size)], coeff_ring=coeff_ring, ring=ring)


    @staticmethod
    def fill(value: 'RingElement', rows: int, cols: int=None, coeff_ring: Ring=None, ring: Ring=None) -> 'Matrix':
        """
        Fills a `Matrix` with `value`.

        Parameters:
            value (RingElement): Value every element should be.
            rows          (int): Number of rows.
            cols          (int): Number of columns.
            coeff_ring   (Ring): Ring elements will be in.
            ring         (Ring): Parent ring.

        Returns:
            Matrix: `Matrix` filled with `value`.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix.fill(ZZ.zero, 3, 4)
            <Matrix: coeff_ring=ZZ, num_rows=3, num_cols=4, 
               0  1  2  3
            0 [0, 0, 0, 0]
            1 [0, 0, 0, 0]
            2 [0, 0, 0, 0]>

        """
        return Matrix([[value for c in range(cols or rows)] for r in range(rows)], coeff_ring=coeff_ring, ring=ring)


    def apply_elementwise(self, func: FunctionType) -> 'Matrix':
        """
        Applies a function to each element and returns a `Matrix` of the results.

        Parameters:
            func (func): Function to apply.

        Returns:
            Matrix: Result matrix.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2,3],[4,5,6],[7,8,9]], ZZ).apply_elementwise(lambda elem: elem**2)
            <Matrix: coeff_ring=ZZ, num_rows=3, num_cols=3, 
                0   1   2
            0 [ 1,  4,  9]
            1 [16, 25, 36]
            2 [49, 64, 81]>

        """
        return Matrix([[func(self.rows[r][c]) for c in range(self.num_cols)] for r in range(self.num_rows)])


    def change_ring(self, ring: 'Ring') -> 'Matrix':
        """
        Returns a new Matrix with the coefficients coerced into `ring`.

        Parameters:
            ring (Ring): Ring to embed into.

        Returns:
            Matrix: Resultant Matrix.
        """
        return Matrix([[ring(col) for col in row] for row in self.rows], coeff_ring=ring)


    def determinant(self) -> 'RingElement':
        """
        Finds the determinant of the matrix.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> A = Matrix([[2,1],[-1,0]], ZZ)
            >>> A.determinant()
            <IntegerElement: val=1, ring=ZZ>

            >>> B = Matrix([[1, 0, 2, -1],[3, 0, 0, 5],[2, 1, 4, -3],[1, 0, 5, 0]], ZZ)
            >>> B.determinant()
            <IntegerElement: val=30, ring=ZZ>

        References:
            https://www.geeksforgeeks.org/determinant-of-a-matrix/
        """
        assert self.is_square()
        mat = Matrix([[elem for elem in row] for row in self.rows], coeff_ring=self.coeff_ring)
        R   = mat.coeff_ring

        n     = len(mat)
        temp  = [R.zero] * n
        total = R.one
        det   = R.one

        for i in range(n):
            idx = i

            # Find first nonzero
            while idx < n and not mat[idx, i]:
                idx += 1

            if idx == n:
                continue


            if idx != i:
                for j in range(n):
                    mat[idx,j], mat[i,j] = mat[i,j], mat[idx,j]


                # Sign change when we shift rows
                if idx-i % 2:
                    det = -det

            temp = [mat[i,j] for j in range(n)]

            for j in range(i+1, n):
                a = temp[i]
                b = mat[j,i]

                for k in range(n):
                    mat[j,k] = (a*mat[j,k]) - (b*temp[k])

                total *= a


        # Multiply diagonals
        for i in range(n):
            det *= mat[i,i]

        return det / total


    det = determinant


    def adjugate(self):
        assert self.is_square()
        if self.num_rows == 2:
            return Matrix([[self[1,1], -self[0,1]], [-self[1,0], self[0,0]]])

        return (Matrix.identity(self.num_rows, self.coeff_ring)*self.det())/self


    adj = adjugate


    def trace(self) -> 'RingElement':
        if not self.is_square():
            raise ValueError('Cannot calculate trace of a nonsquare matrix')
        return sum(self[i][i] for i in range(self.num_cols))



    def characteristic_polynomial(self, symbol: 'Symbol'=None) -> 'Polynomial':
        """
        Finds the characteristic polynomial `p_a` such that the roots of `p_a` are eigenvalues of `self`.

        Parameters:
            symbol (Symbol): Symbol to use for polynomial.

        Returns:
            Polynomial: Characteristic polynomial.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> A = Matrix([[2,1],[-1,0]], ZZ)
            >>> A.characteristic_polynomial()
            <Polynomial: x^2 + (-2)*x + 1, coeff_ring=ZZ>

            >>> B = Matrix([[1, 0, 2, -1],[3, 0, 0, 5],[2, 1, 4, -3],[1, 0, 5, 0]], ZZ)
            >>> B.characteristic_polynomial()
            <Polynomial: x^4 + (-5)*x^3 + (16)*x^2 + (-34)*x + 30, coeff_ring=ZZ>

        References:
            https://en.wikipedia.org/wiki/Characteristic_polynomial#Formal_definition
        """
        from samson.math.symbols import Symbol

        x = symbol or Symbol('x')
        R = self.coeff_ring
        I = Matrix.identity(self.num_rows, R)
        _ = R[x]
        return (I*x - self).det()


    def trace(self) -> 'RingElement':
        if not self.is_square():
            raise ValueError('Cannot calculate trace of a nonsquare matrix')
        return sum(self[i][i] for i in range(self.num_cols))


    def row_join(self, other: 'Matrix') -> 'Matrix':
        """
        Extends `self`'s rows with `others`.

        Parameters:
            other (Matrix): Other `Matrix`.

        Returns:
            Matrix: The joined matrices.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2], [3,4]], ZZ).row_join(Matrix([[5,6], [7,8]], ZZ))
            <Matrix: coeff_ring=ZZ, num_rows=2, num_cols=4, 
               0  1  2  3
            0 [1, 2, 5, 6]
            1 [3, 4, 7, 8]>


        """
        type_o = type(other)

        if type_o is Matrix:
            cols = other.rows
        else:
            cols = other

        return Matrix([row_a + row_b for row_a, row_b in zip(self.rows, cols)], coeff_ring=self.coeff_ring, ring=self.ring)


    augment = row_join

    def col_join(self, other: 'Matrix') -> 'Matrix':
        """
        Extends `self`'s columns with `others`.

        Parameters:
            other (Matrix): Other `Matrix`.

        Returns:
            Matrix: The joined matrices.

        Examples:
            >>> from samson.math.all import Matrix, ZZ
            >>> Matrix([[1,2], [3,4]], ZZ).col_join(Matrix([[5,6], [7,8]], ZZ))
            <Matrix: coeff_ring=ZZ, num_rows=4, num_cols=2, 
               0  1
            0 [1, 2]
            1 [3, 4]
            2 [5, 6]
            3 [7, 8]>

        """
        type_o = type(other)

        if type_o is Matrix:
            rows = other.rows
        else:
            rows = other

        return Matrix(self.rows + rows, coeff_ring=self.coeff_ring, ring=self.ring)


    def LLL(self, delta: float=0.75) -> 'Matrix':
        """
        Performs the Lenstra–Lenstra–Lovász lattice basis reduction algorithm.

        Parameters:
            delta (float): Minimum optimality of the reduced basis.

        Returns:
            Matrix: Reduced basis.

        Examples:
            >>> from samson.math.matrix import Matrix
            >>> from samson.math.all import QQ
            >>> m = Matrix([[1, 2, 3, 4], [5, 6, 7, 8]], QQ)
            >>> m.LLL()
            <Matrix: coeff_ring=Frac(ZZ), num_rows=2, num_cols=4, 
                0  1  2  3
            0 [ 3, 2, 1, 0]
            1 [-2, 0, 2, 4]>

    
        """
        return lll(self, delta)


    def gram_schmidt(self, full: bool=False) -> 'Matrix':
        """
        Performs Gram-Schmidt orthonormalization.

        Parameters:
            normalize (bool): Whether or not to normalize the vectors.

        Returns:
            Matrix: Orthonormalized row vectors.

        Examples:
            >>> from samson.math.all import QQ
            >>> from samson.math.matrix import Matrix
            >>> out, _ = Matrix([[3,1],[2,2]], QQ).gram_schmidt()
            >>> [[float(out[r][c]) for c in range(out.num_cols)] for r in range(out.num_rows)]
            [[3.0, 1.0], [-0.4, 1.2]]

        """
        return gram_schmidt(self, full)


    # TODO: This only works with QQ since we're letting Python's `sqrt` function coerce it into a Python float.
    # The root problem is two-fold:
    # 1) Finding the square-root of an element in an arbitrary ring
    # 2) Handling irrational numbers

    # Python's floating-point arithmetic will automatically truncate irrational numbers to 53 bits, however, `Frac(ZZ)` will use arbitrary-precision integers
    # to represent the numerator and denominator, resulting in an infinite expansion.
    def normalize(self) -> 'Matrix':
        """
        Normalizes the `Matrix` by dividing all elements by its magnitude.

        Returns:
            Matrix: Normalized `Matrix`.

        Examples:
            >>> from samson.math.all import QQ, Matrix
            >>> Matrix([[4,4,4,4]]*4, QQ).normalize()
            <Matrix: coeff_ring=Frac(ZZ), num_rows=4, num_cols=4, 
                 0    1    2    3
            0 [1/2, 1/2, 1/2, 1/2]
            1 [1/2, 1/2, 1/2, 1/2]
            2 [1/2, 1/2, 1/2, 1/2]
            3 [1/2, 1/2, 1/2, 1/2]>

        """
        magnitude = (self.apply_elementwise(lambda elem: elem**2)*Matrix.fill(self.coeff_ring.one, rows=self.num_cols, cols=1))[0,0].sqrt()
        return self * ~magnitude


    def LUsolve(self, rhs: 'Matrix') -> 'Matrix':
        """
        Solves `Ax = b` for `x` where `A` is `self` and `b` is `rhs`.

        Parameters:
            rhs (Matrix): The right-hand side matrix.

        Returns:
            Matrix: The `x` matrix.

        Examples:
            >>> from samson.math.all import QQ
            >>> from samson.math.matrix import Matrix
            >>> a = Matrix([[3, 2,-4], [2, 3, 3], [5, -3, 1]], coeff_ring=QQ)
            >>> b = Matrix([[3], [15], [14]], coeff_ring=QQ)
            >>> c = a.LUsolve(b)
            >>> a*c == b
            True

        """
        return gaussian_elimination(self, rhs)

    solve_right = LUsolve


    def solve_left(self, rhs: 'Matrix') -> 'Matrix':
        return self.T.solve_right(rhs.T).T


    def rref(self) -> 'Matrix':
        """
        Returns the reduced row echelon form.

        Returns:
            Matrix: RREF of `self`.
        """
        A = deepcopy(self)

        n = A.num_rows
        m = A.num_cols

        lead = 0

        for r in range(n):
            if m <= lead:
                return A

            i = r

            while not A[i, lead]:
                i += 1
                if i == n:
                    i = r
                    lead += 1

                    if lead == m:
                        return A

            if i != r:
                A[i], A[r] = A[r], A[i]

            scalar = A[r, lead]
            A[r]   = [e / scalar for e in A[r]]
            r_vec  = A[r]

            for i in range(n):
                if i != r:
                    A[i] = [a-b for a,b in zip(A[i], r_vec*A[i, lead])]

            lead += 1

        return A


    def rcef(self) -> 'Matrix':
        """
        Returns the reduced column echelon form.

        Returns:
            Matrix: RCEF of `self`.
        """
        return self.T.rref().T


    def right_kernel(self):
        """
        Computes the right kernel `x` of `self` such that `self`*`x`.`T`=0.

        Returns:
            Matrix: Right kernel.

        References:
            https://en.wikipedia.org/wiki/Kernel_(linear_algebra)#Computation_by_Gaussian_elimination
        """
        AI   = self.col_join(Matrix.identity(self.num_cols, self.coeff_ring))
        c    = AI.T.rref()
        rows = [row[self.num_rows:] for row in c if not any(row[:self.num_rows])]

        if not rows:
            raise NoSolutionException

        return Matrix(rows)


    def left_kernel(self) -> 'Matrix':
        """
        Computes the left kernel `x` of `self` such that `x`*`self`=0.

        Returns:
            Matrix: Left kernel.
        """
        return self.T.right_kernel()


    def direct_product(self, B: 'Matrix') -> 'Matrix':
        C = None
        for a_row in self:
            D = None
            for a_elem in a_row:
                if D is not None:
                    D = D.row_join(B*a_elem)
                else:
                    D = B*a_elem
            
            if C is not None:
                C = C.col_join(D)
            else:
                C = D

        return C


    @staticmethod
    def hadamard(n: int) -> 'Matrix':
        from samson.math.factorization.general import factor
        n21     = n // 2 - 1
        n_facs  = factor(n21)
        n1_facs = factor(n-1)

        if n == 1:
            return Matrix([[1]], coeff_ring=ZZ)

        elif is_power_of_two(n):
            M = Matrix([[1, 1], [1, -1]], coeff_ring=ZZ)
            N = M
            for _ in range(n.bit_length()-2):
                N = M.direct_product(N)
            
            return N

        elif not n % 2 and n_facs.is_prime_power() and n21 % 4 == 1:
            return Matrix.conference(n21+1).conference_to_hadamard()
        
        elif n1_facs.is_prime_power() and not n % 4:
            return Matrix.hadamard_paleyI(n)

        else:
            raise NotImplementedError(f"Hadamard matrices of order {n} not implemented")


    @staticmethod
    def conference(n: int):
        """
        http://math.ucdenver.edu/~wcherowi/courses/m6406/hadamard.pdf
        """
        from samson.math.factorization.general import factor
        from samson.math.algebra.fields.finite_field import FiniteField as FF

        q = n-1
        F = FF(*list(factor(q).items())[0])

        M = Matrix.fill(ZZ.zero, q+1, q+1)
        for i in range(1, q+1):
            M[0,i] = 1
            M[i,0] = 1

        for i in range(q):
            for j in range(q):
                M[i+1, j+1] = (F.element_at(i) - F.element_at(j)).quadratic_character()
        
        return M
    

    @staticmethod
    def hadamard_paleyI(n: int) -> 'Matrix':
        from samson.math.factorization.general import factor
        from samson.math.algebra.fields.finite_field import FiniteField as FF

        assert factor(n-1).is_prime_power() and not n % 4

        q = n-1
        F = FF(*list(factor(q).items())[0])

        M = Matrix.fill(ZZ.zero, q+1, q+1)
        for i in range(1, q+1):
            M[0,i] = 1
            M[i,0] = -1

        for i in range(q):
            for j in range(q):
                M[i+1, j+1] = (F.element_at(i) - F.element_at(j)).quadratic_character()
        

        for i in range(n):
            M[i,i] = -1
        
        return M


    def conference_to_hadamard(self):
        I = Matrix.identity(self.num_rows, self.coeff_ring)
        assert self*self.T == I*(self.num_rows-1)

        M0 = (self+I).row_join(self-I)
        M1 = (self-I).row_join(-self-I)
        return M0.col_join(M1)


    def is_linearly_independent(self) -> bool:
        if self.num_rows > self.num_cols:
            return False

        elif self.num_cols > self.num_rows:
            return self*~self == Matrix.identity(self.num_rows, self.coeff_ring)

        return bool(self.det())


    def find_linearly_dependent_rows(self) -> list:
        return [i for i,r in enumerate((self*~self - Matrix.identity(self.num_rows, self.coeff_ring))) if any(r)]


    def remove_rows(self, indices):
        indices = set(indices)
        return Matrix([r for i,r in enumerate(self.rows) if i not in indices])


    def is_basis(self) -> bool:
        # The idea is that any basis can be rewritten as another basis
        # If we generate the identity, then we can generate any other vector
        return self.is_square() and self * ~self == self.ring.one


    def __getitem__(self, idx: object) -> 'RingElement':
        if type(idx) is tuple:
            if type(idx[0]) is slice:
                val = [row[idx[1]] for row in self.rows[idx[0]]]

                if type(val[0]) is not list:
                    val = [[v] for v in val]

                return Matrix(val)

            else:
                val = self.rows[idx[0]][idx[1]]
                if type(val) is list:
                    if type(idx[0]) is slice:
                        val = [[v] for v in val]
                    else:
                        val = [val]

                    val = Matrix(val)

                return val
        else:
            if type(idx) is slice:
                return Matrix(self.rows[idx])
            else:
                return DenseVector(self.rows[idx])


    def __setitem__(self, idx, value):
        # Just trying to get `value` into a list of lists
        t_value = type(value)
        if t_value is DenseVector:
            value = [value.values]

        elif t_value is Matrix:
            value = value.rows

        elif t_value is list:
            if type(value[0]) is not list:
                value = [value]
            else:
                value = value

        elif value in self.coeff_ring:
            value = [self.coeff_ring(value)]


        if type(idx) is tuple:
            if type(idx[0]) is slice:
                if type(idx[1]) is slice:
                    for row, val in zip(self.rows[idx[0]], value):
                        row[idx[1]] = val
                else:
                    for row, val in zip(self.rows[idx[0]], value):
                        row[idx[1]] = val[0]

            else:
                self.rows[idx[0]][idx[1]] = value[0]

        else:
            if type(idx) is not slice:
                value = value[0]

            self.rows[idx] = value


    def __len__(self) -> int:
        return len(self.rows)

    def __or__(self, other: 'Matrix') -> 'Matrix':
        return self.row_join(other)

    def __neg__(self) -> 'Matrix':
        return self.apply_elementwise(lambda elem: -elem)


    def __add__(self, other: 'Matrix') -> 'Matrix':
        if type(other) == type(self):
            return Matrix([[self.rows[r][c] + other.rows[r][c] for c in range(self.num_cols)] for r in range(self.num_rows)], coeff_ring=self.coeff_ring, ring=self.ring)
        else:
            raise ValueError("other type not addible")


    def __mul__(self, other: 'Matrix') -> 'Matrix':
        if type(other) is Matrix:
            s_rows = self.num_rows
            s_cols = self.num_cols
            o_cols = other.num_cols
            o_rows = other.num_rows

            if s_cols != o_rows:
                raise ValueError(f"Cannot multiply {s_rows}x{s_cols} matrix by {o_rows}x{o_cols} matrix")

            ans = []
            for row in range(s_rows):
                ans.append([])
                for o_col in range(o_cols):
                    col_total = self.coeff_ring.zero
                    for col in range(s_cols):
                        col_total += self.rows[row][col] * other.rows[col][o_col]

                    ans[-1].append(col_total)

            return Matrix(ans, coeff_ring=self.coeff_ring, ring=self.ring)

        else:
            return self.apply_elementwise(lambda elem: elem * other)


    def __invert__(self) -> 'Matrix':
        if self.ring:
            return gaussian_elimination(self, Matrix.identity(len(self), coeff_ring=self.coeff_ring, ring=self.ring))
        else:
            raise ArithmeticError('Matrix is not square and has no ring')


    def pseudoinverse(self):
        B = Matrix.identity(self.num_cols, self.coeff_ring)
        A = B.solve_left(self)
        At = A.T
        Bt = B.T

        Q = (At * A) * (B * Bt)
        return Bt * ~Q * At


    def ground_div(self, other: 'RingElement') -> None:
        if type(other) is not Matrix and other in self.coeff_ring:
            return self * ~self.coeff_ring(other)


    def __floordiv__(self, other: 'Matrix') -> 'Matrix':
        return self / other


    def __eq__(self, other: 'Matrix') -> bool:
        return type(self) == type(other) and self.rows == other.rows


    def __hash__(self):
        return hash((self.__class__, *[tuple(r) for r in self.rows]))