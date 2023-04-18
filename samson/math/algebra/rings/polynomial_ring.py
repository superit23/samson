from samson.math.algebra.rings.ring import RingElement, Ring
from samson.utilities.exceptions import CoercionException, ProbabilisticFailureException
from samson.math.polynomial import Polynomial
from samson.math.symbols import Symbol, oo
from samson.math.general import random_int, is_prime, random_int_between, next_prime, int_to_poly
from samson.math.factorization.general import factor
from samson.auxiliary.gf2_irreducible_poly_db import build_gf2_irreducible_poly
import math

from samson.auxiliary.lazy_loader import LazyLoader
_integer_ring  = LazyLoader('_integer_ring', globals(), 'samson.math.algebra.rings.integer_ring')


class PolynomialRing(Ring):
    """
    Ring of polynomials over a ring.

    Examples:
        >>> from samson.math.all import *
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> poly_ring = (ZZ/ZZ(53))[x]
        >>> poly_ring(x**3 + 4*x - 3)
        <Polynomial: x^3 + (4)*x + 50, coeff_ring=ZZ/(ZZ(53))>

    """

    def __init__(self, ring: Ring, symbol: Symbol=None, use_karatsuba: bool=False):
        """
        Parameters:
            ring (Ring): Underlying ring.
        """
        super().__init__()
        self.use_karatsuba = use_karatsuba
        self.ring   = ring
        self.symbol = symbol or Symbol('x')
        self.symbol.build(self)
        symbol.top_ring = self

        self.zero = Polynomial([self.ring.zero], coeff_ring=self.ring, ring=self, symbol=self.symbol)
        self.one  = Polynomial([self.ring.one], coeff_ring=self.ring, ring=self, symbol=self.symbol)


    def characteristic(self):
        return self.ring.characteristic()


    def order(self) -> int:
        return oo


    def __reprdir__(self):
        return ['ring']


    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[{self.symbol}]'


    def __eq__(self, other: 'PolynomialRing') -> bool:
        return type(self) == type(other) and self.ring == other.ring


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))
    

    def _elem_is_sub_poly(self, elem):
        return elem.ring == self.ring


    def coerce(self, other: object) -> Polynomial:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            Polynomial: Coerced element.
        """
        from samson.math.sparse_vector import SparseVector

        type_o = type(other)

        if type_o in [list, dict, SparseVector]:
            return Polynomial(other, coeff_ring=self.ring, ring=self, symbol=self.symbol)


        elif type_o is Polynomial:
            if other.ring == self:
                return other

            # This check is in case we're using multivariate polynomials
            elif other.ring == self.ring:
                return self.coerce([other])

            elif self.ring.is_superstructure_of(other.ring):
                return self.coerce([self.ring(other)])

            elif self.ring.is_superstructure_of(other.coeff_ring):
                try:
                    coeff_coerced = other.change_ring(self.ring)
                    coeff_coerced.symbol = self.symbol
                    return coeff_coerced
                except CoercionException:
                    pass

        elif type_o is Symbol and other.var and other.var.ring == self:
            return other.var

        # Handle grounds
        elif type_o is int or hasattr(other, 'ring') and other in self.ring:
            return self.coerce([self.ring(other)])


        raise CoercionException(self, other)


    def element_at(self, x: int) -> Polynomial:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           Polynomial: The `x`-th element.
        """
        base_coeffs = []
        modulus     = self.ring.order()

        if modulus != 0:
            # Use != to handle negative numbers
            while x != 0 and x != -1:
                x, r = divmod(x, modulus)
                base_coeffs.append(self.ring[r])

            return self(base_coeffs)
        else:
            return self([x])


    def find_gen(self) -> 'Polynomial':
        """
        Finds a generator of the `Ring`.

        Returns:
            RingElement: A generator element.
        """
        return self.symbol


    def _find_irred_ZZ(self, n, elem_size, sparsity=None):
        """
        References:
            https://en.wikipedia.org/wiki/Cohn%27s_irreducibility_criterion
        """
        sparsity = max(sparsity or 2, 1)
        r = elem_size**(random_int(sparsity-1))*random_int_between(1, elem_size-1)
        p = next_prime(elem_size**n+r)

        while True:
            q = int_to_poly(p, elem_size)

            if q.coeffs.sparsity <= sparsity:
                q = q.change_ring(_integer_ring.ZZ)
                q.is_irreducible.user_cache[q] = True
                return q
            
            p = next_prime(p+1)
            if p >= elem_size**n:
                sparsity += 1
                r = elem_size**(random_int(sparsity-1))*random_int_between(1,elem_size-1)
                p = next_prime(elem_size**n+r)



    def find_irreducible_poly(self, n: int, sparsity: int=None, elem_size: RingElement=None) -> Polynomial:
        """
        Finds a sparse, irreducible polynomial. Uses as many unit values as possible.

        Parameters:
            n                 (int): Degree.
            sparsity          (int): Number of non-zeroes to have.
            elem_size (RingElement): Maximum size of randomly generated element.

        Returns:
            Polynomial: Irreducible polynomial
        """
        if self.ring == _integer_ring.ZZ:
            return self._find_irred_ZZ(n=n, sparsity=sparsity, elem_size=elem_size)

        elif self.characteristic() == 2:
            return build_gf2_irreducible_poly(self, n)

        logn = math.ceil(math.log(n, 2))
        sparsity = max(sparsity or logn-2, 1)
        x = self.symbol
        p = x**n

        degrees = list(range(1,n))
        R       = self.ring
        one     = R.one

        max_attempts = n*(logn+1)

        while sparsity < n:
            for _ in range(max_attempts):
                degrees.sort(key=lambda i: random_int(n**2))
                q = p
                for d in degrees[:sparsity-1]:
                    q += one*x**d

                q += R.random(elem_size)*x**degrees[sparsity-1]
                q += one

                if q.is_irreducible():
                    return q
            
            sparsity += 1
        
        raise ProbabilisticFailureException


    def number_of_irreducible(self, n: int) -> int:
        """
        Determine the number of irreducible polynomials over a FiniteField.

        Parameters:
            n (int): The desired degree of polynomials.

        Returns:
            int: Number of irreducible polynomials of degree `n`.
        """
        if is_prime(self.ring.characteristic()):
            total = 0
            for d in factor(n).divisors(False):
                total += d.mobius()*(self.ring.order())**(n // d.recombine())

            return total // n
        else:
            raise NotImplementedError(f"Not implemented for {self.ring}")


    def random(self, size: object) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/RingElement): The maximum ordinality/element (non-inclusive).

        Returns:
            RingElement: Random element of the algebra.
        """
        if self.characteristic():
            return super().random(size)

        else:
            deg = size.degree()
            max_val = max(size.coeffs.values.values()) + self.ring.one
            return self([self.ring.random(max_val) for _ in range(deg)])


    def interpolate(self, points: list) -> Polynomial:
        """
        Given a list of `points`, returns the polynomial that generates them (i.e. interpolation).

        Parameters:
            points (list): List of points formatted as [(x,y), ...].

        Returns:
            Polynomial: Interpolated polynomial.

        Examples:
            >>> from samson.math.all import ZZ, Symbol
            >>> x = Symbol('x')
            >>> P = ZZ[x]
            >>> q = 10*x**8 + 7*x**7 + 25*x**6 + 6*x**5 + 8*x**4 + 9*x**3 + 4*x**2 + 4*x + 3
            >>> P.interpolate([(i, q(i)) for i in range(q.degree()+1)]) == q
            True

        References:
            https://en.wikipedia.org/wiki/Polynomial_interpolation#Constructing_the_interpolation_polynomial
        """
        from samson.utilities.exceptions import NoSolutionException
        from samson.math.algebra.fields.fraction_field import FractionField
        from samson.math.matrix import Matrix

        R = self.ring
        not_field = not R.is_field()

        # Gaussian elimination requires a field
        if not_field:
            R = FractionField(R)
            points = [(R(x), R(y)) for x,y in points]

        # Build the Vandermonde matrix
        degree = len(points)
        a      = Matrix([[p[0] for p in points]], R).T
        vand   = a.apply_elementwise(lambda elem: elem**(degree-1))

        for e in reversed(range(degree-1)):
            vand = vand.row_join(a.apply_elementwise(lambda elem: elem**e))

        # Calculate poly
        y      = Matrix([[p[1] for p in points]], R).T
        result = list(vand.LUsolve(y).T[0])

        if not_field:
            if not all([c.denominator == self.ring.one for c in result]):
                raise NoSolutionException(f"No solution in ring {self.ring}")

            result = [c.numerator for c in result]

        return self(result[::-1])



    def binomial(self, n: int, y: 'RingElement'=None, d: int=1) -> 'Polynomial':
        """
        Calculates the powers of a binomial of the form `(x^d + y)^n`.

        Parameters:
            n (int): Power to raise to.
            y (int): Constant coefficient.
            d (int): Degree of the non-constant term.

        Returns:
            Polynomial: Binomial expansion of `(x^d + y)^n`.
        """
        R = self.ring
        result = 1
        coeffs = [R.one]
        c = R(1)
        y = R(y) if y else R.one

        if y == R.one:
            # Happy path, do half the work
            for k in range(n // 2):
                result  *= (n-k)
                result //= (k+1)
                c *= y
                coeffs.append(R(result)*c)

            coeffs = coeffs[::-1]
            return self(coeffs[(n+1) % 2:][::-1] + coeffs).map_coeffs(lambda idx, c: (idx*d, c))
        else:
            for k in range(n):
                result  *= (n-k)
                result //= (k+1)
                c *= y
                coeffs.append(R(result)*c)

            return self(coeffs[::-1]).map_coeffs(lambda idx, c: (idx*d, c))
