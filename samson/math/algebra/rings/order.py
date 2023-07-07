from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ, _get_QQ
from samson.math.general import hilbert_class_polynomial, is_prime, product, cyclotomic_polynomial, cornacchias_algorithm, xgcd
from samson.math.symbols import Symbol, oo
from samson.math.factorization.general import factor, Factors
from samson.math.matrix import Matrix
from samson.utilities.exceptions import NoSolutionException, NotInvertibleException


QQ = _get_QQ()

class OrderElement(RingElement):
    def __init__(self, val: RingElement, ring: Ring):
        super().__init__(ring)
        self.val = val


    def __reprdir__(self):
        return ['val', 'ring']


    def __neg__(self) -> 'OrderElement':
        return self.__class__(-self.val, self.ring)


    def is_prime(self) -> bool:
        p = self.val.val
        K = self.ring

        if self in [K(0), K(1)]:
            return False

        if p.degree():
            return p.is_irreducible()
        else:
            n = int(p[0])
            if not n % K.discriminant():
                return False

            return is_prime(abs(n)) and K.defining_polynomial.change_ring(ZZ/ZZ(abs(n))).is_irreducible()


    is_irreducible = is_prime


    def factor(self) -> 'Factors':
        """
        References:
            https://math.stackexchange.com/questions/1033901/prime-ideals-of-the-ring-of-integers-of-an-algebraic-number-field
            https://cstheory.stackexchange.com/questions/16214/complexity-of-factoring-in-number-fields
            https://people.math.umass.edu/~weston/cn/notes.pdf
        """
        K = self.ring

        if self in (K.zero, K.one) or self.is_prime():
            return Factors({self: 1})

        m = self.val.val
        d = m.degree()

        if d:
            m_facs  = m.factor()
            factors = Factors()

            for fac, e in m_facs.items():
                k_fac = K(fac)

                if k_fac.val.val.degree():
                    factors.add(k_fac)
                else:
                    factors += k_fac.factor()**e

            return factors


        n = int(m[0])

        # K(n) can only be prime if `n` is
        # Note the converse is not true i.e. 11 may not be prime in K
        if is_prime(abs(n)):
            negate = False
            if n < 0:
                negate = True
                n = -n


            if not n % K.discriminant():
                facs = {K.symbol*1: K.degree()}

                if n // K.discriminant() < 0 and not negate:
                    facs[K(-1)] = 1

                return Factors(facs)


            q = K.defining_polynomial.change_ring(ZZ/ZZ(n))

            if q.is_irreducible():
                factors = Factors({K(n): 1})

                if negate:
                    factors.add(K(-1))
                
                return factors


            facs = q.factor()

            K_facs = [f.change_ring(ZZ)(K.symbol) for f in facs.expand()]
            for i in range(2**K.degree()):
                candidates = [k+n*-int(b) for k,b in zip(K_facs, bin(i)[2:].zfill(K.degree()))]
                prod = product(candidates)

                if prod in [K(n), -K(n)]:
                    facs = Factors()
                    if (prod == -K(n)) ^ negate:
                        candidates.append(K(-1))

                    for cand in candidates:
                        facs.add(cand)
                    return facs


        else:
            neg_one = K(-1)
            if n == -1:
                return Factors({neg_one: 1})

            facs = Factors()
            for p, e in factor(n).items():
                facs += K(p).factor()**e
            

            if neg_one in facs:
                facs[neg_one] %= 2

                if not facs[neg_one]:
                    del facs.factors[neg_one]


            return facs


    def __iter__(self):
        z = QQ.zero
        d = self.ring.degree()
        n = self.val.val.degree()+1

        for c in (list(self.val.val) + [z]*(d-n)):
            yield c


    def matrix(self) -> Matrix:
        cur = Matrix([list(self)])
        X   = self.ring.generator_matrix()
        v   = [list(cur)[0]]

        for _ in range(self.ring.degree()-1):
            cur *= X
            v   += [list(cur)[0]]

        return Matrix(v)


    def is_rational(self) -> bool:
        return not self.val.val.degree()


    def minimum_polynomial(self) -> 'Polynomial':
        if self.is_rational():
            x = Symbol('x')
            _ = ZZ[x]
            return x - list(self)[0]

        else:
            return self.matrix().characteristic_polynomial()


    def norm(self) -> RingElement:
        return ZZ(self.matrix().det())


    def trace(self) -> RingElement:
        return ZZ(self.matrix().trace())
    

    # def __elemfloordiv__(self, other: 'RingElement') -> 'RingElement':
       
    #     if self.is_rational() and other.is_rational():
    #         return self.ring(self.val // other.val)
    #     else:
    #         sf = self.factor()
    #         of = other.factor()




    def gcd(self, other: 'OrderElement') -> 'OrderElement':
        R = self.ring

        if R.is_field():
            return R.one
        elif self.is_rational() and other.is_rational():
            return self.val.gcd(other.val)
        else:
            return R(self.factor().gcd(other.factor()).recombine())




class Order(Ring):
    ELEMENT_TYPE = OrderElement

    def __init__(self, defining_polynomial: 'Polynomial'):
        if not defining_polynomial.is_irreducible():
            raise ValueError(f"{defining_polynomial} is not irreducible")

        self.defining_polynomial = defining_polynomial.change_ring(QQ)
        self.symbol          = defining_polynomial.symbol
        self.ring            = QQ[self.symbol]
        self.internal_ring   = self.ring/self.defining_polynomial
        self.symbol.top_ring = self

        self.one  = self.ELEMENT_TYPE(self.internal_ring.one, self)
        self.zero = self.ELEMENT_TYPE(self.internal_ring.zero, self)


    def __reprdir__(self):
        return ['defining_polynomial']


    def __hash__(self) -> int:
        return hash((self.internal_ring, self.__class__))


    def shorthand(self) -> str:
        return f'ZZ[{self.symbol}]'


    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        return oo


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        return self.internal_ring.is_superstructure_of(R)


    def coerce(self, other: object) -> OrderElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            OrderElement: Coerced element.
        """
        if not type(other) is self.ELEMENT_TYPE:
            other = self.ELEMENT_TYPE(self.internal_ring(other), self)

        return other


    def element_at(self, x: int) -> OrderElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           OrderElement: The `x`-th element.
        """
        return self.ELEMENT_TYPE(self.internal_ring.element_at(x), self)


    def random(self, size: OrderElement=None) -> OrderElement:
        if size is not None:
            size = size.val
        return self(self.internal_ring.random(size))


    def __eq__(self, other: 'NumberField') -> bool:
        return type(self) == type(other) and self.internal_ring == other.internal_ring


    def is_field(self) -> bool:
        return False


    def degree(self) -> int:
        return self.defining_polynomial.degree()


    def discriminant(self) -> int:
        return self.defining_polynomial.discriminant()


    def generator_matrix(self) -> Matrix:
        x = self.symbol
        a = x
        d = self.degree()
        v = [list((x*1))]

        for _ in range(d-1):
            a *= x
            v += [list(a)]
        
        return Matrix(v)



class QuadraticFieldElement(OrderElement):
    def factor(self) -> Factors:
        """
        Factors the element in the ring of integers.

        References:
            https://math.stackexchange.com/questions/1043480/how-to-factor-ideals-in-a-quadratic-number-field

        Examples:
            >>> from samson.math.algebra.rings.order import QuadraticField
            >>> K = QuadraticField(-7)
            >>> K(12).factor()
            <Factors: {<QuadraticFieldElement: val=-3, ring=ZZ[√-1]>: 1, <QuadraticFieldElement: val=√-1 + 1, ring=ZZ[√-1]>: 4}>

            >>> (K(3)*K(5)).factor()
            <Factors: {<QuadraticFieldElement: val=3, ring=ZZ[√-7]>: 1, <QuadraticFieldElement: val=5, ring=ZZ[√-7]>: 1}>

            >>> (K(3)*K(3)).factor()
            <Factors: {<QuadraticFieldElement: val=3, ring=ZZ[√-7]>: 2}>

            >>> c = (K(3)*K(3)*K(5)*K(2)*K(a+49)*K(2*a+991))
            >>> c.factor().recombine() == c
            True

            >>> K = QuadraticField(-1)
            >>> K(2).factor()
            <Factors: {<QuadraticFieldElement: val=(-1)*√-1, ring=ZZ[√-1]>: 1, <QuadraticFieldElement: val=√-1 + 1, ring=ZZ[√-1]>: 2}>

            >>> K = QuadraticField(-11)
            >>> K(2).factor()
            <Factors: {<QuadraticFieldElement: val=2, ring=ZZ[√-11]>: 1}>

            >>> a = K.symbol
            >>> d = K(a + 1)/2
            >>> (K(3)*d).factor()
            <Factors: {<QuadraticFieldElement: val=(-1/2)*√-11 + 1/2, ring=ZZ[√-11]>: 1, <QuadraticFieldElement: val=(1/2)*√-11 + 1/2, ring=ZZ[√-11]>: 2}>

        """
        p = self.val.val
        K = self.ring

        facs = Factors()
        curr = self

        if not self.is_prime():
            d = K.defining_polynomial[0]
            a = K.symbol

            for p, e in self.norm().factor().items():
                # Handle primes with non-prime norms
                Kp = K(p)
                if not e % 2 and Kp.norm() == p**2 and Kp.is_prime():
                    facs.add(Kp, e // 2)
                    curr /= Kp**(e // 2)
                    continue

                # Attempt to find element from norm
                for _ in range(e):
                    try:
                        x, y  = cornacchias_algorithm(d, int(p))
                        fac   = K(x + a*y)
                        curr /= fac
                        facs.add(fac)

                    except NoSolutionException:
                        # Handle fractional prime case
                        x = QQ(1)/2
                        if K.discriminant() % 4 == 1 and x**2 + d*x**2 == p:
                            fac  = K(x + a*x)
                            conj = fac.conjugate()

                            for c in (fac, conj):
                                result = curr / c

                                # If it's not in OK, denominator will be 4
                                if result.val.val.content().denominator in (1, 2):
                                    curr = result
                                    facs.add(c)

        if curr != self.ring.one:
            facs.add(curr)

        return facs


    def conjugate(self) -> 'OrderElement':
        p = self.val.val
        return self.ring(p[0] + -p[1]*self.ring.symbol)


    def is_prime(self) -> bool:
        """
        References:
            https://kconrad.math.uconn.edu/blurbs/gradnumthy/quadraticgrad.pdf
        """
        if abs(self.norm()).is_prime():
            return True
        
        x = Symbol('x')
        ZZ[x]

        d = self.ring.discriminant()
        if d % 4 == 1:
            f = x**2 - x + (1-d) // 4
        else:
            f = self.ring.defining_polynomial

    
        if self.is_rational():
            p = abs(int(self.val.val[0]))
            return is_prime(p) and f.change_ring(ZZ/ZZ(p)).is_irreducible()


        for p in self.norm().factor():
            try:
                cornacchias_algorithm(-d, int(4*p))
                return False
            except NoSolutionException:
                pass

            try:
                cornacchias_algorithm(-d, int(p))
                return False
            except NoSolutionException:
                pass

        return True


    def __invert__(self) -> 'RingElement':
        a = self.val.val
        n = self.ring.defining_polynomial

        _, x, _ = xgcd(a, n)

        if self.ring(a * x) != self.ring.one:
            raise NotInvertibleException(f"{self} is not invertible", parameters={'a': a, 'x': x, 'n': n})

        return self.ring(x)



class QuadraticField(Order):
    ELEMENT_TYPE = QuadraticFieldElement

    def __init__(self, D: int, symbol_name: str=None) -> 'Order':
        if ZZ(D).is_square():
            raise ValueError(f'"D" ({D}) cannot be square')
        
        if not symbol_name:
            symbol_name = f'√{D}'

        x = Symbol(symbol_name)
        QQ[x]

        super().__init__(x**2 - D)


    def discriminant(self) -> int:
        D = ZZ(self.defining_polynomial.discriminant())
        d = factor(int(D)).square_free().recombine()

        if d % 4 != 1:
            d *= 4
        
        return d


    def hilbert_class_polynomial(self) -> 'Polynomial':
        disc = self.discriminant()

        if disc > 0:
            raise ValueError('Discriminant cannot be positive')

        return hilbert_class_polynomial(int(disc))



class CyclotomicField(Order):
    def __init__(self, n: int) -> 'Order':
        self.n = n
        super().__init__(cyclotomic_polynomial(n))


    def discriminant(self) -> int:
        """
        References:
            https://math.stackexchange.com/questions/240651/the-discriminant-of-the-cyclotomic-phi-px
            https://github.com/sagemath/sage/blob/a60179ab6b642246ee54120e43fdf9663afe5638/src/sage/rings/number_field/number_field.py#L11319
        """
        deg     = self.defining_polynomial.degree()
        d       = 1
        factors = factor(self.n)

        for (p, r) in factors.items():
            e = (r*p - r - 1) * deg // (p-1)
            d *= p**e

        sign = 1

        if len(factors) == 1 and (self.n == 4 or list(factors)[0] % 4 == 3):
            sign = -1
        elif len(factors) == 2 and list(factors.items())[0] == (2, 1) and list(factors)[1] % 4 == 3:
            sign = -1

        return sign*d
