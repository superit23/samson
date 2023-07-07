from samson.math.general import mod_inv
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import oo
from fractions import Fraction


class FractionFieldElement(FieldElement):
    """
    Element of a `FractionField`.
    """

    def __init__(self, numerator: FieldElement, denominator: FieldElement, field: Field):
        """
        Parameters:
            numerator   (FieldElement): Numerator of the fraction.
            denominator (FieldElement): Denominator of the fraction.
            field      (FractionField): Parent field.
        """
        if field.simplify:
            try:
                # Simplification in non-integral domains
                # Total ring of fractions
                if hasattr(denominator, 'partial_inverse'):
                    n, d        = denominator.partial_inverse()
                    numerator  *= n
                    denominator = d

                d             = numerator.gcd(denominator)
                numerator   //= d
                denominator //= d
            except Exception:
                pass

        if denominator == field.ring.zero:
            raise ZeroDivisionError

        self.numerator   = field.ring(numerator)
        self.denominator = field.ring(denominator)
        super().__init__(field)

        if self.ring.precision:
            self.trim_to_precision()




    def shorthand(self) -> str:
        return f'{self.field.shorthand()}({self.numerator}/{self.denominator})'


    def tinyhand(self) -> str:
        return f'{self.numerator.tinyhand()}{"/" + str(self.denominator.tinyhand()) if self.denominator != self.ring.ring.one else ""}'


    def __hash__(self):
        return hash((self.numerator, self.denominator, self.field))

    def __eq__(self, other: 'FractionFieldElement'):
        other = self.ring.coerce(other)
        return type(self) == type(other) and self.numerator * other.denominator == self.denominator * other.numerator


    def __call__(self, x: int) -> 'RingElement':
        return self.numerator(x) / self.denominator(x)


    def __reprdir__(self):
        return ['numerator', 'denominator', 'field']


    def valuation(self, p: int) -> int:
        from samson.math.symbols import oo

        if not self:
            return oo

        return self.numerator.valuation(p) - self.denominator.valuation(p)


    def kth_root(self, k: int, **kwargs) -> 'FractionFieldElement':
        return self.__class__(self.numerator.kth_root(k, **kwargs), self.denominator.kth_root(k, **kwargs), self.ring)


    def sqrt(self) -> 'FractionFieldElement':
        return self.__class__(self.numerator.sqrt(), self.denominator.sqrt(), self.ring)


    def trim_to_precision(self) -> 'FractionFieldElement':
        """
        WARNING: Side effect based.

        Attempts to trim `self` so that the error is less than `precision`.
        """
        precision      = self.ring.precision
        precision_type = self.ring.precision_type

        if precision_type == 'relative':
            if self.numerator != self.denominator and self.ring.ring.one not in [self.numerator, self.denominator]:
                if self.numerator > self.denominator:
                    q,r = divmod(self.numerator, self.denominator)
                    den = self.ring.ring.one
                    num = q

                    compare_num = r
                    compare_den = abs(q)


                elif self.numerator < self.denominator:
                    q,r = divmod(self.denominator, self.numerator)
                    num = self.ring.ring.one
                    den = q

                    compare_num = r
                    compare_den = self.denominator

                if compare_num * precision.denominator < precision.numerator * compare_den:
                    self.numerator   = num
                    self.denominator = den
        else:
            if self.denominator > precision:
                q,r = divmod(self.numerator, self.denominator)
                c   = self.ring(r / self.denominator * precision)

                self.numerator   = q * precision + c.numerator // c.denominator
                self.denominator = precision


    def gcd(self, other):
        from samson.math.general import lcm
        return self.ring((self.numerator.gcd(other.numerator), lcm(self.denominator, other.denominator)))


    def is_integral(self) -> bool:
        return self.denominator == self.ring.ring.one


    def __elemadd__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        return self.__class__(self.numerator * other.denominator + self.denominator * other.numerator, self.denominator * other.denominator, self.ring)


    def __elemmul__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        return self.__class__(self.numerator * other.numerator, self.denominator * other.denominator, self.ring)


    def __elemmod__(self, other: 'FractionFieldElement') -> 'FractionFieldElement':
        if not other:
            raise ZeroDivisionError
        
        if not self:
            return self.ring.zero

        other = self.ring.ring(other)

        n = self.numerator % other
        d = self.denominator % other
        d = mod_inv(d, other)

        return self.ring((n*d) % other)


    def __neg__(self) -> 'FractionFieldElement':
        return self.__class__(-self.numerator, self.denominator, self.ring)


    def __invert__(self) -> 'FractionFieldElement':
        if not self:
            raise ZeroDivisionError

        return self.__class__(self.denominator, self.numerator, self.ring)


    def __float__(self):
        return int(self.numerator) / int(self.denominator)

    def __int__(self):
        return int(self.numerator) // int(self.denominator)


    def __round__(self):
        q,r = divmod(self.numerator, self.denominator)
        R = self.ring.ring
        return q + (R.one if r*2 >= self.denominator else R.zero)



    def __lt__(self, other: 'FractionFieldElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator < other.numerator * self.denominator


    def __gt__(self, other: 'FractionFieldElement') -> bool:
        other = self.ring.coerce(other)
        if self.ring != other.ring:
            raise ValueError("Cannot compare elements with different underlying rings.")

        return self.numerator * other.denominator > other.numerator * self.denominator


class FractionField(Field):
    """
    Fraction field over a ring.

    Examples:
        >>> from samson.math.algebra.rings.integer_ring import IntegerRing
        >>> QQ = FractionField(IntegerRing())
        >>> assert QQ(5) * QQ((1, 5)) == QQ.one

    """

    def __init__(self, ring: Ring, simplify: bool=True):
        """
        Parameters:
            ring     (Ring): Underlying ring.
            simplify (bool): Whether or not to simplify the fraction.
        """
        super().__init__()
        self.ring      = ring
        self.simplify  = simplify
        self.precision = None
        self.precision_type = None

        self.zero = FractionFieldElement(self.ring.zero, self.ring.one, self)
        self.one  = FractionFieldElement(self.ring.one, self.ring.one, self)



    def __reprdir__(self):
        return ['ring']


    def __hash__(self) -> int:
        return hash((self.ring, self.__class__))


    def __eq__(self, other: 'FractionField'):
        return type(self) == type(other) and self.ring == other.ring


    def characteristic(self):
        return self.ring.characteristic()


    def order(self) -> int:
        return self.ring.order()**2


    def set_precision(self, precision: FractionFieldElement, precision_type: str='absolute'):
        """
        Sets the element used for determine whether a trim is acceptable.
        """
        self.precision = precision
        self.precision_type = precision_type


    def random(self, size: int=None) -> FractionFieldElement:
        """
        Generate a random element.

        Parameters:
            size (int): The ring-specific 'size' of the element.
    
        Returns:
            FractionFieldElement: Random element of the algebra.
        """
        if type(size) is int:
            numerator   = size
            denominator = size
        elif size and size in self:
            size        = self(size)
            numerator   = size.numerator
            denominator = size.denominator
        else:
            numerator   = self.ring.random(size)
            denominator = self.ring.random(size)

        return FractionFieldElement(self.ring.random(numerator), max(self.ring.one, self.ring.random(denominator)), self)


    def shorthand(self) -> str:
        return f'Frac({self.ring})'


    def coerce(self, other: object) -> FractionFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            FractionFieldElement: Coerced element.
        """
        type_other = type(other)
        if type_other is FractionFieldElement:
            return other

        elif type_other is float and self.ring == ZZ:
            frac = Fraction(other)
            result = (self.ring.coerce(frac.numerator), self.ring.coerce(frac.denominator))

        elif type_other is tuple:
            if len(other) < 2:
                denom = self.ring.one
            else:
                denom = self.ring.coerce(other[1])

            result = (self.ring.coerce(other[0]), denom)
        else:
            result = (self.ring.coerce(other), self.ring.one)


        return FractionFieldElement(*result, self)


    def field_extension(self, degree: int) -> ('Map', 'Field'):
        if self.ring == ZZ:
            Q = ZZ.field_extension(degree).fraction_field()
            return Q._coerce_map(self), Q
        else:
            return super().field_extension(degree)


    def _base_ext_degree(self):
        return oo
