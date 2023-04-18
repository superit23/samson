from samson.math.general import is_prime
from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.symbols import Symbol
from samson.math.polynomial import Polynomial
from samson.utilities.exceptions import CoercionException

from samson.auxiliary.lazy_loader import LazyLoader
_factor = LazyLoader('_factor', globals(), 'samson.math.factorization.general')


class FiniteFieldElement(FieldElement):
    """
    Element of a `FiniteField`.
    """

    def __init__(self, val: Polynomial, field: Field):
        """
        Parameters:
            val    (Polynomial): Value of the element.
            field (FiniteField): Parent field.
        """
        self.val = field.internal_field.coerce(val)
        super().__init__(field)


    def __reprdir__(self):
        return ['val', 'field']


    def shorthand(self) -> str:
        return self.field.shorthand() + f'({self.val.shorthand()})'


    def __call__(self, arg):
        return self.val(arg)
    

    def __iter__(self):
        return self.val.val.__iter__()


    def __getitem__(self, idx):
        return self.val.val[idx]


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return int(self)


    def __invert__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(~self.val, self.field)


    def __neg__(self) -> 'FiniteFieldElement':
        return FiniteFieldElement(-self.val, self.field)


    def __elemfloordiv__(self, other: 'FiniteFieldElement') -> 'FiniteFieldElement':
        return self.__truediv__(other)
    

    def degree(self) -> int:
        return self.val.val.degree()



    def minimal_polynomial(self):
        min_poly = 1
        z        = Symbol('z')
        _P       = self.field[z]
        frob     = self
        frob_set = set()

        # Do some Frobenius magic
        for _ in range(self.field.degree()):
            if frob in frob_set:
                break

            frob_set.add(frob)
            min_poly *= (z - frob)
            frob    **= self.field.characteristic()

        return min_poly


    def natural_subfield(self):
        min_poly    = self.minimal_polynomial()
        reduc_poly  = min_poly.change_ring(self.field.internal_ring)
        return self.field.__class__(self.field.p, min_poly.degree(), reducing_poly=reduc_poly)


    def find_subfield_representative(self, subfield, return_all: bool=False):
        # Find isomorphism between natural subfield and provided subfield
        nat = self.natural_subfield()

        if return_all:
            return [nat.isomorphism(subfield, root_idx=i) for i in range(nat.degree())]
        else:
            return nat.isomorphism(subfield)



class FiniteField(Field):
    """
    Finite field of GF(p**n) constructed using a `PolynomialRing`.

    Examples:
        >>> from samson.math import *
        >>> from samson.math.symbols import Symbol
        >>> x = Symbol('x')
        >>> F = FiniteField(2, 8)
        >>> assert F[5] / F[5] == F(1)
        >>> F[x]/(x**7 + x**2 + 1)
        <QuotientRing: ring=F_(2^8)[x], quotient=x^7 + x^2 + 1>

    """

    def __init__(self, p: int, n: int=1, reducing_poly: Polynomial=None, symbol_repr: str='x'):
        """
        Parameters:
            p                    (int): Prime.
            n                    (int): Exponent.
            reducing_poly (Polynomial): Polynomial to reduce the `PolynomialRing`.
        """
        from samson.math.algebra.rings.integer_ring import ZZ

        assert is_prime(p)
        self.p = p
        self.n = n

        self.internal_ring = ZZ/ZZ(p)

        if reducing_poly:
            assert reducing_poly.coeff_ring == self.internal_ring
            x = Symbol(reducing_poly.symbol.repr)
            P = self.internal_ring[x]

        else:
            x = Symbol(symbol_repr)
            P = self.internal_ring[x]

            if n == 1:
                reducing_poly = Polynomial([0, 1], self.internal_ring)

            else:
                reducing_poly = P.find_irreducible_poly(n)


        self.reducing_poly  = reducing_poly
        self.internal_field = P/P(reducing_poly)
        if n > 1:
            self.internal_field.quotient.cache_div((n-1)*2)

        self.symbol          = x
        self.symbol.top_ring = self

        self.zero = self.coerce(0)
        self.one  = self.coerce(1)
        super().__init__()


    def __reprdir__(self):
        return ['p', 'n', 'reducing_poly',]


    def __hash__(self) -> int:
        return hash((self.internal_field, self.__class__))


    def shorthand(self) -> str:
        return f'F_({self.p}^{self.n})' if self.n > 1 else f'F_{self.p}'


    def characteristic(self) -> int:
        return self.p


    def order(self) -> int:
        return self.p**self.n


    def degree(self) -> int:
        return self.reducing_poly.degree()


    def is_superstructure_of(self, R: 'Ring') -> bool:
        """
        Determines whether `self` is a superstructure of `R`.

        Parameters:
            R (Ring): Possible substructure.

        Returns:
            bool: Whether `self` is a superstructure of `R`.
        """
        return self.internal_field.is_superstructure_of(R)


    def coerce(self, other: object) -> FiniteFieldElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            FiniteFieldElement: Coerced element.
        """
        if not type(other) is FiniteFieldElement:
            other = FiniteFieldElement(self.internal_field(other), self)
        elif other.field.p != self.p:
            raise CoercionException("Coerced object characteristic mismatches")
        elif other.field.n != self.n:
            other = FiniteFieldElement(self.internal_field(other.val.val), self)

        return other


    def element_at(self, x: int) -> FiniteFieldElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           FiniteFieldElement: The `x`-th element.
        """
        return FiniteFieldElement(self.internal_field.element_at(x), self)


    def random(self, size: FiniteFieldElement=None) -> FiniteFieldElement:
        if size is not None:
            size = size.val
        return self(self.internal_field.random(size))


    def __eq__(self, other: 'FiniteField') -> bool:
        return type(self) == type(other) and self.p == other.p and self.n == other.n


    def isomorphism(self, other: 'FiniteField', root_idx: int=0) -> list:
        from samson.math.algebra.fields.finite_field_isomorphism import FiniteFieldIsomorphism
        return FiniteFieldIsomorphism(self, other, root_idx=root_idx)


    def extension(self, degree: int) -> ('Map', 'Field'):
        from samson.math.algebra.fields.finite_field_isomorphism import FiniteFieldHomomorphism
        from samson.math.map import Map

        if type(degree) is int:
            if degree == 1:
                return Map(self, self, map_func=lambda a: a), self

            codomain = self.__class__(self.p, degree*self.n)
        else:
            codomain = self.__class__(p=self.p, n=degree.degree(), reducing_poly=degree)

        return FiniteFieldHomomorphism(self, codomain), codomain
