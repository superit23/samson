from samson.math.algebra.fields.finite_field import FiniteField, FiniteFieldElement
from samson.math.algebra.fields.field import FieldElement
from samson.math.general import random_int, int_to_poly, poly_to_int

class GF2Element(FiniteFieldElement):
    """
    Element of a `GF2`.
    """

    def __init__(self, val: 'Polynomial', field: 'Field'):
        """
        Parameters:
            val (Polynomial): Value of the element.
            field      (GF2): Parent field.
        """
        if type(val) is int:
            self.val = val
        else:
            self.val = int(field.internal_field.coerce(val))

        super(FieldElement, self).__init__(field)
        self.field = field
    


    def __reprdir__(self):
        return ['val', 'field']


    def shorthand(self) -> str:
        return self.field.shorthand() + f'({self.val})'


    def tinyhand(self) -> str:
        return str(self.val)


    def ordinality(self) -> int:
        """
        The ordinality of this element within the set.

        Returns:
            int: Ordinality.
        """
        return int(self)


    def degree(self):
        return self.val.bit_length()-1


    def __elemadd__(self, other):
        return GF2Element(self.val ^ other.val, self.field)


    def __elemmul__(self, other):
        p = self.field.poly_int
        m = 0
        n = self.field.n
        q = 2**n
        r = 2**(n-1)
        x,y = self.val, other.val

        for _ in range(n):
            m <<= 1
            if m & q:
                m ^= p
            if y & r:
                m ^= x
            y <<= 1
        return GF2Element(m, self.field)


    def __invert__(self) -> 'GF2Element':
        return self**(self.field.p**self.field.n-2)


    def __neg__(self) -> 'GF2Element':
        return self.copy()


    def __elemfloordiv__(self, other: 'GF2Element') -> 'GF2Element':
        return self.__truediv__(other)


    def __getitem__(self, idx):
        return self.ring.internal_ring((self.val >> idx) & 1)


class GF2(FiniteField):
    def __init__(self, n: int = 1, reducing_poly: 'Polynomial' = None, symbol_repr: str = 'x'):
        super().__init__(2, n, reducing_poly, symbol_repr)
        self.poly_int = int(self.reducing_poly)


    def coerce(self, other: object) -> GF2Element:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            GF2Element: Coerced element.
        """
        if not type(other) is GF2Element:
            if type(other) is int and other < self.p**self.n:
                other = GF2Element(other, self)
            else:
                other = GF2Element(poly_to_int(self.internal_field(int_to_poly(other, self.p)).val), self)

        return other


    def element_at(self, x: int) -> GF2Element:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           GF2Element: The `x`-th element.
        """
        return GF2Element(self.internal_field.element_at(x), self)


    def random(self, size: GF2Element=None) -> GF2Element:
        if size is not None:
            size = size.val
        else:
            size = 2**self.n
        return self(random_int(size))


    def degree(self):
        return self.n


    def extension(self, degree: int) -> ('Map', 'Field'):
        from samson.math.algebra.fields.finite_field_isomorphism import FiniteFieldHomomorphism
        from samson.math.map import Map

        if type(degree) is int:
            if degree == 1:
                return Map(self, self, map_func=lambda a: a), self

            codomain = self.__class__(degree*self.n)
        else:
            codomain = self.__class__(n=degree.degree(), reducing_poly=degree)

        return FiniteFieldHomomorphism(self, codomain), codomain
