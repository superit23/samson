from samson.math.algebra.fields.finite_field import FiniteField, FiniteFieldElement
from samson.math.algebra.fields.field import FieldElement
from samson.math.fft.ntt import NTTParameters, NTTPointValueForm
from samson.math.algebra.rings.integer_ring import ZZ

class PVFFElement(FiniteFieldElement):

    def __init__(self, val: 'FiniteFieldElement', field: 'Field'):
        """
        Parameters:
            val (Polynomial): Value of the element.
            field      (GF2): Parent field.
        """
        if type(val) is FiniteFieldElement:
            val = field.params.fft(val.val.val.change_ring(ZZ))

        self.val: NTTPointValueForm = val
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


    def poly(self):
        return self.field.internal_ff(self.val.ifft())
        # n, m   = self.val.length, self.field.cache.divisor.degree()
        # T      = self.field.cache.T.copy()
        # T.prec = n-m+1
        # res    = T((self.field.ppv*self.val).ifft().change_ring(self.field.internal_ff.internal_ring)).val.reverse()
        # return self.field.internal_ff(res << (n-m-res.degree()))


    def __elemadd__(self, other):
        return PVFFElement(self.val + other.val, self.field)


    def __elemmul__(self, other):
        return PVFFElement(self.val * other.val, self.field)


    def __invert__(self) -> 'PVFFElement':
        return self**(self.field.internal_ff.p**self.field.internal_ff.n-2)


    def __neg__(self) -> 'PVFFElement':
        return self.copy()


    def __elemfloordiv__(self, other: 'PVFFElement') -> 'PVFFElement':
        return self.__truediv__(other)



class PVFField(FiniteField):
    def __init__(self, internal_ff: FiniteField):
        self.internal_ff = internal_ff
        self.d = self.internal_ff.reducing_poly.degree()

        self.params = NTTParameters.build(6*(self.d-1), self.internal_ff.characteristic()**4)
        self.internal_ff.reducing_poly.cache_div(self.d-1)
        self.cache  = self.internal_ff.reducing_poly._Polynomial__div_cache
        pz  = self.cache.g.val.change_ring(ZZ)
        self.ppv = self.params.fft(pz)


    @property
    def p(self):
        return self.internal_ff.p

    @property
    def n(self):
        return self.internal_ff.n

    @property
    def reducing_poly(self):
        return self.internal_ff.reducing_poly


    def coerce(self, other: object) -> PVFFElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            PVFFElement: Coerced element.
        """
        if not type(other) is PVFFElement:
            other = PVFFElement(other, self)

        return other


    def element_at(self, x: int) -> PVFFElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           PVFFElement: The `x`-th element.
        """
        return PVFFElement(self.internal_ff.element_at(x), self)


    def random(self, size: PVFFElement=None) -> PVFFElement:
        if size is not None:
            size = size.val
        else:
            size = 2**self.n
        return self(self.internal_ff.random())
