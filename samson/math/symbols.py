from samson.math.polynomial import Polynomial
from samson.utilities.exceptions import NoSolutionException

from samson.auxiliary.lazy_loader import LazyLoader
_poly_ring = LazyLoader('_poly_ring', globals(), 'samson.math.algebra.rings.polynomial_ring')

class Infinity(object):
    def __repr__(self):
        return '∞'

    def __eq__(self, other):
        return type(self) == type(other)

    def __str__(self):
        return self.__repr__()

    def __lt__(self, other):
        return False

    def __gt__(self, other):
        return self != other

    def __neg__(self):
        return NegativeInfinity()

    def __add__(self, other):
        if type(other) is NegativeInfinity:
            raise ValueError("Cannot subtract infinity from infinity.")

        return self
    

    def __radd__(self, other):
        return self + other


    def __sub__(self, other):
        if type(other) is Infinity:
            raise ValueError("Cannot subtract infinity from infinity.")

        return self


    def __rsub__(self, other):
        return -self + other


    def __mul__(self, other):
        if not other:
            return other
        elif other == -self:
            return -oo
        
        elif other == self:
            return oo
        
        elif other < 0:
            return -self

        return self


    def __rmul__(self, other):
        return self*other

    def __pow__(self, other):
        return self

    def __truediv__(self, other):
        if issubclass(type(other), Infinity):
            raise ValueError("Cannot divide infinity by infinity.")

        return self

    def __rtruediv__(self, other):
        return 0


    def __floordiv__(self, other):
        return self / other


    def __rfloordiv__(self, other):
        return 0


class NegativeInfinity(Infinity):
    def __repr__(self):
        return '-∞'

    def __str__(self):
        return self.__repr__()

    def __lt__(self, other):
        return self != other

    def __gt__(self, other):
        return False

    def __neg__(self):
        return Infinity()


    def __add__(self, other):
        if type(other) is Infinity:
            raise ValueError("Cannot subtract infinity from infinity.")

        return self

    def __sub__(self, other):
        if type(other) is NegativeInfinity:
            raise ValueError("Cannot subtract infinity from infinity.")

        return self


    def __pow__(self, exp):
        return ((exp % 2)*2 - 1) * self


class Symbol(Polynomial):
    def __init__(self, str_representation):
        self.repr = str_representation
        self.ring = None
        self.var  = None
        self.top_ring = None


    def __reprdir__(self):
        return ['repr', 'ring']

    def __str__(self):
        return self.repr

    def __hash__(self):
        return hash(self.var)

    def __eq__(self, other: 'Symbol') -> bool:
        return type(self) == type(other) and self.repr == other.repr and self.ring == other.ring

    def __bool__(self) -> bool:
        return True


    def __top_coerce(self, poly):
        me = self.var

        if self.top_ring:
            if not hasattr(poly, 'ring') or self.top_ring.is_superstructure_of(poly.ring):
                poly = self.top_ring(poly)
                me   = self.top_ring(me)

            elif poly.ring.is_superstructure_of(self.top_ring):
                me = poly.ring(me)

        return me, poly


    def __add__(self, other):
        me, other = self.__top_coerce(other)
        return  me + other

    def __radd__(self, other):
        me, other = self.__top_coerce(other)
        return other + me


    def __sub__(self, other):
        me, other = self.__top_coerce(other)
        return me - other

    def __rsub__(self, other):
        me, other = self.__top_coerce(other)
        return other - me


    def __mul__(self, other):
        me, other = self.__top_coerce(other)
        return me * other


    def __rmul__(self, other):
        me, other = self.__top_coerce(other)
        return other * me


    def __invert__(self):
        me, _ = self.__top_coerce(self.var)
        return ~me


    def __truediv__(self, other):
        me, other = self.__top_coerce(other)
        return me / other


    def __lshift__(self, other):
        me, poly = self.__top_coerce(self.var << other)
        return poly


    def __rshift__(self, other):
        me, poly = self.__top_coerce(self.var >> other)
        return poly


    def __divmod__(self, other):
        me, other = self.__top_coerce(other)
        return divmod(me, other)


    def __floordiv__(self, other):
        me, other = self.__top_coerce(other)
        return me // other


    def __mod__(self, other):
        me, other = self.__top_coerce(other)
        return me % other


    def __pow__(self, power):
        poly = self.var._create_poly({power: self.ring.ring.one})
        return self.__top_coerce(poly)[1]


    def build(self, ring):
        self.ring = ring
        self.var  = Polynomial([ring.ring.zero, ring.ring.one], coeff_ring=ring.ring, ring=ring, symbol=self)


    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.var, name)

        return attr


    def adjoin(self, base_ring: 'Ring'):
        return _poly_ring.PolynomialRing(base_ring, self)



oo = Infinity()

class Root(Symbol):
    def __init__(self, minimal_poly, repr: str=None):
        self.minimal_poly = minimal_poly
        self.repr = repr or self._find_repr()

    
    def _find_repr(self):
        # Of the form x^k + c
        if self.minimal_poly.coeffs.sparsity == 2 and self.minimal_poly[0]:
            k = self.minimal_poly.degree()
            c = -self.minimal_poly[0]
            trans_sup = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")

            if k == 2:
                return f'√{c}'
            else:
                root_deg_str = ''
                for char in str(k):
                    root_deg_str += chr(trans_sup[ord(char)])

                return f'{root_deg_str}√{c}'

        # Prime cyclotomic poly
        elif self.minimal_poly.coeffs.sparsity == self.minimal_poly.degree() + 1 == sum(self.minimal_poly):
            trans_sub = str.maketrans("0123456789", "₀₁₂₃₄₅₆₇₈₉")
            return f'ξ{chr(trans_sub[ord(str(self.minimal_poly.degree() + 1))])}'

        else:
            return str(self.minimal_poly).replace(self.minimal_poly.symbol.repr, 'α')



    def __reprdir__(self):
        return ['__raw__']


    @property
    def __raw__(self):
        return self.repr

    
    def __getattribute__(self, name):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = object.__getattribute__(self.minimal_poly, name)

        return attr


    def adjoin(self, base_ring: 'Ring'):
        P = super().adjoin(base_ring)
        Q = P/self.minimal_poly.change_ring(P.ring)
        self.top_ring = Q
        return Q



def root(element, k: int):
    try:
        return element.kth_root(k)
    except NoSolutionException:
        x = Symbol('x')
        _ = element.ring[x]
        r = Root(x**k - element)
        _ = element.ring.polynomial_ring(r)
        return r 