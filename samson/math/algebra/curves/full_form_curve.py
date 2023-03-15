from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint

class FullFormWeierstrassPoint(WeierstrassPoint):
    """
    References:
        https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html
    """
    def __init__(self, x: 'RingElement', y: 'RingElement', curve: 'WeierstrassCurve', z: 'RingElement' = None):
        super().__init__(x, y, curve, z)


    def __neg__(self) -> 'FullFormWeierstrassPoint':
        a = self.ring.ai
        return FullFormWeierstrassPoint(self._x, -a(1)*self._x - a(3) - self._y, self.curve, self._z)


    def __double(self):
        a    = self.ring.ai
        lamb = (3*self._x**2 + 2*a(2)*self._x - a(1)*self._y + a(4)) / (2*self._y + a(1)*self._x + a(3))
        x3   = lamb*(lamb + a(1)) - a(2) - 2*self._x
        y3   = -a(1)*x3 - a(3) - lamb*(x3 + self._x) - self._y

        return FullFormWeierstrassPoint(x3, y3, self.ring)


    def __add(self, Q):
        a    = self.ring.ai
        lamb = (Q._y - self._y) / (Q._x - self._x)
        x3   = lamb*(lamb + a(1)) - a(2) - self._x - Q._x
        y3   = -a(1)*x3 - a(3) - lamb*(x3 + self._x) - self._y

        return FullFormWeierstrassPoint(x3, y3, self.ring)


    def add_no_cache(self, P2: 'WeierstrassPoint') -> 'WeierstrassPoint':
        if self.curve.POINT_AT_INFINITY == P2:
            return self

        elif self.curve.POINT_AT_INFINITY == self:
            return P2


        if self == P2:
            return self.__double()
        elif self == -P2:
            return self.curve.POINT_AT_INFINITY
        else:
            return self.__add(P2)


class FullFormWeierstrassCurve(WeierstrassCurve):
    _POINT_CLS = FullFormWeierstrassPoint

    def __init__(self, a: 'List[RingElement]', ring: 'Ring' = None, base_tuple: tuple = None, cardinality: int = None, check_singularity: bool = True, cm_discriminant: int = None, embedding_degree: int = None):
        super().__init__(a[3], a[5], ring, base_tuple, cardinality, check_singularity, cm_discriminant, embedding_degree)
        self._a = a
    

    def ai(self, i):
        return self._a[i-1]
