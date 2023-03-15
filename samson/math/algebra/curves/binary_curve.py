from samson.math.algebra.curves.weierstrass_curve import WeierstrassCurve, WeierstrassPoint, EllipticCurveCardAlg

class BinaryCurvePoint(WeierstrassPoint):
    def __init__(self, x: 'RingElement', y: 'RingElement', curve: 'WeierstrassCurve', z: 'RingElement' = None):
        super().__init__(x, y, curve, z)

    def __neg__(self) -> 'WeierstrassPoint':
        return BinaryCurvePoint(self._x, self._x + self._y, self.ring)


    def __double(self):
        lamb = self._x + self._y/self._x
        x3   = lamb**2 + lamb + self.ring.a
        y3   = lamb*(self._x + x3) + x3 + self._y

        return BinaryCurvePoint(x3, y3, self.ring)


    def __add(self, Q):
        lamb = (self._y + Q._y) / (self._x + Q._x)
        x3   = lamb**2 + lamb + self.ring.a + self._x + Q._x
        y3   = lamb*(self._x + x3) + x3 + self._y
        return BinaryCurvePoint(x3, y3, self.ring)


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



class BinaryCurve(WeierstrassCurve):
    _POINT_CLS = BinaryCurvePoint

    def __init__(self, a: 'RingElement', b: 'RingElement', ring: 'Ring' = None, base_tuple: tuple = None, cardinality: int = None, check_singularity: bool = True, cm_discriminant: int = None, embedding_degree: int = None):
        super().__init__(a, b, ring, base_tuple, cardinality, check_singularity, cm_discriminant, embedding_degree)


    def cardinality(self, algorithm: 'EllipticCurveCardAlg' = EllipticCurveCardAlg.AUTO, check_supersingular: bool = True) -> int:
        pass
