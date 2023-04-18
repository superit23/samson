from samson.utilities.general import add_or_increment
from samson.analysis.general import count_items
from samson.math.general import kth_root, gcd
from samson.core.base_object import BaseObject
from functools import reduce
from itertools import combinations, chain
from sortedcontainers import SortedDict

class Factors(BaseObject):
    def __init__(self, factors=None):
        self.factors = SortedDict(factors or {})


    def __str__(self):
        facs = list(self.factors.items())
        if facs and type(facs[0][0]) is int:
            fac_format = "{fac}"
        else:
            fac_format = "({fac})"

        return ' * '.join([f"{fac_format.format(fac=fac)}{'**' + str(exponent) if exponent > 1 else ''}" for fac, exponent in facs])


    @property
    def __raw__(self):
        return str(self.factors)[11:-1]


    def __reprdir__(self):
        return ['__raw__']


    def __getitem__(self, idx: int):
        return self.factors[idx]

    def __setitem__(self, idx: int, value):
        self.factors[idx] = value

    def __iter__(self):
        return self.factors.__iter__()


    def __getstate__(self):
        return self.factors


    def __setstate__(self, state):
        self.factors = state


    def __len__(self) -> int:
        return len(self.factors)


    def __hash__(self):
        return hash(self.recombine())


    def _compare(self, other, func):
        t = type(other)

        if t in [dict, SortedDict]:
            other = Factors(other)

        elif t is not Factors:
            return func(self.recombine(), other)

        return func(self.recombine(), other.recombine())


    def __eq__(self, other):
        return self._compare(other, lambda a, b: a == b)


    def __lt__(self, other):
        return self._compare(other, lambda a, b: a < b)


    def __gt__(self, other):
        return self._compare(other, lambda a, b: a > b)


    def __ge__(self, other):
        return self._compare(other, lambda a, b: a >= b)


    def __le__(self, other):
        return self._compare(other, lambda a, b: a <= b)



    def __add__(self, other: dict) -> 'Factors':
        if type(other) not in (dict, Factors):
            from samson.math.factorization.general import factor
            other = factor(other)

        new_facs = Factors()
        for key in self:
            new_facs.add(key, self[key])

        for key in other:
            new_facs.add(key, other[key])

        return new_facs


    def __pow__(self, exp: int) -> 'Factors':
        return Factors({p: e*exp for p,e in self.factors.items()})


    def __truediv__(self, other: 'RingElement') -> 'Factors':
        t = type(other)
        if t is int:
            from samson.math.factorization.general import trial_division
            keys  = list(self.keys())
            if -1 in keys:
                keys.remove(-1)

            other = trial_division(other, prime_base=keys)

        elif t not in [Factors, dict, SortedDict]:
            other = other.factor()

        return self.difference(other)


    __mul__ = __add__
    __floordiv__ = __truediv__
    __sub__ = __truediv__


    def __getattr__(self, name: str):
        try:
            attr = object.__getattribute__(self, name)
        except AttributeError:
            attr = getattr(self.factors, name)

        return attr


    def add(self, factor: 'RingElement', number: int=1):
        add_or_increment(self.factors, factor, number)


    def remove(self, factor: 'RingElement', number: int=1):
        if number >= self.factors[factor]:
            del self.factors[factor]
        else:
            self.factors[factor] -= number


    def difference(self, other: dict) -> 'Factors':
        facs = Factors({})
        for key in self:
            facs[key] = self[key]
            if key in other:
                facs.remove(key, other[key])

        if not facs:
            if key and hasattr(key, 'ring'):
                facs[key.ring.one] = 1
            else:
                facs[1] = 1

        return facs


    def expand(self) -> list:
        facs = [[fac]*exponent for fac, exponent in self.factors.items()]
        return [item for sublist in facs for item in sublist]


    def combinations(self, n: int) -> list:
        return (Factors(count_items(c)) for c in combinations(self.expand(), n))


    def number_of_factors(self) -> int:
        return sum(self.factors.values())


    def all_combinations(self) -> list:
        return chain(*[self.combinations(i) for i in range(1, self.number_of_factors()+1)])


    def all_divisors(self, recombine: bool=True) -> set:
        if recombine:
            return {c.recombine() for c in self.all_combinations()}.union({1})
        else:
            return set(self.all_combinations()).union({Factors({1: 1})})
    

    def square_free(self) -> 'Factors':
        """
        Returns the square-free portion of the factors. Checks to make sure factors
        aren't squares themselves.
        """
        if hasattr(list(self)[0], 'ring'):
            is_square = lambda n: n.is_square()
        else:
            is_square = lambda n: kth_root(n, 2)**2 == n

        squares = Factors({p: e for p,e in self.items() if p > 0 and is_square(p)})
        sqrt    = Factors({p: e // 2 for p,e in self.items()})
        return self // sqrt.recombine()**2 // squares


    divisors = all_divisors

    def _get_one(self):
        n = list(self)[0]
        if hasattr(n, 'ring'):
            return n.ring.one
        else:
            return 1



    def mobius(self) -> int:
        n = self.recombine()
        if n == self._get_one():
            return 1

        elif max(self.factors.values()) > 1:
            return 0

        elif self.number_of_factors() % 2:
            return -1

        else:
            return 1


    def recombine(self) -> 'RingElement':
        if not self.factors:
            return 1

        elem0 = list(self.factors.keys())[0]
        mul   = type(elem0).__mul__
        one   = elem0.ring.one if hasattr(elem0, 'ring') else 1
        return reduce(mul, [p**e for p,e in self.factors.items()], one)


    def is_prime_power(self):
        n = self.recombine()
        return len(self) == 1 and n != self._get_one()
    

    def largest_root(self):
        return gcd(*self.factors.values())


    def is_perfect_power(self):
        return self.largest_root() > 1


    def kth_root(self, k: int):
        max_root = self.largest_root()
        if k > max_root:
            raise ValueError(f"Factorization is not {k}-th power")
        
        return Factors({fac: exp // k for fac, exp in self.factors.items()})


    def gcd(self, other: 'Factors') -> 'Factors':
        result = Factors()
        if type(other) is Factors:
            for k,v in self.factors.items():
                if k in other:
                    result[k] = min(other.factors[k], v)
            
            return result
        else:
            from samson.math.factorization.general import trial_division
            keys = list(self.keys())
            if -1 in keys:
                keys.remove(-1)

            other = trial_division(other, prime_base=keys)
            return self.gcd(other)
