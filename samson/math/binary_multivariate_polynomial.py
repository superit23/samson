from copy import copy

class BinaryMultivariatePolynomial(object):
    def __init__(self, coeffs: set, symbols) -> None:
        self.coeffs  = coeffs
        self.symbols = symbols


    def __add__(self, other):
        c_coeffs = copy(self.coeffs)
        for b in other.coeffs:
            if b in c_coeffs:
                c_coeffs.remove(b)
            else:
                c_coeffs.add(b)
        
        return BinaryMultivariatePolynomial(c_coeffs, symbols=self.symbols)
    

    def  __sub__(self, other):
        return self + other
    

    def __neg__(self):
        return self


    def __mul__(self, other):
        c_coeffs = set()

        for a_exp in self.coeffs:
            for b_exp in other.coeffs:
                c_exp = a_exp | b_exp

                if c_exp in c_coeffs:
                    c_coeffs.remove(c_exp)
                else:
                    c_coeffs.add(c_exp)

        return BinaryMultivariatePolynomial(c_coeffs, symbols=self.symbols)


    def __pow__(self, exp):
        if exp:
            return self
        else:
            return BinaryMultivariatePolynomial(set(), symbols=self.symbols)


    def evaluate(self, **kwargs):
        result    = set()
        sym_reprs = [s.repr for s in self.symbols]
        sym_locs  = {len(self.symbols)-sym_reprs.index(sym)-1: val for sym,val in kwargs.items()}

        zeroes = sum(1 << idx for idx, val in sym_locs.items() if not val)
        ones   = sum(1 << idx for idx, val in sym_locs.items() if val)

        for c in self.coeffs:
            if c & zeroes:
                continue

            c -= c & ones
            if c in result:
                result.remove(c)
            else:
                result.add(c)

        return BinaryMultivariatePolynomial(result, symbols=self.symbols)
