from samson.utilities.runtime import RUNTIME
from samson.utilities.exceptions import CoercionException
from samson.auxiliary.theme import POLY_COLOR_WHEEL, color_format
from samson.math.algebra.rings.ring import Ring, RingElement
from samson.math.polynomial import Polynomial
from samson.math.algebra.rings.polynomial_ring import PolynomialRing
from samson.math.matrix import Matrix
from samson.math.algebra.rings.integer_ring import ZZ
from samson.core.base_object import BaseObject
from enum import Enum


def lex(m1, m2):
    return sorted([m1, m2], key=lambda mon: mon.degrees, reverse=True)

def deglex(m1, m2):
    return sorted(lex(m1, m2), key=lambda mon: mon.total(), reverse=True)

def grevlex(m1, m2):
    return sorted(lex(m1, m2)[::-1], key=lambda mon: mon.total(), reverse=True)


# Note these order from GREATEST to LEAST
class MonomialOrdering(Enum):
    LEX     = 'lex'
    DEGLEX  = 'deglex'
    GREVLEX = 'grevlex'


_order_func_map = {
    MonomialOrdering.LEX: lex,
    MonomialOrdering.DEGLEX: deglex,
    MonomialOrdering.GREVLEX: grevlex
}


class MultivariatePolynomial(RingElement):
    def __init__(self, coeffs, symbols: list, ring=None, coeff_ring=None, ordering: MonomialOrdering=None) -> None:
        coeffs = dict(coeffs)

        if not coeffs:
            coeffs = {tuple([0]*len(symbols)): coeff_ring.zero}
        
        if not ring:
            ring = MultivariatePolynomialRing(coeff_ring, symbols)

        coeff_ring = coeff_ring or list(coeffs.values())[0].ring

        self.coeffs  = {k: coeff_ring(v) for k,v in coeffs.items()}
        self.symbols = symbols
        self.coeff_ring = coeff_ring
        self.ring = ring
        self.ordering = ordering
    

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.coeffs == other.coeffs


    def __reprdir__(self):
        return ['__raw__', 'coeff_ring']


    @property
    def __raw__(self):
        return str(self)


    def __str__(self):
        return RUNTIME.default_short_printer(self)
    

    def is_constant(self):
        return len(self.coeffs) == 1 and list(self.coeffs.keys())[0] == tuple([0]*len(self.symbols))


    def shorthand(self, tinyhand: bool=False):
        poly_repr = []
        constant_vec = tuple([0]*len(self.symbols))

        if not self.is_constant():
            idx_color = POLY_COLOR_WHEEL[(self.coeff_ring.structure_depth()-1) % len(POLY_COLOR_WHEEL)]

            for exp_vec, coeff in sorted(self.coeffs.items(), key=lambda kv: Monomial(kv[0], self.ordering)):
                # Skip zero coeffs unless the poly is zero
                if coeff == coeff.ring.zero and not len(self.coeffs) == 1:
                    continue

                # Remove implicit ones
                if coeff == coeff.ring.one and exp_vec != constant_vec:
                    coeff_short_mul = ''
                else:
                    if tinyhand:
                        shorthand = coeff.tinyhand()
                    else:
                        shorthand = coeff.shorthand()

                    if exp_vec != constant_vec:
                        shorthand = f'({shorthand})'
                
                    if exp_vec == constant_vec:
                        coeff_short_mul = shorthand
                    else:
                        coeff_short_mul = shorthand + "*"

                # Handle special indices
                exp_strs = []
                for exp, symbol in zip(exp_vec, self.symbols):
                    if exp == 0:
                        str_exp = ''
                    elif exp == 1:
                        str_exp = str(symbol)
                    else:
                        str_exp = f'{symbol}{RUNTIME.poly_exp_separator}{color_format(idx_color, exp)}'
                    
                    if str_exp:
                        exp_strs.append(str_exp)
                
                full_exp_str = '*'.join(exp_strs)
                full_coeff   = coeff_short_mul + full_exp_str

                poly_repr.append(full_coeff)

            return ' + '.join(poly_repr[::-1])
        else:
            return self.coeffs[constant_vec].shorthand()



    tinyhand = shorthand


    def __elemadd__(self, other):
        coeff_vector = {k:v for k,v in self.coeffs.items()}

        for exp_vec, coeff in other.coeffs.items():
            if exp_vec in coeff_vector:
                coeff_vector[exp_vec] += coeff
            else:
                coeff_vector[exp_vec] = coeff
        
        return self.ring._create_poly(coeff_vector)


    def __elemmul__(self, other):
        coeff_vector = {}

        for exp_vec_s, coeff_s in self.coeffs.items():
            for exp_vec_o, coeff_o in other.coeffs.items():
                exponent = [0]*len(self.symbols)

                for e in range(len(self.symbols)):
                    exponent[e] += exp_vec_s[e]

                for e in range(len(self.symbols)):
                    exponent[e] += exp_vec_o[e]
    

                exponent = tuple(exponent)

                if exponent in coeff_vector:
                    coeff_vector[exponent] += coeff_s * coeff_o
                else:
                    coeff_vector[exponent]  = coeff_s * coeff_o
        
        return self.ring._create_poly(coeff_vector)


    def __elemdivmod__(self, other):
        try:
            return lead_red(self, other)
        except ValueError:
            return self.ring.zero, self


    def __elemmod__(self, other):
        return divmod(self, other)[1]


    def __elemfloordiv__(self, other):
        return divmod(self, other)[0]


    def __neg__(self):
        return self.ring._create_poly({k:-v for k,v in self.coeffs.items()})


    def __call__(self, **kwargs):
        return self.evaluate(**kwargs)


    def evaluate(self, auto_peel: bool=True, **kwargs):
        result    = {}
        sym_reprs = [s.repr for s in self.symbols]
        sym_locs  = {sym_reprs.index(sym): val for sym,val in kwargs.items()}

        for exp_vec, coeff in self.coeffs.items():
            term_result = coeff

            result_exp_vec = [0]*len(self.symbols)

            for idx, exp in enumerate(exp_vec):
                # Allow partial evaluation
                if idx in sym_locs:
                    term_result *= sym_locs[idx]**exp
                    result_exp_vec[idx] = 0

                else:
                    result_exp_vec[idx] = exp
            
            result_exp_vec = tuple(result_exp_vec)
            result[result_exp_vec] = result.get(result_exp_vec, self.coeff_ring.zero) + term_result


        # Coerce result dict into poly
        result = self.ring(result)

        # Peel if constant
        if auto_peel and result.is_constant():
            return result[tuple([0]*len(self.symbols))]
        else:
            return result
    

    def monomials(self):
        return sorted([Monomial(exp_vec, self.ordering) for exp_vec in self.coeffs], reverse=True)
    

    def lc(self):
        return self.coeffs[self.lm().degrees]


    def lm(self):
        return self.monomials()[0]


    def lt(self):
        return self.ring._create_poly({self.lm().degrees: self.lc()})
    

    def __hash__(self) -> int:
        return hash(tuple(self.coeffs))
    

    def __getitem__(self, idx):
        if type(idx) is tuple:
            return self.coeffs.get(idx, self.coeff_ring.zero)

        elif type(idx) is Monomial:
            return self.coeffs.get(idx.degrees, self.coeff_ring.zero)
        
        elif type(idx) is MultivariatePolynomial and len(idx.coeffs) == 1:
            return self.coeffs.get(list(idx.coeffs)[0], self.coeff_ring.zero)

        else:
            raise ValueError
    

    def make_univariate(self, symbol):
        idx = self.symbols.index(symbol)
        return Polynomial({exp_vec[idx]: coeff for exp_vec,coeff in self.coeffs.items()})


    def is_univariate_in(self, symbol):
        idx = self.symbols.index(symbol)
        for exp_vec in self.coeffs:
            if any(e for i,e in enumerate(exp_vec) if i != idx):
                return False
        
        return True
    

    def monic(self):
        if self:
            return self*self.ring(~self.lc())
        else:
            return self
    

    def change_ring(self, ring):
        MP = MultivariatePolynomialRing(ring=ring, symbols=self.symbols, ordering=self.ordering)
        return MP({exp_vec: ring(coeff) for exp_vec, coeff in self.coeffs.items()})



    def kronecker_substitution(self, symbol, max_degree, idx):
        from copy import copy
        f = self
        p = f.coeff_ring.characteristic()
        d = max_degree
        n = 2*(p-1).bit_length()+(d).bit_length()
        a = f.change_ring(ZZ)(**{symbol.repr: 2**(n*(idx+1))})

        symbols = copy(self.symbols)
        sym_idx = symbols.index(symbol)
        symbols.remove(symbol)

        MP = MultivariatePolynomialRing(ring=self.coeff_ring, symbols=symbols, ordering=self.ordering)
        a.coeffs  = {tuple(exp[:sym_idx] + exp[sym_idx+1:]):coeff for exp,coeff in a.coeffs.items()}
        a.ring    = MP
        a.symbols = symbols
        return a
        



class MultivariatePolynomialRing(Ring):
    def __init__(self, ring, symbols, ordering=MonomialOrdering.DEGLEX) -> None:
        self.ring = ring
        self.symbols = sorted(symbols, key=lambda sym: sym.repr)
        self.ordering = ordering
        self.one  = self(1)
        self.zero = self(0)

        for sym in self.symbols:
            sym.build(self)
            sym.top_ring = self
    

    def __reprdir__(self):
        return ['ring', 'symbols', 'ordering']
    

    def __eq__(self, other):
        return self.__class__ == other.__class__ and self.ring == other.ring and self.symbols == other.symbols
    

    def shorthand(self) -> str:
        return f'{self.ring.shorthand()}[{",".join([s.repr for s in self.symbols])}]'
    

    def is_field(self):
        return False


    def _create_poly(self, coeffs):
        return MultivariatePolynomial({k:v for k,v in coeffs.items() if v}, coeff_ring=self.ring, ring=self, symbols=self.symbols, ordering=self.ordering)


    def coerce(self, other: object) -> MultivariatePolynomial:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            MultivariatePolynomial: Coerced element.
        """
        type_o = type(other)

        if type_o in [list, dict]:
            return self._create_poly(other)


        # Lift univariates in same ring to multivariate
        elif type_o is Polynomial and self.ring.is_superstructure_of(other.ring.ring):#s or other.coeff_ring.one in self.ring):
            sym_idx = self.symbols.index(other.symbol)
            return self._create_poly({tuple([0]*sym_idx + [idx] + [0]*(len(self.symbols)-sym_idx-1)): coeff for idx, coeff in other.coeffs.values.items()})

        elif type_o is MultivariatePolynomial:
            if other.ring == self:
                return other

            # Check if strict subset, then lift
            elif set(other.ring.symbols).issubset(set(self.symbols)) and set(other.ring.symbols) != set(self.symbols):
                syms     = other.symbols
                sym_idxs = {sym: self.symbols.index(sym) for sym in syms}
                coeffs   = {}

                for exp_vec_o, coeff in other.coeffs.items():
                    exp_vec = [0]*len(self.symbols)

                    for sym, exp in zip(other.symbols, exp_vec_o):
                        exp_vec[sym_idxs[sym]] = exp
                    
                    coeffs[tuple(exp_vec)] = coeff

                return self._create_poly(coeffs)


        # Handle lifting univariate polynomials
        elif type_o is Polynomial:
            def get_sym_order(poly):
                syms = [poly.symbol]
                ring = poly.ring

                while type(ring.ring) is PolynomialRing:
                    ring = ring.ring
                    syms.append(ring.symbol)
                
                return syms, ring.ring


            def get_coeff_vecs(poly):
                exp_vecs = []
                for exp, coeff in poly.coeffs.values.items():
                    if type(coeff) is Polynomial:
                        for lower_vec, c in get_coeff_vecs(coeff):
                            exp_vecs.append(([exp] + lower_vec, c))
                    else:
                        exp_vecs.append(([exp], coeff))
                
                return exp_vecs


            # We need to reorder the symbols to make sure they match up with their sorting
            orig_order, base_ring = get_sym_order(other)
            new_order = sorted(orig_order, key=lambda sym: sym.repr)
            order_map = [orig_order.index(new_sym) for new_sym in new_order]

            coeff_vecs = get_coeff_vecs(other)

            # Create possible subring and lift layered univariate to multivariate
            P = MultivariatePolynomialRing(ring=base_ring, symbols=new_order, ordering=self.ordering)
            lifted = P._create_poly({tuple([exp_vec[i] for i in order_map]): coeff for exp_vec, coeff in coeff_vecs})

            return self.coerce(lifted)

                

        # Handle constants
        elif type_o is int or hasattr(other, 'ring') and other in self.ring:
            return self._create_poly({tuple([0]*len(self.symbols)): self.ring(other)})
        
        raise CoercionException(self, other)


    def groebner_basis(self, polynomials):
        return GroebnerBasis(reduced_basis(buchberger(polynomials)))



class Monomial(BaseObject):
    def __init__(self, degrees, ordering: MonomialOrdering) -> None:
        self.degrees  = degrees
        self.ordering = ordering
    

    def lcm(self, other):
        return Monomial(tuple(max(s,o) for s,o in zip(self.degrees, other.degrees)), self.ordering)


    def gcd(self, other):
        return Monomial(tuple(min(s,o) for s,o in zip(self.degrees, other.degrees)), self.ordering)


    def total(self):
        return sum(self.degrees)


    def divides(self, other):
        return all(s <= o for s,o in zip(self.degrees, other.degrees))


    def __mul__(self, other):
        return Monomial(tuple(s + o for s,o in zip(self.degrees, other.degrees)), self.ordering)


    def __truediv__(self, other):
        return Monomial(tuple(s - o for s,o in zip(self.degrees, other.degrees)), self.ordering)


    def __pow__(self, exp):
        return Monomial(tuple(s * exp for s in self.degrees), self.ordering)


    def __gt__(self, other):
        return self != other and _order_func_map[self.ordering](self, other)[0] == self


    def __lt__(self, other):
        return self != other and _order_func_map[self.ordering](self, other)[0] == other


    def __le__(self, other):
        return not self > other
    
    def __ge__(self, other):
        return not self < other



def S(f1, f2):
    f1lc = f1.lc()
    f2lc = f2.lc()
    f1lm = f1.lm()
    f2lm = f2.lm()

    tau = f1lm.lcm(f2lm)

    return f1.ring({(tau / f1lm).degrees: ~f1lc})*f1 - f1.ring({(tau / f2lm).degrees: ~f2lc})*f2



def lead_red(f, g):
    lmg = g.lm()
    lmf = f.lm()

    if not lmg.divides(lmf):
        raise ValueError

    div = f.ring({(lmf/lmg).degrees: f[lmf]/g.lc()})
    res = f - div*g
    if not res.lm() < f.lm():
        raise ValueError

    return div, res



def red1(f, g):
    lmg = g.lm()
    m   = None

    for mon in f.monomials():
        if lmg.divides(mon):
            m = mon
    
    if m is None:
        raise ValueError


    print(lmg, m)    
    print(f.lm(), (f.ring({(m/lmg).degrees: f[m]/g.lc()})*g).lm())
    print()

    return f - f.ring({(m/lmg).degrees: f[m]/g.lc()})*g



def buchberger(F):
    """
    References:
        https://www.theoremoftheday.org/MathsStudyGroup/Buchberger.pdf
    """
    G  = [f for f in F if f]
    checked = set()

    while True:
        ret_to_top = False
        Gp = [_ for _ in G]

        for i,gi in enumerate(Gp):
            for j, gj in enumerate(Gp):
                if i != j and (i,j) not in checked:
                    s = S(gi, gj)

                    for g in Gp:
                        try:
                            while s:
                                _, s = lead_red(s, g)
                        except ValueError:
                            pass
                    
                    if s:
                        G.append(s)
                        ret_to_top = True
                        break
                    else:
                        # Prevent redoing this work later
                        checked.add((i,j))
            
            if ret_to_top:
                break
        
        if G == Gp:
            return G



def reduced_basis(B):
    B  = [b.monic() for b in B]
    while True:
        ret_to_top = False
        Bp = [_ for _ in B]

        # Remove basis with same LM
        for i,f in enumerate(Bp):
            for j,g in enumerate(Bp):
                if i != j:
                    if f.lm().divides(g.lm()):
                        try:
                            B.remove(g)
                            ret_to_top = True
                            break
                        except ValueError:
                            pass
            
            if ret_to_top:
                break

        if B == Bp:
            return B


class GroebnerBasis(BaseObject):
    def __init__(self, B: list) -> None:
        self.B = B
    

    def __contains__(self, p):
        return self.generates(p)


    def __iter__(self):
        return self.B.__iter__()
    

    def __getitem__(self, idx):
        return self.B[idx]


    def reduce(self, p):
        s = p
        comb = []
        for d in self.B:
            try:
                div, s = lead_red(s, d)
                comb.append((div, d))
            except ValueError:
                pass
        
        if s:
            raise ValueError

        return comb


    def generates(self, p):
        try:
            self.reduce(p)
            return True
        except ValueError:
            return False


    def to_matrix(self):
        mons = sorted(set([item for sublist in [b.monomials() for b in self.B] for item in sublist]))
        rows = []
        R    = self.B[0].coeff_ring

        for b in self.B:
            row = []
            for mon in mons:
                row.append(b[mon])
            
            rows.append(row)
        
        return Matrix(rows, R), mons