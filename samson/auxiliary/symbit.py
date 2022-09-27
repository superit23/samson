from samson.core.base_object import BaseObject
from samson.math.polynomial import Polynomial
from samson.math.algebra.rings.integer_ring import ZZ
from samson.math.symbols import Symbol
from samson.utilities.bytes import Bytes
from samson.auxiliary.constraint_system import bv_process, SolveFor
from copy import copy
from typing import List
import linecache
from enum import Enum
import itertools
import inspect


class Op(Enum):
    AND = 0
    OR  = 1
    XOR = 2
    IMP = 3
    NOT = 4
    EQ  = 5


_OP_MAP_WORDS = {
    Op.AND: 'AND',
    Op.OR: 'OR',
    Op.XOR: 'XOR',
    Op.IMP: 'IMP',
    Op.NOT: 'NOT ',
    Op.EQ: 'EQ',
}

_OP_MAP_SYM = {
    Op.AND: '&',
    Op.OR: '|',
    Op.XOR: '^',
    Op.IMP: '@',
    Op.NOT: '~',
    Op.EQ: '==',
}


def parse_poly(poly, OP_MAP):
    coeffs  = list(poly)
    content = poly.content()

    if content > poly.coeff_ring.one:
        return f'{parse_poly(content, OP_MAP)} & {parse_poly(poly // content, OP_MAP)}'

    if type(coeffs[0]) is Polynomial:
        coeffs = [parse_poly(c, OP_MAP) for c in poly]


    if len(coeffs) == 1:
        coeffs += [0]


    c0, c1 = coeffs
    if not c1 and not c0:
        return ''

    elif c1 and not c0:
        return poly.symbol.repr

    elif c1 and c0 and type(c0) is not str:
        return f'{OP_MAP[Op.NOT]}{poly.symbol.repr}'
    
    elif not c1 and c0 and type(c0) is not Polynomial:
        return '1'

    elif not c1 and c0:
        return c0.symbol.repr
    
    elif type(c0) is str and c0 and c1:
        
        c1_mod = f'{c1} {OP_MAP[Op.AND]} {poly.symbol.repr}'

        if type(c1) is str:
            if c1 == '1':
                c1_mod = f'{poly.symbol.repr}'
            elif c1 == '0':
                c1_mod = ''


        c0_mod = f' {OP_MAP[Op.XOR]} {c0}'
        if type(c0) is str:
            if c0 == '0':
                return f'{c1_mod}'
            elif c0 == '1':
                return f'~{c1_mod}'

        return f'({c1_mod}{c0_mod})'

    elif c0 and c1:
        return f'({c0} {OP_MAP[Op.XOR]} {c1})'



def collapse_poly(poly):
    if type(poly) is not Polynomial:
        return poly

    if type(poly[0]) is Polynomial:
        poly = poly.map_coeffs(lambda i,c: (i, collapse_poly(c)))

    # Every degree > 1 is `x` AND `x`, AKA the identity!
    # We can collapse the coefficients above degree 0 into a new degree 1
    c1 = sum(list(poly >> 1))
    c0 = poly[0]

    # This is about 2x as slow, but it handles when poly can't coerce c0 or c1
    if poly.ring in (c0.ring, c1.ring) or c1.ring.is_superstructure_of(poly.ring) or c0.ring.is_superstructure_of(poly.ring):
        result = c1*poly.symbol + c0

        if result.degree() > 1:
            result = collapse_poly(result)
    else:
        result = poly.ring([c0, c1])

    return result


class SymBit(BaseObject):
    def __init__(self, value) -> None:
        self.value = collapse_poly(value)


    def __call__(self, *args, **kwargs):
        return SymBit(self.value(*args, **kwargs))


    def __and__(self, other):
        other = self._coerce(other)
        return SymBit(self.value * other.value)


    def __xor__(self, other):
        other = self._coerce(other)
        return SymBit(self.value + other.value)


    def __invert__(self):
        return SymBit(self.value + 1)


    def __or__(self, other):
        other = self._coerce(other)
        return (self ^ other) ^ (self & other)


    def __eq__(self, other):
        other = self._coerce(other)
        return self ^ ~other


    def __matmul__(self, other):
        other = self._coerce(other)
        return ~self | other


    def is_constant(self):
        return not bool(self.value[1]) and self.value[0] in (self.value.ring.zero, self.value.ring.one)
 

    def __bool__(self):
        return self.value.degree() == 0 and bool(self.value[0])


    def __hash__(self):
        return hash(self.value)
    

    def _coerce(self, other):
        if type(other) is int:
            return SymBit(self.value.ring([other]))
        else:
            return other


    def get_parameters(self):
        curr   = self.value
        params = []
        while type(curr) is Polynomial:
            params.append(curr.symbol.repr)
            curr = curr[0]
        
        return params[::-1]


    def reconstruct(self):
        params   = self.get_parameters()
        body     = parse_poly(self.value, _OP_MAP_SYM)
        params   = ', '.join(params)
        filename = f'<dynamic-{Bytes.random(8).hex().decode()}>'

        # Clean up function
        if body[0] == '(' and body[-1] == ')':
            body = body[1:-1]
        
        body = body.replace('& 1', '')
        body = body.replace('~~', '')

        while '  ' in body:
            body = body.replace('  ', ' ')


        if hasattr(self, 'func'):
            func_name = self.func.__name__
        else:
            func_name = f'dynamic_{Bytes.random(8).hex().decode()}'

        source = f'def {func_name}({params}):\n    return {body}'
        code   = compile(source, filename, 'exec')

        l = {}
        exec(code, {}, l)

        lines = [line + '\n' for line in source.splitlines()]

        linecache.cache[filename] = (len(source), None, lines, filename)
        return l[func_name]


    def build_output_table(self) -> 'IOTable':
        params = self.get_parameters()
        table  = {}
        for args in itertools.product(*[list(range(2)) for _ in range(len(params))]):
            table[args] = self(**dict(zip(params, args)))
        
        return IOTable(table, self.get_parameters())



def build_symbols(parameters: list) -> tuple:
    symbols = tuple([Symbol(param) for param in parameters])
    R = ZZ/ZZ(2)
    P = R[symbols]

    return [SymBit(P(sym)) for sym in symbols], SymBit(P.zero), SymBit(P.one)



class IOTable(BaseObject):
    def __init__(self, table: dict, symbols: list) -> None:
        self.table   = table
        self.symbols = symbols
    

    def pretty(self):
        from rich.table import Table
        from rich import print

        table = Table(title="Output Table", show_lines=True)

        styles  = itertools.cycle(["dim white", "green", "magenta", "yellow", "cyan", "dim white"])
        columns = self.symbols + ['Output']

        for name, style in zip(columns, styles):
            table.add_column(name, style="bold " + style, no_wrap=True)

        for args, output in self.table.items():
            table.add_row(*[str(a) for a in args], str(int(output)))

        print()
        print(table)



    def build_symbit(self) -> 'Symbit':
        symbols, zero, one = build_symbols(self.symbols)
        func = zero

        for k,v in self.table.items():
            curr = one
            if v:
                for sym, val in zip(symbols, k):
                    if not val:
                        sym = ~sym
                    
                    curr &= sym
                
                func ^= curr
        
        return func


    def serialize(self) -> Bytes:
        out_string = [None] * len(self.table)

        for in_args, output in self.table.items():
            pos = int(''.join([str(a) for a in in_args]), 2)
            out_string[pos] = int(output)

        return Bytes(len(self.symbols)) + Bytes(int(''.join([str(b) for b in out_string]), 2))


    @staticmethod
    def deserialize(in_bytes: bytes) -> 'IOTable':
        import string
        num_args = in_bytes[0]
        symbols  = string.ascii_letters[:num_args]
        outputs  = [int(b) for b in bin(Bytes.wrap(in_bytes[1:]).int())[2:].zfill(len(symbols))]

        return IOTable({tuple([int(b) for b in bin(i)[2:].zfill(len(symbols))]): o for i,o in enumerate(outputs)}, list(symbols))



class SymFunc(SymBit):
    def __init__(self, func, sig, symbols, zero, one, symbolic) -> None:
        self.func = func
        self.sig = sig
        self.symbols = symbols
        self.zero = zero
        self.one = one
        self.symbolic = symbolic


    @staticmethod
    def from_func(func):
        sig  = inspect.signature(func)
        symbols, zero, one  = build_symbols(sig.parameters) 
        symbolic = func(*symbols)
        return SymFunc(func=func, sig=sig, symbols=symbols, zero=zero, one=one, symbolic=symbolic)


    def __call__(self, *args, **kwargs):
        bound = self.sig.bind(*args, **kwargs)
        return self.symbolic(**bound.arguments)


    @property
    def value(self):
        return self.symbolic.value



def check_equiv(func1, func2, num_args):
    for args in itertools.product(*[list(range(2)) for _ in range(num_args)]):
        if (func1(*args) & 1) != (func2(*args) & 1):
            print(args)



class SizableMeta(type):
    SIZABLE_CLS = None

    def __getitem__(cls, size):
        class Inst(cls.SIZABLE_CLS):
            pass

        Inst.__name__ = f'{cls.__name__}[{size}]'
        Inst.SIZE = size
        return Inst



class SymbolSet(BaseObject):
    def __init__(self, symbol_names, size) -> None:
        self.vars = [[Symbol(f'{var}{i}') for i in range(size)] for var in symbol_names]
        symbols   = tuple([item for b in self.vars for item in b])
        self.R    = ZZ/ZZ(2)
        self.P    = self.R[symbols]
    

    def __iter__(self):
        return self.vars.__iter__()


    def __getitem__(self, idx):
        return self.vars[idx]



class FixedBitVector(BaseObject):
    SIZE = None

    def __init__(self, var, symbol_set) -> None:
        self.var_name = var
        self.vars = symbol_set


    def __getitem__(self, idx):
        return self.symbols[idx]


    @property
    def zero(self):
        return SymBit(self.symbols[0].value.coeff_ring.zero)


    @property
    def one(self):
        return SymBit(self.symbols[0].value.coeff_ring.one)


    def __call__(self, *vals, **kwargs):
        size_len = len(str(self.SIZE))
        v_names  = set(v.repr for l in self.vars for v in l)
        v_map    = {v.repr[:-size_len]:l for l in self.vars for v in l}
        val_dict = {}

        def val_to_dict(var, val):
            val %= 2**self.SIZE
            args = [int(b) for b in bin(val)[2:].zfill(self.SIZE)]
            return {s.repr:v for s,v in zip(var, args[::-1])}


        for var, val in zip(self.vars, vals):
            val_dict.update(val_to_dict(var, val))


        for var, val in kwargs.items():
            if var in v_names:
                val_dict[var] = val
            else:
                # Handle unwrapping bitvectors like a=bv
                if hasattr(val, "symbols"):
                    val_dict.update({s.repr:v for s,v in zip(v_map[var], val.symbols)})
                
                # Handle unwrapping concrete values like a=7
                else:
                    val_dict.update(val_to_dict(v_map[var], val))


        # Strip symbits
        for k,v in val_dict.items():
            if type(v) is SymBit:
                val_dict[k] = v.value

        binary = [a(**val_dict) for a in self.symbols]

        bv = self._create_copy()
        bv.symbols = binary
        return bv
    

    def solve(self, *bits: List[SolveFor]):
        return bv_process(self, bits)


    def is_constant(self):
        return all((s.value if hasattr(s, 'value') else s.val) in ZZ for s in self.symbols)
    

    def int(self):
        if self.is_constant():
            return int(''.join(str(int(b.value if hasattr(b, 'value') else b.val)) for b in self.symbols), 2)
        else:
            raise ValueError("BitVector is not constant")


    def __int__(self):
        return self.int()



    def inject_locals(self, locals):
        locals.update({symbit.repr:SymBit(symbit) for sublist in self.vars.vars for symbit in sublist})


    def _create_copy(self):
        bv = self.__class__(self.var_name, self.vars)
        bv.symbols = [s for s in self.symbols]
        return bv
    
    
    def _coerce(self, other: int):
        if type(other) is int:
            bv = self._create_copy()
            other %= 2**self.SIZE
            bv.symbols = [self.one if int(b) else self.zero for b in bin(other)[2:].zfill(self.SIZE)]
            return bv

        elif type(other) is SymBit:
            bv = self._create_copy()
            bv.symbols = [self.zero]*(self.SIZE-1) + [other]
            return bv

        elif type(other) is list and len(other) == self.SIZE:
            bv = self._create_copy()
            bv.symbols = copy(other)
            return bv

        else:
            return other
    

    def __lshift__(self, idx):
        bv = self._create_copy()
        bv.symbols.extend([bv.zero]*idx)
        bv.symbols = bv.symbols[-self.SIZE:]
        return bv



    def __rshift__(self, idx):
        bv = self._create_copy()
        bv.symbols = ([bv.zero]*idx) + bv.symbols
        bv.symbols = bv.symbols[:self.SIZE]
        return bv


    def __xor__(self, other):
        bv = self._create_copy()
        other = self._coerce(other)

        bv.symbols = [a^b for a,b in zip(self.symbols, other.symbols)]
        return bv


    def __and__(self, other):
        bv = self._create_copy()
        other = self._coerce(other)
        bv.symbols = [a&b for a,b in zip(self.symbols, other.symbols)]
        return bv


    def __or__(self, other):
        bv = self._create_copy()
        other = self._coerce(other)
        bv.symbols = [a|b for a,b in zip(self.symbols, other.symbols)]
        return bv


    def __eq__(self, other):
        bv = self._create_copy()
        other = self._coerce(other)
        bv.symbols = [a==b for a,b in zip(self.symbols, other.symbols)]
        return bv


    def __invert__(self):
        bv = self._create_copy()
        bv.symbols = [~s for s in bv.symbols]
        return bv


    def __matmul__(self, other):
        other = self._coerce(other)
        return ~self | other



class BitVector(BaseObject, metaclass=SizableMeta):
    SIZABLE_CLS = FixedBitVector

    @staticmethod
    def from_func(func):
        sig = inspect.signature(func)
        all_sym_names = [param.name for param in sig.parameters.values()]
        sym_set = SymbolSet(all_sym_names, list(sig.parameters.values())[0].annotation.SIZE)

        b_vecs = [param.annotation(param.name, sym_set) for param in sig.parameters.values()]

        for i, b_vec in enumerate(b_vecs):
            b_vec.symbols = [SymBit(sym_set.P(sym)) for sym in b_vec.vars[i]][::-1]
        

        return func(*b_vecs)


class ALUOP(Enum):
    ADD = 0
    SUB = 1
    AND = 2
    OR  = 3
    XOR = 4
    TWO_CMPT_A = 5
    TWO_CMPT_B = 6
    MUL = 7
    DIV = 8
    MIN = 9
    MAX = 10
    GT = 11
    LT = 12
    EQ = 13


class ALU(BaseObject):
    def __init__(self, num_bits: int) -> None:
        self.n = num_bits


        OP_CODES = {
            ALUOP.ADD: ADVOP.ADD,
            ALUOP.SUB: ADVOP.SUB,
            ALUOP.AND: lambda a,b: a & b,
            ALUOP.OR: lambda a,b: a | b,
            ALUOP.XOR: lambda a,b: a ^ b,
            ALUOP.TWO_CMPT_A: lambda a,b: ADVOP.TWO_CMPT(a),
            ALUOP.TWO_CMPT_B: lambda a,b: ADVOP.TWO_CMPT(b),
            ALUOP.MUL: ADVOP.MUL,
            ALUOP.DIV: ADVOP.DIV,
            ALUOP.MIN: ADVOP.MIN,
            ALUOP.MAX: ADVOP.MAX,
            ALUOP.GT: ADVOP.GT,
            ALUOP.LT: ADVOP.LT,
            ALUOP.EQ: ADVOP.EQ,
            # 14: lambda a,b: ADVOP.LROT(a, b.int()),
            # 15: lambda a,b: ADVOP.RROT(a, b.int())
        }


        def ALU(ctrl: BitVector[self.n]=None, a: BitVector[self.n]=None, b: BitVector[self.n]=None):
            c = a ^ a
            for op_code, func in OP_CODES.items():
                c = ADVOP.IFNZ(ctrl ^ op_code.value, c, func(a, b))

            return c


        self.alu  = BitVector.from_func(ALU)
        self.func = ALU


    def __call__(self, *args, **kwds):
        proc_args = []
        for a in args:
            if type(a) is ALUOP:
                a = a.value
            
            proc_args.append(a)

        proc_kwds = {}
        for k,v in kwds.items():
            if type(v) is ALUOP:
                v = v.value
            
            proc_kwds[k] = v

        return self.alu(*proc_args, **proc_kwds)




class ADVOP:
    def TWO_CMPT(a):
        """Two's complement"""
        m = 2**a.SIZE-1
        return ADVOP.ADD(a ^ m, 1)


    def NZTRANS(a):
        """Transforms non-zero bitvectors to ALL ones"""
        for i in range(a.SIZE.bit_length()-1):
            a |= a >> 2**i

        for i in range(a.SIZE.bit_length()-1):
            a |= a << 2**i

        return a


    def IFNZ(c, s1, s2):
        """If `c` is non-zero, s1, else s2"""
        c = ADVOP.NZTRANS(c)
        return (c & s1) ^ (~c & s2)


    def HALF_ADDER(a, b):
        return a ^ b, a & b


    def FULL_ADDER(a, b, c):
        s1, c1 = ADVOP.HALF_ADDER(a, b)
        s2, c2 = ADVOP.HALF_ADDER(s1, c)
        return s2, c2 | c1


    def ADD_CARRY(a, b, c):
        s, c = a ^ a, a ^ a if c is None else c
        for i in range(a.SIZE):
            a_bit = (a >> i) & 1
            b_bit = (b >> i) & 1
            s1, c = ADVOP.FULL_ADDER(a_bit, b_bit, c)
            s ^= s1 << i

        return s, c


    def ADD(a, b, c=None):
        s, c = ADVOP.ADD_CARRY(a, b, None)
        return s ^ (c << a.SIZE)


    def SUB(a, b):
        return ADVOP.ADD(a, ADVOP.TWO_CMPT(b))


    def MUL(a, b):
        # Initialize Booth's algorithm
        zero  = a._coerce(0)
        size  = a.SIZE
        A_hi  = a
        A_mid = zero
        A_low = zero

        S_hi  = ADVOP.TWO_CMPT(a)
        S_mid = zero
        S_low = zero

        P_hi  = zero
        P_mid = b
        P_low = zero

        for _ in range(size):
            b0 = ADVOP.TESTBIT(P_mid, 0)
            b1 = ADVOP.TESTBIT(P_low, size-1)

            P  = [P_hi, P_mid, P_low]
            PS = ADVOP.MP_ADD(P, (S_hi, S_mid, S_low))
            PA = ADVOP.MP_ADD(P, (A_hi, A_mid, A_low))

            b01 = b0 ^ b1
            P[0] = ADVOP.IFNZ(b01, ADVOP.IFNZ(b0, PS[0], PA[0]), P[0])
            P[1] = ADVOP.IFNZ(b01, ADVOP.IFNZ(b0, PS[1], PA[1]), P[1])
            P[2] = ADVOP.IFNZ(b01, ADVOP.IFNZ(b0, PS[2], PA[2]), P[2])

            P_hi, P_mid, P_low = P
            P_low  = (P_mid & 1) << (size-1)
            P_mid  = (P_mid >> 1) ^ ((P_hi & 1) << (size-1))
            P_hi >>= 1
            

        return P_mid

    

    def TESTBIT(a, i):
        return (a >> i) & 1



    def DIV(a, b):
        """
        https://iq.opengenus.org/bitwise-division/
        """
        # Align most significant ones
        Q   = a._coerce(0)
        one = a._coerce(1)


        # We have to manage overflow!
        # Ex: DIV(3, 2)
        # 2 = 0010
        # 2 << 3 = 0001 0000

        # Since a's overflow will always be zero,
        # if c overflows, it MUST be greater than a
        for i in range(a.SIZE-1, -1, -1):
            c = (b << i)
            overflow = b >> (a.SIZE-i)

            z = ADVOP.GT(c, a)
            z = ADVOP.IFNZ(overflow, one, z)
            a = ADVOP.IFNZ(z, a, ADVOP.SUB(a, c))
            Q = ADVOP.IFNZ(z, Q, ADVOP.ADD(Q, a._coerce(2**i)))

        return Q


    def ABS(a):
        """
        https://stackoverflow.com/questions/12041632/how-to-compute-the-integer-absolute-value
        """
        mask = a >> (a.SIZE-1)
        a    = a ^ mask
        return ADVOP.SUB(a, mask)


    def S_GT(a, b):
        diff = a ^ b
        for i in range(a.SIZE.bit_length()-1):
            diff |= diff >> 2**i

        m1 = 1 << (a.SIZE-1)
        m2 = m1-1

        diff &= ~(diff >> 1) | m1
        diff &= (a ^ m1) & (b ^ m2)

        return diff


    def GT(a, b):
        ltb = ~a & b
        gtb = a & ~b

        for i in range(a.SIZE.bit_length()-1):
            ltb |= ltb >> 2**i
        
        return gtb & ~ltb


    def LT(a, b):
        return ~(a == b) & ~ADVOP.NZTRANS(ADVOP.GT(a, b))
    

    def EQ(a, b):
        return ~ADVOP.NZTRANS(a ^ b)


    def GE(a, b):
        return ADVOP.GT(a, b) | ADVOP.EQ(a, b)


    def LE(a, b):
        return ADVOP.LT(a, b) | ADVOP.EQ(a, b)


    def MAX(a, b):
        return ADVOP.IFNZ(ADVOP.GT(a, b), a, b)


    def MIN(a, b):
        return ADVOP.IFNZ(ADVOP.GT(a, b), b, a)


    def LROT(a, n):
        mask = 2**n-1
        return ((a<<n) | (a>>(a.SIZE-n))) & mask


    def RROT(a, n):
        mask = 2**n-1
        return ((a>>n) | (a<<(a.SIZE-n))) & mask


    def MP_ADD(A, B):
        C = []
        c = None

        for a, b in zip(A, B):
            l, c = ADVOP.ADD_CARRY(a, b, c)
            C.append(l)
        
        return C



class LUT(BaseObject):
    def __init__(self, table=None) -> None:
        self.table = table or []


    def contains(self, k):
        c = k ^ k
        for key, _val in self.table:
            c = ADVOP.IFNZ(key ^ k, c, c._coerce(1))
        
        return c


    def __getitem__(self, k):
        c = k ^ k
        for key, val in self.table:
            c = ADVOP.IFNZ(k ^ key, c, val)

        return c


    def __setitem__(self, k, v):
        self.table.append((k, v))



class SymList(BaseObject):
    def __init__(self, val=None) -> None:
        self.val = val or []
    

    def contains(self, other):
        c = other ^ other
        for v in self.val:
            c = ADVOP.IFNZ(v ^ other, c, c._coerce(1))
        
        return c


    def __getitem__(self, other):
        c = other ^ other
        for idx, v in enumerate(self.val):
            c = ADVOP.IFNZ(other ^ idx, c, v)

        return c


    def index(self, other):
        c = other ^ other
        for idx, v in enumerate(self.val):
            c = ADVOP.IFNZ(v ^ other, c, c._coerce(idx))

        return c
    

    def append(self, other):
        self.val.append(other)



class UInt(BaseObject):
    pass


class MPUInt(BaseObject):
    def __init__(self, values) -> None:
        self.values = values
    

    def _coerce(self, other):
        if type(other) is type(self):
            return other
        

        values = []
        a = self.values[0]

        for i in range(32 // a.SIZE):
            d = (other >> (i*a.SIZE)) & ((1 << a.SIZE)-1)
            values.append(a._coerce(d))
        
        return MPUInt(values)
