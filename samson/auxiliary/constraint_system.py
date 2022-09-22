
from samson.utilities.exceptions import NoSolutionException
from samson.core.base_object import BaseObject
from typing import List


# EQUALS.val = (symbol, required_val)
# ONE_OF.val = (symbols, ConstraintSystem[(EQUALS,...),...])


# BEHAVIORS
# -------------
# EQ[a] + EQ[b]
#   if a == b: a
#   if a.sym == b.sym and a != b: NOSOL
#   if a.sym != b.sym: [a, b]

# EQ[a] + ONEOF[b]
#   if a in b.syms: select b.cons where a == con.val, remove a from con
#   if a not in b.syms: 

# ONEOF[a] + ONEOF[b]
#   if

# [
#     {'a0': 1, 'a1': 0, 'a2': 1}
# ]
# +
# [
#     {'a0': 1},
#     {'a0': 0}
# ]



class EqualsConstraint(BaseObject):
    def __init__(self, sym: str, val: int) -> None:
        self.sym = sym
        self.val = val
    

    def __hash__(self):
        return hash((self.__class__, tuple(self.sym), self.val))


    def __eq__(self, other) -> bool:
        return type(self) == type(other) and self.sym == other.sym and self.val == other.val


    def constrains(self, sym):
        return self.sym == sym
    

    def generate(self):
        return [{self.sym: self.val}]


    def conflicts(self, other):
        if type(other) is EqualsConstraint:
            # We already have an equals constraint; make sure they don't contradict
            if self.sym == other.sym:
                return self.val != other.val
            else:
                return False
        else:
            raise NotImplementedError
    

    def __add__(self, other):
        if type(other) is EqualsConstraint:
            # We already have an equals constraint; make sure they don't contradict
            if self.sym == other.sym:
                if self.val == other.val:
                    return ConstraintSystem([self])
                else:
                    raise NoSolutionException
            else:
                return ConstraintSystem([self, other])

        elif type(other) is OneOfConstraint:
            if self.sym in other.syms:
                new_one_of = []

                # Delete any subcons that don't satisfy the equals
                for sub_con_system in other.con_sys:
                    for sub_con in sub_con_system.constraints:

                        # If we're in it, remove us from it and add the others
                        if self == sub_con:
                            con_sys = ConstraintSystem([con for con in sub_con_system.constraints if con.sym != self.sym])
                            new_one_of.append(con_sys)

                if new_one_of:
                    if len(new_one_of) == 1:
                        constraints = list(new_one_of[0].constraints)
                    else:
                        constraints = [OneOfConstraint([s for s in other.syms if s != self.sym], new_one_of)]

                    return ConstraintSystem([self] + constraints)
                else:
                    raise NoSolutionException
            
            else:
                return ConstraintSystem([self, other])

        elif type(other) is ConstraintSystem:
            return other + self
        
        else:
            raise NotImplementedError(f"Add not implemented for {self.__class__.__name__} and {other.__class__.__name__}")



class OneOfConstraint(BaseObject):
    def __init__(self, syms: list, con_sys: List['ConstraintSystem']) -> None:
        self.syms = set(syms)
        self.con_sys = set(con_sys)

    def constrains(self, sym):
        return sym in self.syms
    

    def generate(self):
        return [con.generate() for con in self.con_sys]

    def __hash__(self):
        return hash((self.__class__, tuple(self.syms), tuple(self.con_sys)))


    def __eq__(self, other) -> bool:
        return type(self) == type(other) and self.syms == other.syms and self.con_sys == other.con_sys
    

    def __add__(self, other):
        if type(other) is EqualsConstraint:
            return other + self

        elif type(other) is OneOfConstraint:
            subset = set()
            for s_con in self.con_sys:
                for o_con in other.con_sys:
                    try:
                        subset.add(s_con + o_con)
                    except NoSolutionException:
                        pass

            if not subset:
                raise NoSolutionException
            
            if len(subset) == 1:
                return list(subset)[0]
            return ConstraintSystem([OneOfConstraint(self.syms.union(other.syms), subset)])

        elif type(other) is ConstraintSystem:
            return other + self

        else:
            raise NotImplementedError(f"Add not implemented for {self.__class__.__name__} and {other.__class__.__name__}")



import time
class ConstraintSystem(BaseObject):
    def __init__(self, constraints=None) -> None:
        self.constraints = set(constraints or [])
    
    def __hash__(self):
        return hash((self.__class__, tuple(self.constraints)))
    

    def generate(self):
        for con in self.constraints:
            con.generate()


    def __add__(self, other):
        if type(other) is not ConstraintSystem:
            other = ConstraintSystem([other])
        
        if not self.constraints:
            return other

        if not other.constraints:
            return self

        systems = set([self, other])

        i = 0
        while len(systems) > 1:
            print(i, systems)
            i += 1
            # time.sleep(0.3)
            l_sys = list(systems)
            s, o = l_sys[:2]
            systems = set(l_sys[2:])

            # Deal with equals constraints wholesale
            eq_constraints = set()
            for o_con in o.constraints:
                if type(o_con) is EqualsConstraint:
                    for s_con in s.constraints:
                        if type(s_con) is EqualsConstraint:
                            o_con + s_con
                            eq_constraints.add(o_con)
                            eq_constraints.add(s_con)

            if eq_constraints:
                systems.add(ConstraintSystem(eq_constraints))
                continue


            for o_con in o.constraints:
                for s_con in s.constraints:
                    if (o_con + s_con) is None:
                        print("NONE AT ALL CONSTRAINTS", o_con + s_con)
                        raise RuntimeError
                    systems.add(o_con + s_con)


        return list(systems)[0]




sys0 = ConstraintSystem([
    EqualsConstraint('a3', 1)
])

sys1 = ConstraintSystem([
    EqualsConstraint('a3', 1)
])

sys2 = ConstraintSystem([
    EqualsConstraint('a3', 0)
])

sys3 = ConstraintSystem([
    EqualsConstraint('a2', 0)
])

sys4 = ConstraintSystem([
    OneOfConstraint(syms=['a3', 'a2'], con_sys=[
        ConstraintSystem([EqualsConstraint('a3', 0), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a3', 1), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a3', 0), EqualsConstraint('a2', 1)]),
    ])])


sys5 = ConstraintSystem([
    OneOfConstraint(syms=['a3', 'a2'], con_sys=[
        ConstraintSystem([EqualsConstraint('a3', 1), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a3', 1), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a3', 1), EqualsConstraint('a2', 1)]),
    ])])



sys6 = ConstraintSystem([
    OneOfConstraint(syms=['a0', 'a2'], con_sys=[
        ConstraintSystem([EqualsConstraint('a0', 1), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a0', 1), EqualsConstraint('a2', 0)]),
        ConstraintSystem([EqualsConstraint('a0', 1), EqualsConstraint('a2', 1)]),
    ])])


sys7 = ConstraintSystem([
    EqualsConstraint('a2', 0),
    EqualsConstraint('a3', 0)
])

sys8 = ConstraintSystem([
    EqualsConstraint('a2', 0),
    EqualsConstraint('a0', 0)
])

sys9 = ConstraintSystem([
    OneOfConstraint(syms=['a1', 'a3'], con_sys=[
        ConstraintSystem([EqualsConstraint('a1', 0), EqualsConstraint('a3', 0)]),
        ConstraintSystem([EqualsConstraint('a1', 1), EqualsConstraint('a3', 0)]),
        ConstraintSystem([EqualsConstraint('a1', 0), EqualsConstraint('a3', 1)]),
    ])])


sys10 = ConstraintSystem([EqualsConstraint('a1', 1)])


def bv_process(bv, outputs):
    constraints = ConstraintSystem()
    for s, out in zip(bv.symbols, outputs):
        p = s.value
        constraints = poly_rec(p, out, constraints)

    return constraints


from samson.math.polynomial import Polynomial


def get_syms(con_sys):
    syms = set()
    for con in con_sys.constraints:
        if hasattr(con, 'sym'):
            syms.add(con.sym)
        else:
            syms = syms.union(con.syms)
    return syms


def poly_rec(p, output, constraints):
    print(p, output, constraints)
    if type(p) is not Polynomial:
        print("p not poly; abort")
        return constraints

    a = p.symbol.repr

    # x*a == 1, then x == 1 AND a == 1
    if not p[0] and output:
        print('not p[0] and output')
        constraints += EqualsConstraint(a, 1)
        constraints = poly_rec(p[1], output, constraints)
        print("not p[0] and output RECURSIVE RETURN")
    
    # x*a == 0, then (x == 0 AND a == 0) OR (x == 0 AND a == 1) OR (x == 1 OR a == 0)
    elif not p[0] and not output:
        print('not p[0] and not output')
        print('p[1]', p[1], p[1] == p.coeff_ring.one)
        if p[1] == p.coeff_ring.one:
            print('p[1] == 1')
            constraints += EqualsConstraint(a, output)
            return constraints
        

        #print(p[1], 0)
        x_cons_0 = poly_rec(p[1], 0, ConstraintSystem())
        print("not p[0] and not output RECURSIVE RETURN, x_cons_0")
        x_cons_1 = poly_rec(p[1], 1, ConstraintSystem())
        print("not p[0] and not output RECURSIVE RETURN, x_cons_1")
        # constraints += OneOfConstraint({a}, [
        #     ConstraintSystem([EqualsConstraint(a, 0), x_cons_0]),
        #     ConstraintSystem([EqualsConstraint(a, 1), x_cons_0]),
        #     ConstraintSystem([EqualsConstraint(a, 0), x_cons_1])
        # ])

        print(x_cons_0)
        print(x_cons_1)
        # constraints += a0 + x_cons_0
        # constraints += a1 + x_cons_0
        # constraints += a0 + x_cons_1

        constraints += OneOfConstraint({a}.union(get_syms(x_cons_0)).union(get_syms(x_cons_1)), [
            ConstraintSystem([EqualsConstraint(a, 0), *x_cons_0.constraints]),
            ConstraintSystem([EqualsConstraint(a, 1), *x_cons_0.constraints]),
            ConstraintSystem([EqualsConstraint(a, 0), *x_cons_1.constraints])
        ])


    # This layer is null, just hop to the next
    elif p[0] and not p[1]:
        print('p[0] and not p[1]')
        # if p[0] == 1:
        #     constraints += EqualsConstraint(a, 1)
        # else:

        # Make sure it's not a constant
        if p[0] != p.coeff_ring.one:
            print(repr(p[0]))
            constraints = poly_rec(p[0], output, constraints)
            print("p[0] and not p[1] RECURSIVE RETURN")

    # If we're here, p0 and p1 have values
    elif output:
        print("START OUTPUT")
        a0 = EqualsConstraint(a, 0)
        a1 = EqualsConstraint(a, 1)

        # 1 here means p0 != p1 (p0 + p1 = 1)
        # Check for constant
        if p[0] == p.coeff_ring.one:
            constraints += a0

        # Non constant p[0]; handle symbols
        else:
            print("WOOPS! OUTPUT, ", repr(p))
            p0_cons_0 = poly_rec(p[0], 0, ConstraintSystem())
            print("output RECURSIVE RETURN, p0_cons_0")
            p0_cons_1 = poly_rec(p[0], 1, ConstraintSystem())
            print("output RECURSIVE RETURN, p0_cons_1")
            p1_cons_0 = poly_rec(p[1]*p.symbol, 0, ConstraintSystem())
            print("output RECURSIVE RETURN, p1_cons_0")
            p1_cons_1 = poly_rec(p[1]*p.symbol, 1, ConstraintSystem())
            print("output RECURSIVE RETURN, p1_cons_1")
            syms = {a}.union(get_syms(p0_cons_0)).union(get_syms(p0_cons_1)).union(get_syms(p1_cons_0)).union(get_syms(p1_cons_1))

            print("p0_cons_0", p0_cons_0)
            print("p0_cons_1", p0_cons_1)
            print("p1_cons_0", p1_cons_0)
            print("p1_cons_1", p1_cons_1)


            try:
                constraints += OneOfConstraint(syms, [
                    p0_cons_0 + p1_cons_1,
                    p0_cons_1 + p1_cons_0
                ])
            except NoSolutionException:
                try:
                    constraints += p0_cons_0 + p1_cons_1
                except NoSolutionException:
                    print("This should work?!")
                    print("p0_cons_1", p0_cons_1)
                    print("p1_cons_0", p1_cons_0)
                    print("p0_cons_1 + p1_cons_0", p0_cons_1 + p1_cons_0)
                    print("constraints", constraints)
                    print("altogether", p0_cons_1 + p1_cons_0 + constraints)
                    constraints += p0_cons_1 + p1_cons_0


    else:
        # p0 == p1
        print("p0 == p1; NOT IMPLEMENTED?!")
        p0_cons_0 = poly_rec(p[0], 0, ConstraintSystem())
        print("NOT IMPLEMENTED RECURSIVE RETURN, p0_cons_0")
        p0_cons_1 = poly_rec(p[0], 1, ConstraintSystem())
        print("NOT IMPLEMENTED RECURSIVE RETURN, p0_cons_1")
        p1_cons_0 = poly_rec(p[1]*p.symbol, 0, ConstraintSystem())
        print("NOT IMPLEMENTED RECURSIVE RETURN, p1_cons_0")
        p1_cons_1 = poly_rec(p[1]*p.symbol, 1, ConstraintSystem())
        print("NOT IMPLEMENTED RECURSIVE RETURN, p1_cons_1")
        syms = {a}.union(get_syms(p0_cons_0)).union(get_syms(p0_cons_1)).union(get_syms(p1_cons_0)).union(get_syms(p1_cons_1))

        # print("p0_cons_0 + p1_cons_0", p0_cons_0 + p1_cons_0)
        # print("p0_cons_1 + p1_cons_1", p0_cons_1 + p1_cons_1)
        
        try:
            constraints += OneOfConstraint(syms, [
                p0_cons_0 + p1_cons_0,
                p0_cons_1 + p1_cons_1
            ])
        except NoSolutionException:
            try:
                constraints += p0_cons_0 + p1_cons_0
            except NoSolutionException:
                constraints += p0_cons_1 + p1_cons_1
            


    print("RETURN", constraints)
    print()
    return constraints
