
from enum import Enum
from samson.utilities.exceptions import NoSolutionException
from samson.core.base_object import BaseObject
from samson.math.polynomial import Polynomial
from typing import List
from copy import copy
import itertools


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


class AnyConstraint(BaseObject):
    def __init__(self, sym: str) -> None:
        self.sym = sym


    def __hash__(self):
        return hash((self.__class__, self.sym))

    def __eq__(self, other) -> bool:
        return type(self) == type(other) and self.sym == other.sym


    def generate(self):
        return [{self.sym: 0}, {self.sym: 1}]


    def constrains(self, sym):
        return sym == self.sym


    def __add__(self, other):
        if type(self) == type(other):
            if self.sym == other.sym:
                return ConstraintSystem([self])
            else:
                return ConstraintSystem([self, other])

        else:
            return other + self



class EqualsConstraint(BaseObject):
    def __init__(self, sym: str, val: int) -> None:
        self.sym = sym
        self.val = val
    

    def __hash__(self):
        return hash((self.__class__, self.sym, self.val))


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
                    satisfied = True
                    good_constraints = set()

                    for sub_con in sub_con_system.constraints:

                        try:
                            mod_constraint = (self + sub_con).constraints

                            if self in mod_constraint:
                                mod_constraint.remove(self)

                            for con in mod_constraint:
                                if type(con) is OneOfConstraint and con.simplify():
                                    con = con.simplify()

                                    good_constraints = good_constraints.union(con.constraints)
                                else:
                                    good_constraints.add(con)
                        except NoSolutionException:
                            satisfied = False
                            break

                    if satisfied and good_constraints:
                        con_sys = ConstraintSystem(good_constraints)

                        new_one_of.append(con_sys)



                if new_one_of:
                    if len(new_one_of) == 1:
                        constraints = list(new_one_of[0].constraints)
                    else:
                        oneof = OneOfConstraint([s for s in other.syms if s != self.sym], new_one_of)
                        simp  = oneof.simplify()

                        if simp:
                            return simp
    
                        constraints = [oneof]

                    return ConstraintSystem([self] + constraints)
                else:
                    raise NoSolutionException

            else:
                return ConstraintSystem([self, other])
        

        elif type(other) is AnyConstraint:
            if self.sym == other.sym:
                return ConstraintSystem([self])
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


    def simplify(self):
        if len(self.con_sys) == 2**len(self.syms):
            return ConstraintSystem([AnyConstraint(s) for s in self.syms])

        elif len(self.con_sys) == 1:
            return list(self.con_sys)[0]

        else:
            gens = [(a, {tuple(sorted(tuple(dic.items()))) for dic in a.generate()}) for a in self.con_sys]

            bad_con_sys = set()
            for a,a_gen in gens:
                for b,b_gen in gens:
                    if a == b:
                        continue

                    if a_gen.issuperset(b_gen):
                        bad_con_sys.add(b)
            

            new_con_sys = self.con_sys.difference(bad_con_sys)
            syms = set()
            for c in new_con_sys:
                syms = syms.union(c.get_syms())

            if len(new_con_sys) < len(self.con_sys):
                oo = OneOfConstraint(syms, new_con_sys)
                return oo.simplify() or ConstraintSystem([oo])



    def recursive_simplify(self):
        n_oo = set()
        for con_sys in self.con_sys:
            n_cs = set()
            for con in con_sys.constraints:
                if type(con) is OneOfConstraint:
                    simp = con.recursive_simplify()
                    

                    if type(simp) is ConstraintSystem:
                        n_cs = n_cs.union(simp.constraints)
                    else:
                        n_cs.add(simp)
                else:
                    n_cs.add(con)

            n_oo.add(ConstraintSystem(n_cs))


        syms = set()
        for c in n_oo:
            syms = syms.union(c.get_syms())

        oo = OneOfConstraint(syms, n_oo)
        result = oo.simplify() or oo

        return result


    def generate(self):
        results = []

        for con in self.con_sys:
            results.extend(con.generate())

        return results


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
            
            syms  = self.syms.union(other.syms)
            oneof = OneOfConstraint(syms, subset)
            simp  = oneof.simplify()

            if simp:
                return simp 

            return ConstraintSystem([oneof])

        elif type(other) is AnyConstraint:
            if other.sym in self.syms:
                return ConstraintSystem([self])
            else:
                return ConstraintSystem([self, other])

        elif type(other) is ConstraintSystem:
            return other + self

        else:
            raise NotImplementedError(f"Add not implemented for {self.__class__.__name__} and {other.__class__.__name__}")



class ConstraintSystem(BaseObject):
    def __init__(self, constraints=None) -> None:
        self.constraints = set(constraints or [])


    def __hash__(self):
        return hash((self.__class__, tuple(self.constraints)))
    

    def generate(self):
        results = set()

        for product in itertools.product(*[con.generate() for con in self.constraints]):
            combined = {}

            for g in list(product):
                combined.update(g)

            results.add(tuple(sorted(tuple(combined.items()))))

        return [dict(r) for r in results]
    

    def get_syms(self):
        syms = set()
        for con in self.constraints:
            if hasattr(con, 'sym'):
                syms.add(con.sym)
            else:
                syms = syms.union(con.syms)
        return syms



    def __add__(self, other):
        if type(other) is not ConstraintSystem:
            other = ConstraintSystem([other])
        
        if not self.constraints:
            return other

        if not other.constraints:
            return self

        # STEP 1: Separate ALL EQs into single EQ system
        # STEP 2: Separate ALL OOs into single OO system
        # STEP 3: Merge EQs and OOs

        def separate_by_type(constraints):
            cons_by_type = {EqualsConstraint: set(), AnyConstraint: set(), OneOfConstraint: set()}
            for con in constraints:
                con_t = type(con)
                cons_by_type[con_t].add(con)
            
            return cons_by_type


        # CS merge
        s_type_map = separate_by_type(self.constraints)
        o_type_map = separate_by_type(other.constraints)


        s_eq = s_type_map[EqualsConstraint]
        o_eq = o_type_map[EqualsConstraint]

        eq_constraints = set()
        for s in s_eq:
            for o in o_eq:
                s + o
                eq_constraints.add(o)
            eq_constraints.add(s)


        if not s_eq:
            eq_constraints = set(o_eq)


        s_oo = s_type_map[OneOfConstraint]
        o_oo = o_type_map[OneOfConstraint]

        simplified_oos = set()
        extracted_anys = set()


        # Decompose OOs
        all_oos = {*s_oo, *o_oo}
        changed = True

        while changed:
            changed = False

            for oo in all_oos:
                curr = oo
                for eq in copy(eq_constraints):
                    if eq.sym in oo.syms:
                        curr += eq

                        # Remove eq from the system
                        c_type_map = separate_by_type(curr.constraints)
                        eqs  = c_type_map[EqualsConstraint]
                        oos  = c_type_map[OneOfConstraint]
                        anys = c_type_map[AnyConstraint]
                        eq_constraints = eq_constraints.union(eqs)
                        extracted_anys = extracted_anys.union(anys)


                        # Check if it's been decomposed
                        if oos:
                            curr = list(oos)[0]
                            if curr != oo:
                                changed = True
                        else:
                            curr = None
                            changed = True
                            break

                if curr:
                    simp = curr.simplify()
                    if simp:
                        simp_types = separate_by_type(simp.constraints)
                        extracted_anys = extracted_anys.union(simp_types[AnyConstraint])
                        eq_constraints = eq_constraints.union(simp_types[EqualsConstraint])
                        simplified_oos = simplified_oos.union(simp_types[OneOfConstraint])
                    else:
                        simplified_oos.add(curr)
            
            if changed:
                all_oos = simplified_oos
                simplified_oos = set()
        

        # Combine OOs
        while len(simplified_oos) > 1:
            l_oo = list(simplified_oos)
            oo_a, oo_b = l_oo[:2]
            simplified_oos = set(l_oo[2:])

            combined_oos = (oo_a + oo_b).constraints

            for combined in combined_oos:
                if type(combined) is AnyConstraint:
                    extracted_anys.add(combined)

                elif type(combined) is EqualsConstraint:
                    eq_constraints.add(combined)

                else:
                    simplified_oos.add(combined)


        any_cons     = extracted_anys.union(s_type_map[AnyConstraint]).union(o_type_map[AnyConstraint])
        removed_anys = set()

        # Prune anys
        for any_c in any_cons:
            for oo in simplified_oos:
                if any_c.sym in oo.syms:
                    removed_anys.add(any_c)
                    break

            for eq in eq_constraints:
                if any_c.sym == eq.sym:
                    removed_anys.add(any_c)
                    break
        


        # Ensure OOs are simplified
        re_simplified = set()
        for oo in simplified_oos:
            simp = oo.recursive_simplify()

            if type(simp) is ConstraintSystem:
                re_simplified = re_simplified.union(simp.constraints)
            else:
                re_simplified.add(oo)


        # Check that EQs don't contradict
        for eq_a in eq_constraints:
            for eq_b in eq_constraints:
                try:
                    eq_a + eq_b
                except NoSolutionException:
                    raise NoSolutionException


        good_anys = any_cons.difference(removed_anys)
        result = ConstraintSystem(good_anys.union(eq_constraints).union(re_simplified))
        return result


class SolveFor(Enum):
    ONE  = 1
    ZERO = 0
    ANY  = "x"


def bv_process(bv, outputs):
    constraints = ConstraintSystem([AnyConstraint(var.repr) for sublist in bv.vars.vars for var in sublist])
    for s, out in zip(bv.symbols, outputs):
        p = s.value
        if type(out) is SolveFor:
            out = out.value

        if out != "x":
            constraints = poly_rec(p, out, constraints)

    return constraints


def poly_rec(p, output, constraints):
    if type(p) is not Polynomial:
        # p not poly; abort
        return constraints

    a = p.symbol.repr

    # x*a == 1, then x == 1 AND a == 1
    if not p[0] and output:
        if not p[1]:
            raise NoSolutionException

        constraints += EqualsConstraint(a, 1)
        constraints  = poly_rec(p[1], output, constraints)
        # not p[0] and output RECURSIVE RETURN

    # x*a == 0, then (x == 0 AND a == 0) OR (x == 0 AND a == 1) OR (x == 1 OR a == 0)
    elif not p[0] and not output:
        if p[1] == p.coeff_ring.one:
            constraints += EqualsConstraint(a, output)
            return constraints


        # not p[0] and not output; solving p[1] for 0
        x_cons_0 = poly_rec(p[1], 0, ConstraintSystem())

        # not p[0] and not output; solving p[1] for 1

        # We only need this for the variables. If it doesn't work,
        # just throw it out. This should really only happen if
        # we're dealing with a constant anyway
        try:
            x_cons_1 = poly_rec(p[1], 1, ConstraintSystem())
            x_cons_1_syms = x_cons_1.get_syms()
        except NoSolutionException:
            x_cons_1_syms = set()

        any_syms   = x_cons_0.get_syms().union(x_cons_1_syms)
        x_cons_any = [AnyConstraint(s) for s in any_syms]

        assert a not in any_syms

        constraints += OneOfConstraint({a}.union(any_syms), [
            ConstraintSystem([EqualsConstraint(a, 0), *x_cons_any]),
            ConstraintSystem([AnyConstraint(a), *x_cons_0.constraints])
        ])


    # This layer is null, just hop to the next
    elif p[0] and not p[1]:

        # If the constant doesn't match the output, throw
        if p[0] == p.coeff_ring.one:
            if not output:
                raise NoSolutionException
        else:
            constraints = poly_rec(p[0], output, constraints)

    # If we're here, p0 and p1 have values
    elif output:
        # p0 AND p1, output == 1

        # 1 here means p0 != p1 (p1 + p0 = 1)
        # Check for constant
        # p1 + 1 = 1
        # p1 = 0; Solve p1 for 0!
        if p[0] == p.coeff_ring.one:
            constraints = poly_rec(p[1]*p.symbol, 0, constraints)

        # Non constant p[0]; handle symbols
        else:
            p0_cons_0 = poly_rec(p[0], 0, ConstraintSystem())
            p0_cons_1 = poly_rec(p[0], 1, ConstraintSystem())
            p1_cons_0 = poly_rec(p[1]*p.symbol, 0, ConstraintSystem())
            p1_cons_1 = poly_rec(p[1]*p.symbol, 1, ConstraintSystem())

            syms = {a}.union(p0_cons_0.get_syms()).union(p0_cons_1.get_syms()).union(p1_cons_0.get_syms()).union(p1_cons_1.get_syms())

            try:
                constraints += OneOfConstraint(syms, [
                    p0_cons_0 + p1_cons_1,
                    p0_cons_1 + p1_cons_0
                ])
            except NoSolutionException:
                try:
                    constraints += p0_cons_0 + p1_cons_1
                except NoSolutionException:
                    constraints += p0_cons_1 + p1_cons_0


    else:
        # p0 AND p1, output == 0
        if p[0] == p.coeff_ring.one:
            return poly_rec(p[1]*p.symbol, 1, constraints)

        p0_cons_0 = poly_rec(p[0], 0, ConstraintSystem())
        p0_cons_1 = poly_rec(p[0], 1, ConstraintSystem())
        p1_cons_0 = poly_rec(p[1]*p.symbol, 0, ConstraintSystem())
        p1_cons_1 = poly_rec(p[1]*p.symbol, 1, ConstraintSystem())

        syms = {a}.union(p0_cons_0.get_syms()).union(p0_cons_1.get_syms()).union(p1_cons_0.get_syms()).union(p1_cons_1.get_syms())


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


    return constraints
