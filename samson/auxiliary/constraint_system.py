
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



class EqualsConstraint(BaseObject):
    def __init__(self, sym: str, val: int) -> None:
        self.sym = sym
        self.val = val
    

    def __hash__(self):
        return hash((self.__class__, tuple(self.sym), self.val))


    def __eq__(self, other) -> bool:
        return self.sym == other.sym and self.val == other.val


    def constrains(self, sym):
        return self.sym == sym
    

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



class OneOfConstraint(BaseObject):
    def __init__(self, syms: list, con_sys: List['ConstraintSystem']) -> None:
        self.syms = set(syms)
        self.con_sys = set(con_sys)

    def constrains(self, sym):
        return sym in self.syms


    def __hash__(self):
        return hash((self.__class__, tuple(self.syms), tuple(self.con_sys)))


    def __eq__(self, other) -> bool:
        return self.syms == other.syms and self.con_sys == other.con_sys
    

    def __add__(self, other):
        if type(other) is EqualsConstraint:
            return other + self

        elif type(other) is OneOfConstraint:
            if self.syms == other.syms:
                subset = self.con_sys.intersection(other.con_sys)
                if not subset:
                    raise NoSolutionException
                
                if len(subset) == 1:
                    return list(subset)[0]
                return ConstraintSystem([OneOfConstraint(self.syms, subset)])



import time
class ConstraintSystem(BaseObject):
    def __init__(self, constraints=None) -> None:
        self.constraints = set(constraints or [])
    
    def __hash__(self):
        return hash((self.__class__, tuple(self.constraints)))


    # def __getitem__(self, idx):
    #     for s_con in self.constraints:
    #         if s_con.c_type == ConstraintType.EQUALS:
    #             if s_con.val[0] == idx:
    #                 return ConstraintSystem([s_con])

    #         elif s_con.c_type == ConstraintType.ONE_OF:
    #             if idx in s_con.val[0]:
    #                 return s_con
        
    #     raise KeyError
    

    def __add__(self, other):
        if type(other) is not ConstraintSystem:
            other = ConstraintSystem([other])

        systems = set([self, other])

        while len(systems) > 1:
            print(systems)
            time.sleep(0.3)
            l_sys = list(systems)
            s, o = l_sys[:2]
            systems = set(l_sys[2:])

            for o_con in o.constraints:
                handled = False

                for s_con in s.constraints:
                    if type(o_con) is EqualsConstraint:
                        systems.add(s_con + o_con)
                        handled = True

                    elif type(o_con) is OneOfConstraint:
                        if any(s_con.constrains(s) for s in o_con.syms):
                            systems.add(s_con + o_con)
                            handled = True
                        else:
                            systems.add(ConstraintSystem([s_con]))
                
                if not handled:
                    systems.add(ConstraintSystem([o_con]))
        
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
