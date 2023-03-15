from typing import List


class Term(object):
    def __init__(self, name: str, is_fresh: bool=False) -> None:
        self.name = name
        self.is_fresh = is_fresh
    
    def __str__(self) -> str:
        mod = "~" if self.is_fresh else ""
        return f"{mod}{self.name}"



class Tuple(object):
    def __init__(self, terms: List[Term]) -> None:
        self.terms = terms

    def __str__(self) -> str:
        terms = ", ".join([str(t) for t in self.terms])
        return f"<{terms}>"



class Fact(object):
    def __init__(self, name: str, terms: List[Term], persistent: bool=False) -> None:
        self.name = name
        self.terms = terms
        self.persistent = persistent

    def __str__(self) -> str:
        mod   = "!" if self.persistent else ""
        terms = ", ".join([str(t) for t in self.terms])
        return f"{mod}{self.name}({terms})"



class Rule(object):
    def __init__(self, name, lhs, action, rhs) -> None:
        self.name = name
        self.lhs = lhs
        self.action = action
        self.rhs = rhs
    

    def __str__(self) -> str:
        lhs    = ", ".join([str(f) for f in self.lhs])
        rhs    = ", ".join([str(f) for f in self.rhs])
        action = ", ".join([str(f) for f in self.action])
    
        return f"""rule {self.name}:
    [ {lhs} ]
    --[ {action} ]->
    [ {rhs} ]"""


class AllStatement(object):
    def __init__(self, terms, temporal_facts, implication=None) -> None:
        self.terms = terms
        self.temporal_facts = temporal_facts
        self.implication = implication
    

    def __str__(self) -> str:
        variables   = ' '.join([str(v) for v in self.variables])
        facts       = '\n\t& '.join([f"{f} @ {v}" for f, v in self.temporal_facts])
        implication = f"\n\t==> {self.implication}" if self.implication else ""
        return f"All {variables}.\n\t{facts}{implication}"




class Lemma(object):
    def __init__(self, name) -> None:
        self.name = name


    def __str__(self) -> str:
        pass



rule = Rule(
    name="Register_pkA",
    lhs=[Fact("Fr", [Term("ltkA", True)])],
    action=[],
    rhs=[
        Fact("Ltk", [Term("$A"), Term("ltkA", True)])
    ]
)

s = AllStatement(
    terms=[
        Term("A"),
        Term("k1"),
        Term("k2"),
        Term("#i"),
        Term("#j"),
        Term("#l")
    ],
    temporal_facts=[
        (Fact("SessionKey", [Term("A"), Term("k2")]), Term("i")),
        (Fact("K", [Term("k1")]), Term("l"))
    ]
)

def terms(term_str):
    return [Term(t) for t in term_str.split()]


# All A k1 k2 #i #j #l. SessionKey(A, k1) @ i
#     & SessionKey(A, k2) @ j
#     & i < j
#     & K(k1) @ l
#     & i < l
#     ==> ((Ex A #m. Reveal(A) @m & m < l) | (Ex #m. RevealSess(A, k1) @m))"

# rule Register_pkA:
#   [ Fr(~ltkA) ]
#   -->
#   [ !Ltk($A, ~ltkA)
#   , !Pk($A, pk(~ltkA))
#   , Out(pk(~ltkA)) 
#   ]
