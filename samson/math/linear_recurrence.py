from samson.core.base_object import BaseObject
from samson.math.general import berlekamp_massey

class LinearRecurrence(BaseObject):
    def __init__(self, minimal_poly, initial_states) -> None:
        self.minimal_poly = minimal_poly
        self.coeffs = list(-(minimal_poly - minimal_poly.symbol**minimal_poly.degree()))
        self.initial_states = initial_states


    @staticmethod
    def from_outputs(outputs, R=None):
        R = R or outputs[0].ring
        outputs  = [R(o) for o in outputs]
        min_poly = berlekamp_massey(outputs, R)
        return LinearRecurrence(minimal_poly=min_poly, initial_states=outputs[:min_poly.degree()-1])


    def __call__(self, idx):
        if idx < len(self.initial_states):
            return self.initial_states[idx]
        else:
            states = self.initial_states
            for _ in range(idx-len(self.initial_states)):
                state  = sum(c*s for c,s in zip(self.coeffs, states))
                states = (states + [state])[1:]

            return states[-1]


    def __getitem__(self, idx):
        if type(idx) is slice:
            if idx.stop is None:
                raise ValueError

            return [self(i) for i in range(idx.start or 0, idx.stop, idx.step or 1)]
        else:
            return self(idx)
