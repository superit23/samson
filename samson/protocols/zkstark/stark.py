from samson.core.base_object import BaseObject
from samson.constructions.merkle_tree import MerkleTree
from samson.constructions.fiat_shamir_proof_stream import FiatShamirProofStream
from samson.utilities.bytes import Bytes
from samson.math.symbols import Symbol
from samson.math.general import product
from samson.protocols.zkstark.fri import FRI
from samson.utilities.runtime import RUNTIME


def zerofier(P, domain):
    x = P.symbol
    return product([x-d for d in domain])


class STARK(BaseObject):
    """
    References:
        https://aszepieniec.github.io/stark-anatomy/stark
    """

    def __init__(self, field: 'Ring', expansion_factor: int, num_collinearity_checks: int, security_level: int, num_registers: int, num_cycles: int, transition_constraints_deg: int=2, hash_func: 'function'=None) -> None:
        self.field = field
        self.expansion_factor = expansion_factor
        self.num_collinearity_checks = num_collinearity_checks
        self.security_level = security_level
        self.num_registers = num_registers
        self.original_trace_len  = num_cycles
        self.transition_constraints_deg = transition_constraints_deg

        self.num_randomizers = 4*num_collinearity_checks
        randomized_trace_len = self.original_trace_len + self.num_randomizers
        omicron_domain_len   = 2**(randomized_trace_len * transition_constraints_deg).bit_length()
        fri_domain_len       = omicron_domain_len * expansion_factor

        self.hash_func = hash_func

        g = field.mul_group().find_gen()
        self.g = field(g)
        self.w = field(g * (g.order() // fri_domain_len))
        self.o = field(g * (g.order() // omicron_domain_len))

        self.omicron_domain = [self.o**i for i in range(omicron_domain_len)]
        self.fri = FRI(
            w=self.w,
            g=self.g,
            domain_length=fri_domain_len,
            expansion_factor=expansion_factor,
            num_collinearity_checks=num_collinearity_checks,
            hash_func=hash_func
        )
    

    @property
    def P(self):
        return self.fri.P

    @property
    def x(self):
        return self.fri.P.symbol


    def transition_degree_bounds(self, trans_constraints: list):
        point_degrees = [1] + [self.original_trace_len+self.num_randomizers-1] * 2*self.num_registers
        return [max(sum(r*l for r,l in zip(point_degrees, exp_vec)) for exp_vec in con.coeffs.keys()) for con in trans_constraints]
    

    def transition_quotient_degree_bounds(self, trans_constraints: list):
        return [d - (self.original_trace_len-1) for d in self.transition_degree_bounds(trans_constraints)]
    

    def max_degree(self, trans_constraints: list):
        return 2**max(self.transition_quotient_degree_bounds(trans_constraints)).bit_length() - 1
    

    def transition_zerofier(self):
        domain = self.omicron_domain[:self.original_trace_len-1]
        return zerofier(self.P, domain)
    
    
    def boundary_zerofiers(self, boundary):
        return [zerofier(self.P, [self.o**c for c,r,_v in boundary if r == i]) for i in self.num_registers]
    
    
    def boundary_interpolants(self, boundary):
        return [self.P.interpolate([(self.o**c, v) for c,r,v in boundary if r == i]) for i in self.num_registers]
    

    def boundary(self, randomized_trace_length: int, boundary):
        trace_deg = randomized_trace_length-1
        return [trace_deg - bz.degree() for bz in self.boundary_zerofiers(boundary)]
    

    def sample_weights(self, number, seed):
        return [self.field(self.hash_func(Bytes.wrap(seed) + Bytes(i)).int()) for i in range(number)]


    def prove(self, trace, transition_constraints, boundary, proof_stream: FiatShamirProofStream=None):
        proof_stream = proof_stream or FiatShamirProofStream(self.hash_func)

        for _ in range(self.num_randomizers):
            # trace += [[self.field(Bytes.wrap(RUNTIME.random(17)).int()) for _ in range(self.num_registers)]]
            trace += [[self.field.random() for _ in range(self.num_registers)]]
        

        trace_domain = [self.o**i for i in range(len(trace))]
        trace_polys  = []

        for i in range(self.num_registers):
            single_trace = [trace[c][i] for c in range(len(trace))]
            trace_polys.append(self.P.interpolate(zip(trace_domain, single_trace)))


        boundary_quotients = []
        for i in range(self.num_registers):
            interpolant = self.boundary_interpolants(boundary)[i]
            zerofier    = self.boundary_zerofiers(boundary)[i]
            quotient    = (trace_polys[i] - interpolant) / zerofier
            boundary_quotients.append(quotient)


        fri_domain = self.fri.evaluate_domain()
        boundary_quotient_codewords    = []

        for i in range(self.num_registers):
            boundary_quotient_codewords.append([boundary_quotients[i](d) for d in fri_domain])
            root = MerkleTree(self.hash_func, boundary_quotient_codewords[i]).commit()
            proof_stream.write(root)


        point = [self.P.symbol] + trace_polys + [tp(self.o*self.x) for tp in trace_polys]
        transition_polys = [con(point) for con in transition_constraints]

        trans_zerofier = self.transition_zerofier()
        transition_quotients = [tp / trans_zerofier for tp in transition_polys]

        random_poly     = self.P.random(self.P.symbol**(self.max_degree(transition_constraints)+1))
        random_codeword = [random_poly(d) for d in fri_domain]
        random_root     = MerkleTree(self.hash_func, random_codeword).commit()
        proof_stream.write(random_root)


        weights = self.sample_weights(1 + 2*(len(transition_quotients)+len(boundary_quotients)), proof_stream.hash())

        assert [tq.degree() for tq in transition_quotients] == self.transition_quotient_degree_bounds(transition_constraints)

        terms = [random_poly]

        for i in range(len(transition_quotients)):
            terms += [transition_quotients[i]]
            shift  = self.max_degree(transition_constraints) - self.transition_quotient_degree_bounds(transition_constraints)[i]
            terms += [transition_quotients[i] << shift]


        for i in range(self.num_registers):
            terms += [transition_quotients[i]]
            shift  = self.max_degree(transition_constraints) - self.transition_quotient_degree_bounds(transition_constraints)[i]
            terms += [transition_quotients[i] << shift]
        

        combination = sum([w*t for w,t in zip(weights, terms)])
        combined_codeword = [combination(d) for d in fri_domain]

        indices = self.fri.prove(combined_codeword, proof_stream)
        indices.sort()
        
        
