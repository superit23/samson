from samson.core.base_object import BaseObject
from samson.constructions.merkle_tree import MerkleTree
from samson.constructions.fiat_shamir_proof_stream import FiatShamirProofStream
from samson.utilities.bytes import Bytes
from samson.math.symbols import Symbol
from samson.protocols.zkstark.exceptions import LowPolyViolation, CollinearityViolation, MerkleVerificationFailure
from samson.hashes.blake2 import BLAKE2b

class FRI(BaseObject):
    """
    References:
        https://aszepieniec.github.io/stark-anatomy/fri
    """

    def __init__(self, w, g, domain_length: int, expansion_factor, num_collinearity_checks: int, hash_func: 'function'=None) -> None:
        self.w = w
        self.g = g
        self.domain_length = domain_length
        self.expansion_factor = expansion_factor
        self.num_collinearity_checks = num_collinearity_checks
        self.hash_func = hash_func or BLAKE2b().hash
        self.P = self.field[Symbol('x')]

        if not self.expansion_factor > 3:
            raise ValueError("Expansion factor must be at least 4")
        
        if not (self.expansion_factor & (self.expansion_factor - 1) == 0):
            raise ValueError("Expansion factor must be a power of 2")


    @property
    def field(self):
        return self.w.ring
    

    @property
    def num_rounds(self) -> int:
        codeword_len = self.domain_length
        rounds       = 0

        while codeword_len > self.expansion_factor and 4*self.num_collinearity_checks < codeword_len:
            codeword_len //= 2
            rounds        += 1
        
        return rounds
    

    def evaluate_domain(self):
        return [self.g * self.w**i for i in range(self.domain_length)]
    
    def merkle_codeword(self, codeword):
        return MerkleTree(leafs=[Bytes(int(c)) for c in codeword])


    def commit(self, codeword, proof_stream: FiatShamirProofStream):
        codewords = []
        one       = self.field.one
        two_inv   = ~self.field(2)
        omega     = self.w
        offset    = self.g

        for r in range(self.num_rounds):
            # Send codeword root
            mt   = self.merkle_codeword(codeword)
            root = mt.commit()

            proof_stream.write(root)
            codewords += [codeword]

            if r == self.num_rounds-1:
                break


            # Compute next codeword via split and fold
            alpha    = self.field(proof_stream.hash().int())
            N        = len(codeword) // 2
            prev_code = codeword
            codeword = []

            w = one
            for i in range(N):
                div       = alpha/(offset * w)
                codeword += [((one + div)*prev_code[i] + (one - div)*prev_code[N + i])*two_inv]
                w        *= omega
            
            omega  **= 2
            offset **= 2
            

        proof_stream.write(codeword)
        return codewords


    def sample_indices(self, seed: bytes, size: int, reduced_size: int, num_idx: int) -> list:
        if reduced_size <= num_idx <= reduced_size*2:
            raise ValueError(f"The number of requested indices is not between ({reduced_size},{reduced_size*2})")
        
        indices = []
        reduced = []
        counter = 0

        while len(indices) < num_idx:
            idx         = self.hash_func(seed + Bytes(counter)).int() % size
            reduced_idx = idx % reduced_size
            counter    += 1

            if reduced_idx not in reduced:
                indices.append(idx)
                reduced.append(reduced_idx)
        
        return indices


    def query(self, current_codeword: list, next_codeword: list, c_indices: list, proof_stream: FiatShamirProofStream):
        # Compute indices
        a_idxs = [_ for _ in c_indices]
        b_idxs = [idx + len(current_codeword) // 2 for idx in c_indices]

        # Reveal leafs to verifier
        for i in range(self.num_collinearity_checks):
            proof_stream.write((current_codeword[a_idxs[i]], current_codeword[b_idxs[i]], next_codeword[c_indices[i]]))

        mt_current = self.merkle_codeword(current_codeword)
        mt_next    = self.merkle_codeword(next_codeword)

        # Reveal Merkle paths
        for i in range(self.num_collinearity_checks):
            proof_stream.write(mt_current.open(a_idxs[i]))
            proof_stream.write(mt_current.open(b_idxs[i]))
            proof_stream.write(mt_next.open(c_indices[i]))

        return a_idxs + b_idxs


    def prove(self, codeword: list, proof_stream: FiatShamirProofStream):
        if len(codeword) != self.domain_length:
            raise ValueError("Length of codeword does not match domain length")
        
        # Commit phase
        codewords = self.commit(codeword, proof_stream)

        top_idxs  = self.sample_indices(proof_stream.hash(), len(codewords[1]), len(codewords[-1]), self.num_collinearity_checks)
        curr_idxs = [_ for _ in top_idxs]

        # Query phase
        for i in range(len(codewords)-1):
            curr_idxs = [idx % (len(codewords[i]) // 2) for idx in curr_idxs]
            self.query(codewords[i], codewords[i+1], curr_idxs, proof_stream)
        
        return top_idxs

    
    def verify(self, proof_stream: FiatShamirProofStream) -> bool:
        omega  = self.w
        offset = self.g

        # Get all roots and alphas
        roots  = []
        alphas = []

        for _ in range(self.num_rounds):
            roots.append(proof_stream.read())
            alphas.append(self.field(proof_stream.hash(True).int()))

        last_codeword = proof_stream.read()

        # Check if codeword matches last root
        mt = self.merkle_codeword(last_codeword)
        if roots[-1] != mt.commit():
            return False

        # Check if the proof poly is low degree
        degree      = len(last_codeword) // self.expansion_factor -1
        last_omega  = omega**(2**(self.num_rounds-1))
        last_offset = offset**(2**(self.num_rounds-1))

        if ~last_omega != last_omega**(len(last_codeword)-1):
            raise ValueError("Omega has wrong order")
        
        last_domain = [last_offset * last_omega**i for i in range(len(last_codeword))]
        poly        = self.P.interpolate(list(zip(last_domain, last_codeword)))

        if poly.degree() > degree:
            raise LowPolyViolation
        

        top_idxs = self.sample_indices(
            proof_stream.hash(True),
            self.domain_length // 2,
            self.domain_length // (2**(self.num_rounds-1)),
            self.num_collinearity_checks
        )


        # Check each layer of split and fold
        for r in range(self.num_rounds-1):
            reduced_size = self.domain_length // 2**(r+1)

            # Compute the indices
            c_idxs = [idx % reduced_size for idx in top_idxs]
            a_idxs = [_ for _ in c_idxs]
            b_idxs = [idx + reduced_size for idx in c_idxs]

            aa, bb, cc = [], [], []


            # Perform collinearilty tests
            for i in range(self.num_collinearity_checks):
                ay, by, cy = proof_stream.read()
                aa.append(ay)
                bb.append(by)
                cc.append(cy)

                if not r:
                    polynomials = [(a_idxs[i], ay), (b_idxs[i], by)]
                
                ax = offset * omega**(a_idxs[i])
                bx = offset * omega**(b_idxs[i])
                cx = alphas[r]

                if P.interpolate([(ax, ay), (bx, by), (cx, cy)]).degree() > 1:
                    raise CollinearityViolation


            # Verify Merkle paths
            mt = MerkleTree()
            for i in range(self.num_collinearity_checks):
                path = proof_stream.read()
                if not mt.verify(roots[r], a_idxs[i], path, Bytes(int(aa[i]))):
                    raise MerkleVerificationFailure
                
                path = proof_stream.read()
                if not mt.verify(roots[r], b_idxs[i], path, Bytes(int(bb[i]))):
                    raise MerkleVerificationFailure
                
                path = proof_stream.read()
                if not mt.verify(roots[r+1], c_idxs[i], path, Bytes(int(cc[i]))):
                    raise MerkleVerificationFailure
            

            omega  **= 2
            offset **= 2

        return polynomials
