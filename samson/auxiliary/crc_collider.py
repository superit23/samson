
from samson.math.factorization.siqs import BMatrix, ge_f2_nullspace, solve_row
from samson.utilities.bytes import Bytes


class Collider(object):
    def __init__(self, data_size, nullspace=None) -> None:
        self.nullspace = nullspace
        self.data_size = data_size


    def produce_collision(self, index):
        result = Bytes().zfill(self.data_size)
        for vec, coeff in zip(self.nullspace, [int(b) for b in bin(index)[2:].zfill(len(self.nullspace))]):
            if coeff:
                result ^= vec
        
        return result


    def __len__(self):
        return 2**len(self.nullspace)


    def __getitem__(self, idx):
        if idx < 0:
            idx = len(self) - idx
        
        if idx >= len(self):
            raise IndexError

        return self.produce_collision(idx)


    def __iter__(self):
        for i in range(len(self)):
            yield self[i]



    def solve_for_mask(self, mask):
        B = BMatrix([z.int() & mask for z in self.nullspace], num_cols=self.data_size*8)
        sols, marks, M = ge_f2_nullspace(B.T)
        nullspace      = []

        for sol in sols:
            sol_vec = solve_row(sol, M, marks)
            result  = Bytes().zfill(self.data_size)

            for i in sol_vec:
                result ^= self.nullspace[i]
            
            nullspace.append(result)
        
        return Collider(self.data_size, nullspace=nullspace)



class CRCCollider(Collider):
    def __init__(self, crc_func, data_size, crc_size=None):
        self.crc_func  = crc_func
        self.crc_size  = crc_size
        self.data_size = data_size
        self.matrix_info = None
        self.nullspace = self.find_collisions()



    def find_collisions(self):
        c = self.crc_func(Bytes().zfill(self.data_size))

        rows     = [self.crc_func(Bytes(1 << i).zfill(self.data_size)) for i in range(self.data_size*8)]
        crc_size = self.crc_size or max(rows, key=lambda k: k.bit_length()).bit_length()

        B = BMatrix(rows, num_cols=crc_size)
        sols, marks, M = ge_f2_nullspace(B.T)
        self.matrix_info = (sols, marks, M)

        results = []

        for sol in sols:
            sol_vec   = solve_row(sol, M, marks)
            res       = sum([1 << i for i in sol_vec])
            bytes_rep = Bytes(res).zfill(self.data_size)

            if self.crc_func(bytes_rep) == c:
                results.append(bytes_rep)

        return results

