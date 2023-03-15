from samson.core.base_object import BaseObject

class VonNeumannDebiaser(BaseObject):
    def __init__(self, rng: 'FunctionType', bits: int=32) -> None:
        self.rng   = rng
        self.bits  = bits
        self.state = 0


    def generate(self) -> int:
        while self.state.bit_length() < (self.bits+1):
            while True:
                a = self.rng()
                b = self.rng()

                if a ^ b:
                    break

            for i in range(max(a.bit_length(), b.bit_length())):
                ab = (a >> i) & 1
                bb = (b >> i) & 1

                if ab ^ bb:
                    self.state  |= ab
                    self.state <<= 1

        self.state >>= 1
        self.state, val = divmod(self.state, 2**self.bits)
        return val
