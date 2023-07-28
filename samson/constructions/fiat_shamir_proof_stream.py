from samson.core.base_object import BaseObject
from samson.hashes.sha3 import SHAKE256
import dill

class FiatShamirProofStream(BaseObject):
    """
    References:
        https://aszepieniec.github.io/stark-anatomy/basic-tools
    """
    
    def __init__(self, hash_func: 'function'=None) -> None:
        self.hash_func = hash_func or SHAKE256(256).hash
        self.objects   = []
        self.read_idx  = 0
    

    def read(self) -> object:
        if len(self.objects) < self.read_idx+1:
            raise IndexError("Queue is empty")
        
        self.read_idx += 1
        return self.objects[self.read_idx-1]


    def write(self, obj):
        self.objects.append(obj)
    

    def hash(self, up_to_read: bool=False):
        idx = None
        if up_to_read:
            idx = self.read_idx

        return self.hash_func(dill.dumps(self.objects[:idx]))
