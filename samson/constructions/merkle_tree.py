from samson.core.base_object import BaseObject
from samson.hashes.sha3 import SHAKE256

def split(leafs):
    return leafs[:len(leafs) // 2], leafs[len(leafs) // 2:]


class MerkleTree(BaseObject):
    """
    References:
        https://aszepieniec.github.io/stark-anatomy/basic-tools
    """

    def __init__(self, hash_func: 'function'=None, leafs: list=None) -> None:
        self.hash_func = hash_func or SHAKE256(256).hash
        self.leafs     = leafs

        if leafs and len(leafs) & (len(leafs)-1):
            raise ValueError("'leafs' length must be a power of 2")


    def __commit(self, leafs):
        if len(leafs) == 1:
            return leafs[0]
        else:
            left, right = split(leafs)
            return self.hash_func(self.__commit(left) + self.__commit(right))
    

    def __open(self, idx, leafs):
        if len(leafs) == 2:
            return [leafs[1-idx]]

        elif idx < len(leafs) // 2:
            left, right = split(leafs)
            return self.__open(idx, left) + [self.__commit(right)]
        
        else:
            left, right = split(leafs)
            return self.__open(idx - len(leafs) // 2, right) + [self.__commit(left)]


    def __verify(self, root: bytes, idx: int, path: list, leaf: bytes):
        if idx % 2:
            val = path[0] + leaf
        else:
            val = leaf + path[0]

        if len(path) == 1:
            return root == self.hash_func(val)
        else:
            return self.__verify(root, idx // 2, path[1:], self.hash_func(val))


    @property
    def l1_hashes(self):
        return [self.hash_func(bytes(l)) for l in self.leafs]


    def commit(self):
        return self.__commit(self.l1_hashes)


    def open(self, idx):
        return self.__open(idx, self.l1_hashes)


    def verify(self, root: bytes, idx: int, path: list, leaf: object):
        return self.__verify(root, idx, path, self.hash_func(bytes(leaf)))
