from samson.core.base_object import BaseObject

class PKIParserBase(BaseObject):
    @staticmethod
    def check(buffer: bytes, **kwargs):
        raise NotImplementedError

    def encode(self, *args, **kwargs):
        raise NotImplementedError

    @staticmethod
    def decode(buffer: bytes, **kwargs):
        raise NotImplementedError

    @classmethod
    def create(cls, *args, **kwargs):
        return cls(*args, **kwargs)
