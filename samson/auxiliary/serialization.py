from distutils import dep_util
from samson.core.base_object import BaseObject
from samson.utilities.bytes import Bytes
from enum import Enum as _Enum, IntFlag as _IntFlag
from copy import deepcopy
import linecache
import inspect
import math


def int_to_bytes(val):
    return int.to_bytes(val, (val.bit_length() + 7) // 8, 'big')


class ByteWriter(object):
    def __init__(self, data=None) -> None:
        self.data = data or b''
    
    def write(self, buffer):
        self.data += buffer


class BitWriter(object):
    def __init__(self) -> None:
        self.data = ''

    def write(self, buffer, size):
        bits = bin(int.from_bytes(buffer, 'big'))[2:].zfill(size)
        self.data += bits



class ByteConsumer(object):
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.idx  = 0
    
    def next(self, bits):
        num_bytes = math.ceil(bits / 8)
        result    = self.data[self.idx:self.idx+num_bytes]
        self.idx += num_bytes
        return result, num_bytes


class BitConsumer(object):
    def __init__(self, data: bytes) -> None:
        self.data = bin(int.from_bytes(data, 'big'))[2:]
        self.data = self.data.zfill((-len(self.data) % 8)+len(self.data))
        self.idx  = 0


    def is_done(self):
        return self.idx >= len(self.data)


    def next(self, bits):
        if self.idx < len(self.data):
            result    = self.data[self.idx:self.idx+bits]
            self.idx += bits
            if self.idx > len(self.data):
                bits = len(self.data) % bits
            return int.to_bytes(int(result, 2), math.ceil(bits / 8), 'big'), bits
        else:
            return b'', 0


class SizableMeta(type):
    SIZABLE_CLS = None

    def __getitem__(cls, size):
        class Inst(cls.SIZABLE_CLS):
            pass

        Inst.__name__ = f'{cls.__name__}[{size}]'
        Inst.SIZE = size

        if hasattr(Inst, "_construct"):
            Inst._construct()
        return Inst


class SubtypableMeta(type):
    TYPED_CLS = None

    def __getitem__(cls, l_type):
        class Inst(cls.TYPED_CLS or cls):
            pass

        Inst.__name__ = f'{cls.__name__}[{l_type.__name__}]'
        Inst.SUBTYPE = l_type
        return Inst


class SubtypedValueMeta(type):
    TYPED_CLS = None

    def __getitem__(cls, l_type):
        class Inst(cls.TYPED_CLS or cls):
            val: l_type

        Inst.__name__ = f'{cls.__name__}[{l_type.__name__}]'
        Inst.SUBTYPE = l_type
        return Inst



def reconstruct(attr_dict):
    params    = ', '.join([f"{k}={v}" for k,v in attr_dict.items()])
    filename  = f'<dynamic-{Bytes.random(8).hex().decode()}>'
    func_name = f'dynamic_{Bytes.random(8).hex().decode()}'

    source = f'def {func_name}({params}):\n    return True'
    code   = compile(source, filename, 'exec')

    l = {}
    exec(code, {}, l)

    lines = [line + '\n' for line in source.splitlines()]

    linecache.cache[filename] = (len(source), None, lines, filename)
    return inspect.signature(l[func_name])


class SizedSerializable(BaseObject):
    SIZE = 2
    FORCE_TYPE = True

    def __init__(self, *args, **kwargs) -> None:
        self.parent = kwargs.get("parent", None)


        def process(k, v, t):
            # The second type check exists because sometimes a type is not itself (what the fuck)
            # This seems to happen when a type is defined within a class (e.g. samson.protocols.opaque.messages.Messages.KE1)
            # and has requires complex subtypes
            if self.FORCE_TYPE and (type(v) is not t) and not (hasattr(type(v), '__annotations__') and hasattr(t, '__annotations__') and t.__annotations__.keys() == type(v).__annotations__.keys() and type(v).__name__ == t.__name__):
                v = t(v)

            setattr(self, k, v)

            if hasattr(v, 'parent'):
                setattr(v, 'parent', self)


        # Generate a signature
        sig = reconstruct({k:getattr(self.__class__, k, None) for k in self.__annotations__.keys()})
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()

        # Line up and process *args
        for (k, t), v in zip(self.__annotations__.items(), bound.args):
            process(k, v, t)


        # Process **kwargs
        for k, v in bound.kwargs.items():
            t = self.__annotations__[k]
            process(k, v, t)




    @classmethod
    def pack_len(cls, val):
        return int.to_bytes(len(val), cls.SIZE, 'big')


    @classmethod
    def unpack_len(cls, data):
        return data[cls.SIZE:], int.from_bytes(data[:cls.SIZE], 'big')


    def serialize(self):
        data = b''
        for k, v in self.__dict__.items():
            if k != "parent":
                data += v.serialize()
        
        return data


    @classmethod
    def deserialize(cls, data: bytes, state: dict=None):
        if hasattr(data, 'native'):
            data = data.native()
        
        return cls._deserialize(data, state)


    @classmethod
    def _deserialize(cls, data, state: dict=None):
        objs = {}
        objs2 = []
        for k, v in cls.__annotations__.items():
            data, obj = v.deserialize(data, state=objs)
            objs[k] = obj
            objs2.append(obj)

        return data, cls(*objs2)


    @classmethod
    def from_bytes(cls, data):
        return cls.deserialize(data)[1]
    

    def native(self):
        return self


    def __bytes__(self):
        return self.serialize()
    
    def __len__(self):
        return len(bytes(self))


    def __iter__(self):
        return tuple(self.__dict__.values()).__iter__()


    def __hash__(self) -> int:
        return hash((self.__class__, *list(self)))


    def __lt__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val < other


    def __gt__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val > other


    def __le__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val <= other


    def __ge__(self, other):
        if hasattr(other, 'val'):
            other = other.val
        return self.val >= other


    def __eq__(self, other):
        s, o = self, other
        if hasattr(other, 'native'):
            o = other.native()
            s = self.native()

        elif hasattr(other, 'val'):
            o = other.val
            s = self.val
        
        else:
            return o == self.native()

        if type(s) == type(o) and hasattr(s, '__dict__'):
            sd = deepcopy(s.__dict__)
            od = deepcopy(o.__dict__)

            del sd['parent']
            del od['parent']

            if sd == od:
                return True

        return (not issubclass(type(s), SizedSerializable) and s == o)


    def __reprdir__(self):
        return set(super().__reprdir__()).difference({"parent"})


    @classmethod
    def _construct(cls):
        class Subscriptable(object):
            def __getitem__(self, idx):
                return self.__class__(self.val[idx])
        
        cls.Subscriptable = Subscriptable


        class TypedClass(type):
            def __getattribute__(self, __name: str):
                if __name in self.__annotations__:
                    return self.__annotations__[__name]
                return super().__getattribute__(__name)
        
        cls.TypedClass = TypedClass


        class Primitive(object):
            def native(self):
                return self.val
            
            def __bool__(self):
                return bool(self.val)
            
            def __len__(self):
                if self:
                    return len(self.val)
                else:
                    raise TypeError("Uninstantiated primitive has no length")


        cls.Primitive = Primitive


        class Subtypable(cls, metaclass=SubtypableMeta):
            pass

        cls.Subtypable = Subtypable


        class Sizable(cls, metaclass=SizableMeta):
            pass

        cls.Sizable = Sizable



        class DependsMeta(type):
            TYPED_CLS = None

            def __getitem__(cls, params):
                l_type, selector, default = params

                class Inst(cls.TYPED_CLS or cls):
                    val: l_type


                Inst.__name__ = f'{cls.__name__}[{l_type.__name__}]'
                Inst.SUBTYPE  = l_type
                Inst.SELECTOR = selector
                Inst.DEFAULT  = default
                return Inst



        class Depends(cls, metaclass=DependsMeta):
            SUBTYPE  = None
            SELECTOR = None
            DEFAULT  = None

            def serialize(self):
                if self.SELECTOR(self.parent.__dict__):
                    return self.val.serialize()
                else:
                    return b''


            @classmethod
            def _deserialize(cls, data, state=None):
                if cls.SELECTOR(cls, state):
                    return cls.SUBTYPE._deserialize(data)
                else:
                    return data, cls.DEFAULT


        cls.Depends = Depends

        class Fixed(object):
            def __len__(self):
                return self.SIZE



        class SelectorMeta(type):
            TYPED_CLS = None

            def __getitem__(cls, selector):

                class Inst(cls.TYPED_CLS or cls):
                    pass


                Inst.__name__ = f'{cls.__name__}'
                Inst.SELECTOR   = selector
                Inst.FORCE_TYPE = False
                return Inst



        class Selector(cls, metaclass=SelectorMeta):
            SELECTOR = None
            val: object

            def serialize(self):
                return self.val.serialize()


            @classmethod
            def _deserialize(cls, data, state=None):
                return cls.SELECTOR(cls, state)._deserialize(data)


        cls.Selector = Selector


        class FixedInt(Primitive, cls, Fixed):
            SIZE   = None
            SIGNED = False
            val: int

            def __init__(self, val) -> None:
                super().__init__(val)
                if self.val.bit_length() > self.SIZE:
                    raise OverflowError("Int too large")

            def serialize(self):
                return int.to_bytes(self.val, self.SIZE // 8, 'big', signed=self.SIGNED)

            @classmethod
            def _deserialize(cls, data, state=None):
                return data[cls.SIZE // 8:], cls(int.from_bytes(data[:cls.SIZE // 8], 'big', signed=cls.SIGNED))


            def __int__(self):
                return self.val


        cls.FixedInt = FixedInt



        class SignedFixedInt(FixedInt):
            SIGNED = True
        
        cls.SignedFixedInt = SignedFixedInt


        class Int8(SignedFixedInt):
            SIZE = 8
        
        cls.Int8 = Int8


        class Int16(SignedFixedInt):
            SIZE = 16
        
        cls.Int16 = Int16


        class Int32(SignedFixedInt):
            SIZE = 32
        
        cls.Int32 = Int32


        class Int64(SignedFixedInt):
            SIZE = 64
        
        cls.Int64 = Int64


        class UInt8(FixedInt):
            SIZE = 8
        
        cls.UInt8 = UInt8


        class UInt16(FixedInt):
            SIZE = 16
        
        cls.UInt16 = UInt16


        class UInt32(FixedInt):
            SIZE = 32
        
        cls.UInt32 = UInt32


        class UInt64(FixedInt):
            SIZE = 64
        
        cls.UInt64 = UInt64


        class UInt(Primitive, Sizable):
            SIGNED = False
            SIZABLE_CLS = FixedInt
            val: int

            def serialize(self):
                val = int_to_bytes(self.val)
                return self.pack_len(val) + val


            @classmethod
            def _deserialize(cls, data, state=None):
                data, val_len = cls.unpack_len(data)
                val = int.from_bytes(data[:val_len], 'big', signed=cls.SIGNED)
                return data[val_len:], val


            def __int__(self):
                return self.val

        cls.UInt = UInt


        class MPInt(Primitive, cls):
            SIGNED = False
            val: int

            def serialize(self):
                val = int_to_bytes(self.val)
                byte_length = (self.val.bit_length() + 7) // 8
                if self.val >> (byte_length*8-1):
                    val = b'\x00' + val

                return self.pack_len(val) + val


            @classmethod
            def _deserialize(cls, data, state=None):
                data, val_len = cls.unpack_len(data)
                val = int.from_bytes(data[:val_len], 'big', signed=cls.SIGNED)
                return data[val_len:], val


            def __int__(self):
                return self.val

        cls.MPInt = MPInt


        class Int(UInt):
            SIGNED = True
            SIZABLE_CLS = SignedFixedInt
        
        cls.Int = Int


        class SizedList(Subtypable):
            SUBTYPE = None
            val: list

            def __init__(self, val=None) -> None:
                val  = [] if val is None else val
                args = [a if type(a) is self.SUBTYPE else self.SUBTYPE(a) for a in val]
                super().__init__(args)

            def serialize(self):
                data = b''
                for v in self.val:
                    data += v.serialize()
                
                return self.pack_len(self.val) + data


            @classmethod
            def _deserialize(cls, data, state=None):
                objs = []
                data, val_len = cls.unpack_len(data)
                for _ in range(val_len):
                    data, obj = cls.SUBTYPE.deserialize(data)
                    objs.append(obj)
            
                return data, cls(objs)
            

            def native(self):
                return [elem.native() for elem in self.val]


            def __iter__(self):
                return self.val.__iter__()


            def __getitem__(self, idx):
                return self.val[idx]


            def __len__(self):
                return len(self.val)


            def __delitem__(self, idx):
                del self.val[idx]


            def append(self, item):
                if type(item) is not self.SUBTYPE:
                    raise TypeError

                self.val.append(item)


        cls.SizedList = SizedList



        class GreedyList(SizedList):
            SUBTYPE = None
            val: list


            def serialize(self):
                data = b''
                for v in self.val:
                    data += v.serialize()
                
                return data


            @classmethod
            def _deserialize(cls, data, state=None):
                objs = []
                while data:
                    data, obj = cls.SUBTYPE.deserialize(data)
                    objs.append(obj)
            
                return data, cls(objs)


        cls.GreedyList = GreedyList


        class FixedBytes(Primitive, cls, Subscriptable, Fixed):
            SIZE = None
            val: bytes

            def __init__(self, val, **kwargs) -> None:
                if len(val) > self.SIZE:
                    raise OverflowError('Bytes value too large')

                super().__init__(val, **kwargs)

            def serialize(self):
                return b'\x00'*(self.SIZE-len(self.val)) + self.val

            @classmethod
            def _deserialize(cls, data, state=None):
                return data[cls.SIZE:], cls(data[:cls.SIZE])
        
        cls.FixedBytes = FixedBytes


        class Bytes(Primitive, Sizable, Subscriptable):
            SIZABLE_CLS = FixedBytes
            val: bytes

            def serialize(self):
                return self.pack_len(self.val) + self.val

            @classmethod
            def _deserialize(cls, data, state=None):
                data, val_len = cls.unpack_len(data)
                return data[val_len:], Bytes(data[:val_len])
        

        cls.Bytes = Bytes


        class GreedyBytes(Primitive, cls):
            val: bytes

            def serialize(self):
                return self.val

            @staticmethod
            def _deserialize(data, state=None):
                return b'', GreedyBytes(data)
        

        cls.GreedyBytes = GreedyBytes



        class TypedEnum(cls, _Enum):

            def __init__(self, val) -> None:
                pass

            def __repr__(self):
                return _Enum.__repr__(self)

            def __str__(self):
                return _Enum.__str__(self)

            def __boformat__(self, *args, **kwargs):
                return _Enum.__repr__(self)


            @property
            def val(self):
                return self.SUBTYPE(self.value)


            def serialize(self):
                return self.val.serialize()

            @classmethod
            def _deserialize(cls, data, state=None):
                left_over, i8 = cls.SUBTYPE.deserialize(data)
                return left_over, cls(i8.native())
        
        cls.TypedEnum = TypedEnum


        class Enum(Subtypable):
            TYPED_CLS = TypedEnum
        

        cls.Enum = Enum



        class FixedIntFlag(cls, _IntFlag):
            def __init__(self, val) -> None:
                pass

            @property
            def val(self):
                return UInt[self.SIZE](self._value_)

            def __repr__(self):
                return _IntFlag.__repr__(self)

            def __str__(self):
                return _IntFlag.__str__(self)

            def __boformat__(self, *args, **kwargs):
                return _IntFlag.__repr__(self)


            def serialize(self):
                return self.val.serialize()


            @classmethod
            def _deserialize(cls, data, state=None):
                left_over, i8 = UInt[cls.SIZE].deserialize(data)
                return left_over, cls(i8.native())
        

        cls.FixedIntFlag = FixedIntFlag


        class IntFlag(Sizable):
            SIZABLE_CLS = FixedIntFlag
        

        cls.IntFlag = IntFlag


        class Opaque(cls, metaclass=SubtypedValueMeta):
            SUBTYPE = None

            def serialize(self):
                return Bytes(self.val.serialize()).serialize()


            @classmethod
            def _deserialize(cls, data, state=None):
                data, obj = Bytes._deserialize(data)
                return data, cls.SUBTYPE.from_bytes(obj)
            

            def native(self):
                return self.val


        cls.Opaque = Opaque


        class Null(cls):
            val: None

            def __init__(self, val=None, **kwargs) -> None:
                pass

            def serialize(self):
                return b''

            @classmethod
            def _deserialize(cls, data, state=None):
                return data, Null()


        cls.Null = Null




class Serializable(BaseObject, metaclass=SizableMeta):
    SIZABLE_CLS = SizedSerializable


class Router(BaseObject):

    @staticmethod
    def selector(selector):
        def _wrapper(func):
            func.__selector__ = selector
            return func
        
        return _wrapper

    def handle(self, msg):
        for attr_name in dir(self):
            attr = getattr(self, attr_name)

            if hasattr(attr, '__selector__'):
                if getattr(attr, '__selector__')(msg):
                    attr(msg)


    def __call__(self, msg):
        self.handle(msg)


class AttributeRouter(Router):
    def __init__(self, attribute_selector) -> None:
        self.attribute_selector = attribute_selector


    def handle(self, msg):
        for attr_name in dir(self):
            attr = getattr(self, attr_name)

            if hasattr(attr, '__selector__'):
                selected = getattr(attr, '__selector__')
                if self.attribute_selector(msg) == selected:
                    attr(msg)
