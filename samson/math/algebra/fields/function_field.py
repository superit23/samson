from samson.math.algebra.fields.field import Field, FieldElement
from samson.math.factorization.factors import Factors


class RationalFunctionField(Field):
    def __init__(self, symbol, field):
        self.internal_field = field[symbol].fraction_field()
        self.symbol = symbol
        self.symbol.top_ring = self
        self.one   = self(1)
        self.zero  = self(0)
        self.field = field
    

    def __hash__(self):
        dic_items  = []
        for k,v in self.__dict__.items():
            if k not in ('symbol', 'one', 'zero'):
                if type(v) is list:
                    v = tuple(v)
                dic_items.append((k, v))
            
        return hash((self.__class__, tuple(dic_items)))


    def order(self):
        return self.internal_field.order()

    def shorthand(self):
        return f'{self.field.shorthand()}({self.symbol.repr})'


    def coerce(self, other: object):
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            RationalFunctionFieldElement: Coerced element.
        """
        if not type(other) is RationalFunctionFieldElement:
            other = RationalFunctionFieldElement(self.internal_field(other), self)

        return other



class RationalFunctionFieldElement(FieldElement):
    def __init__(self, val: object, field: RationalFunctionField):
        """
        Parameters:
            field (Field): Field this element belongs to.
        """
        self.val = val
        super().__init__(field)
    

    def __invert__(self) -> 'RingElement':
        return self.field(~self.val)


    def factor(self):
        num = self.val.numerator.factor()
        den = self.val.denominator.factor()
        return Factors({self.field(k):v for k,v in num.items()}) + {self.field(k):-v for k,v in den.items()}


    def order(self):
        return self.field.order()


class FiniteFunctionField(RationalFunctionField):
    # def __init__(self, symbol, field):
    #     self.symbol = symbol
    #     self.symbol.top_ring = self
    #     self.one   = self(1)
    #     self.zero  = self(0)
    #     self.field = field



    def coerce(self, other: object):
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            FiniteFunctionFieldElement: Coerced element.
        """
        if not type(other) is FiniteFunctionFieldElement:
            other = FiniteFunctionFieldElement(self.internal_field(other), self)

        return other




class FiniteFunctionFieldElement(FieldElement):
    def __init__(self, val: object, field: RationalFunctionField):
        """
        Parameters:
            field (Field): Field this element belongs to.
        """
        self.val = val
        super().__init__(field)

