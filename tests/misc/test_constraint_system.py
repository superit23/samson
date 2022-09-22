from samson.auxiliary.constraint_system import *
import unittest


a01 = EqualsConstraint('a0', 1)
a00 = EqualsConstraint('a0', 0)
a11 = EqualsConstraint('a1', 1)
a10 = EqualsConstraint('a1', 0)
b01 = EqualsConstraint('b0', 1)
b00 = EqualsConstraint('b0', 0)
b11 = EqualsConstraint('b1', 1)
b10 = EqualsConstraint('b1', 0)

oo_diff = OneOfConstraint({'a0', 'a1'}, [
            ConstraintSystem([
                a00,
                a11
            ]),
            ConstraintSystem([
                a01,
                a10
            ])
        ])


oo_diff_b = OneOfConstraint({'b0', 'b1'}, [
            ConstraintSystem([
                b00,
                b11
            ]),
            ConstraintSystem([
                b01,
                b10
            ])
        ])

class ConstraintSystemTestCase(unittest.TestCase):
    def test_eq_ident(self):
        self.assertEqual(a01 + a01, ConstraintSystem([a01]))


    def test_eq_diff(self):
        self.assertEqual(a01 + a11, ConstraintSystem([a01, a11]))
    

    def test_eq_no_sol(self):
        self.assertRaises(NoSolutionException, lambda: a01 + a00)
    

    def test_oneof_ident(self):
        self.assertEqual(oo_diff + oo_diff, ConstraintSystem([oo_diff]))
    

    def test_oneof_eq_subset(self):
        self.assertEqual(oo_diff + a01, ConstraintSystem([a01, a10]))


    # TODO: Write solution
    def test_oneof_eq_conv(self):
        self.assertEqual(oo_diff + oo_diff_b, ConstraintSystem([a01, a10]))
