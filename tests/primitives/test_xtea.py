from samson.block_ciphers.xtea import XTEA
from samson.utilities.bytes import Bytes
import unittest

# https://github.com/liut/TeaCrypt/blob/master/tea/tea_test.go
class TEATestCase(unittest.TestCase):
    def _run_test(self, key, pt, ct):
        tea = XTEA(key)

        genned_ct = tea.encrypt(pt)
        self.assertEqual(genned_ct, ct)
        self.assertEqual(tea.decrypt(genned_ct), pt)
    

    def test_vec0(self):
        pt  = Bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        key = Bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        ct  = Bytes([0xDE, 0xE9, 0xD4, 0xD8, 0xF7, 0x13, 0x1E, 0xD9])
        self._run_test(key, pt, ct)


    def test_vec1(self):
        pt  = Bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        key = Bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        ct  = Bytes([0x06, 0x5C, 0x1B, 0x89, 0x75, 0xC6, 0xA8, 0x16])
        self._run_test(key, pt, ct)


    def test_vec2(self):
        pt  = Bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        key = Bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ct  = Bytes([0xDC, 0xDD, 0x7A, 0xCD, 0xC1, 0x58, 0x4B, 0x79])
        self._run_test(key, pt, ct)


    def test_vec3(self):
        pt  = Bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])
        key = Bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        ct  = Bytes([0xB8, 0xBF, 0x28, 0x21, 0x62, 0x2B, 0x5B, 0x30])
        self._run_test(key, pt, ct)

