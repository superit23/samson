from samson.encoding.pem import pem_decode
from samson.encoding.general import PKIAutoParser
from samson.public_key.all import *
import unittest


class OpenSSHCodecTestCase(unittest.TestCase):

    def _run_openssh_priv_test(self, openssh_key, passphrase=None):
        decrypted = PKIAutoParser.import_key(openssh_key, passphrase=passphrase)
        self.assertEqual(pem_decode(decrypted.encode(passphrase=passphrase)), pem_decode(openssh_key))

    def _run_openssh_pub_test(self, openssh_key):
        decoded = PKIAutoParser.import_key(openssh_key)
        self.assertEqual(decoded.encode(), openssh_key)


    def test_vec0(self):
        enc_rsa = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC3OI9y/7
XkcWYsp75ZQNg+AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQDEkJ8gu8Ka
OrlokS0bVSsuUQ5m+mDvllZKc0rni6uGDn6njzg43U+Rco077M0y3CGnD9ESrsaHwI5ltS
fx9zceRlinwDma0rVPajfDq7Yh/xk3N2WlBio4nRNF4bPtZIA0vR842PisyKSn9RrF/iR8
9KUzaabEQpGkWGWJrHiGg/h3H4yJBGX9xm+tPU3nFoTj2gjHZTLvEBuSWfYtLnbqmW8Ar9
+zbCs3eUge7T7tCUPmqFMTKXN6N5rFtkoS2WGP2to7OLEXqWoSnMame3Z4UriBj4gbf13x
NVzVUnshwVqkEVz1pDJva0nSMVs1wU4xIm2rzku6hTOcuALF9nElAAAD0JUm6Sr05geQlR
n/VIJ95PW3PUh1qHVcF7TLoSfIkhfcuaS7PtcXyHmQJ+YWmCpGpGTZC/pzY79LXDPGIbcr
K0AjgX6XVKUfgA6H0zZhBHN8H2rNn3IkH9vMh5ENuhMGZYwKNiEirgGbaJNRlJTY5mzVdd
EK7r3asSkn3LdcwqEkuhK6+denGzeMK81eQS2VDrhcv9Djfz0vu4NOFbw68o+oRPeLQ2xO
1MXPCqmTyodfSNPYA2H0Csn3dJqi7aLxNxcpRv1zanc3SM1GREJ36kD70VzoZ9nJgTNiIt
kl10jzY8++WYjz8oAfCs1tFI3ccKC9KmF7E9CtAOBcI9xN84Eb/dpKl5Of2sU6puhYu+sy
xZFfCeE4D2VfI5nNKxrupA8ESxaQwsWmjgws7RrZ+jeLsB0gy+U3XQ6bnXk5gCD66mFN0R
DlYrZxqT3nRh9oIppAo0q6AOB1HiIhQtHD43K/GiKs7JlYnBPkOGX6JsbSeqhakRcQ6lGP
mtWaRITF0zfQxIiW/rkQHcNu8/VQeWKcz3ea+faXzNBG1gvjXYOyifPbA1wKpDWBB40698
UTnf62QR5DG/EqUORrWZ0Q4LhtiFWfDb5YDp3KIJ8NZapkgiMDoEvyddPh3xGK+LhtxZ9F
tTJQGY5+xcjSgM77CGrQSVKBG8NBw8sOdbGM9z3hLVmz7LveQT8hgwYs4q94jUsAMKCKz4
iDLNYqUNypyUcUcLeaDj77HkN/i7q/PpKr1ykEoDz9z+evnniuFZJvKmus5NTTs3dnI1Gr
hIwCcGF/R1QOV6UZnUxBRuvfa/8xXzPDa5j1bTObkNT89jOXSpfvfq1SKfiHHeTFkByQq8
s1LoLUd5aQ722OI9Atl0P23pTeLrI3QHn09Eu9S1DhxHO0Dw8a7PeXgOE2IkYBX1JfyWs1
Sq72jO057AwTyhH58DkbQZ24yHNw0Y6fkVGQ6nSlFEO9BvBvgw2wT1Au8UcGzQvBAr2xZW
z/n2+K0pkgjLLpsTJWCuLLnqirgljRfc/JgJ/eS0ZgTv5716SM04uT0A/GCkLIBEE5tWJO
OMaG4x7k8iOIelHkvwUeb8FscLvV13IU1aCxbNQhHrTziupEyL5VK9Dnung5nwF0Jw/nKr
rr4Te/DCawEIb/TQQrOZ9krFKKew+Y8z2Cjv02tPvQx+G+WJBDQ56RRMCAfmbfdLX+Ks5u
5tshY6hFICd/aoQUh1GChuBy4ME88WEL/9vpNj6KGZ8RR8IB9QfDCFRNqvXEXyHGexgRCA
7s6/e1jqadOkrWct67dkl+P+28IR0=
-----END OPENSSH PRIVATE KEY-----"""

        # Watch out for the spelling mistake in the key
        self._run_openssh_priv_test(enc_rsa, b'super secret passhphrase')


    def test_vec1(self):
        enc_rsa = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAgZYxVX3
wNr/2tmsTgRd25AAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQCcvbb8PXGg
Ohb/T8qHun2JcBjWVJnHepDyQnlfjjqrwpsjqJQ8a0qQ8+dxXuO+B3fYc22Gt1Nr4t3fNS
U21sRmxrR/em1WRh6Wc+7Nj/tFv9nsFh0tvYP5pDPsI+sFRt1mnxGaHy5EXwuxkPgDr/Ak
dvCaicwzuxXpsdwQQ+6om0NXiCjfp9qhd80TnQdmlrATJTXdYyFaysIf8HWQRxGUSQzwhe
J6nU+eOmTqpMVlfQ03LM676OZAztDiqbONg3xQb07n/BK2UY3OZtmebqZgsUw4Ajg+LMxI
O1fCTSVFI+GEvhW0ZmaXtFw2N8NveRKJ3gfM9ugVY7YvXdVdNYfJAAAD0FDG2FqPhIkK+0
W94eEM8+OjIi8C+VV677Ft+1x9BJL4rybawpOoMvTTKPdQB0RwxAUaglPVSyDUL/gRvnv3
gAeAW2PXToOKbxAm2GcfvZbaLl4re9pGrNiUPP92iw9F20w8/KcQ3r5sy1xdSN1mb1W/76
7c2OhTliCbWQS5s1WjDuZ3J9+ppVwwOTzWwqyWT3G1zNoE1pDquM2yiR11iulWD1sJN6n9
4L+2NO52ckuT76WpPUO8Qi1BKhjmY+UyVQNOUOdi0GujRCtA91ww+SIH7dRZIyDQ1N1Lma
IvWl35vFXbP0nSlkDlm5SlwOnjQhmpfBpvJdC+QmpoeX8GIDVn16lkI2FIxtOTqDvBoYmj
AHdB2GK0KkZjA68Dox7AqTQKuGcTXuPKHiTRV2tpZn4kFmOzpoDm1DdyRwIZI4QjrgoLCN
vyakSLRW5drCdiKxMrBFiXC7hvTA4RM8fxdnDFxxwwkfbXFR7ey7HRKVLl3I1Pua6/y2MW
0kN1g9Fceq+WTpfPaAgf8CP5uyFRZGZeZb6E8uRWJGw9K8bpKQ5ufwYJzCVqyXCOTJmHwY
PmpT4QkEvh1Sro4WGibxQCCPuzo0JD8A7fWpMCe/1G8dCp78wj44ETg+bWIKKt3KnErHG9
uBh2y/ADMQv3uxBgHEZzVcq/YprgCW+rVj8W56QsRjZHu4mGNdZ+P0tDOVNlAHu8wwEAFg
ic+kFRB+JBSJbKT0nnxE3Dzb+O3zD925fS0WNRtYJ+ROp/sLwAD7xSEX+0SNsVrhmwQNHl
Po9y971t6M/Kd0kQqENz8xdqo2oKqTOvH24V8PHl3RgNmgHvkGNlPl9/UvXL0V1zdpHD2U
wnRQsGzNiX1LXQFERNGsOEb5ufs0LL07mdV3IuRwlbjnAZVrXU8Iri5pB30qZrlAllIW+b
3Ws+/fQIrMbDb005IRcJqHAUxMuC5YThZgdfsfMRM9F3tH4ryQ4FnW6Rzj4lRp01NWPBAd
DoSYdKvM1oW4J4G6SKfaDiRDYXoCpmPguFCLkdx7gmNU7gWY8XpoH2aAyLjPFGKJLXocyQ
nomsz7oByQzm779FDFMIsqvz7nIzAMxvKSLujkF74wPktbyHlniNNsYa5AJaw0fkMIYtUF
srbmJZmyR0f2z8NHvBSTweOfVgWe+xyzPxe+ysg7ObtF63TtsRx5pjPXxMEooDJj+7hcJ0
E0ahS5viCRC2MF/lzGYp2MV9NtARE1piRUh3M34qzmbQUXjV6Z0YRU4b6zWx6Q+3RcBGY/
5zYQA2HyylyosDPH2KZovi6k3pe60=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(enc_rsa, b'qwertyuiop')


    def test_vec2(self):
        enc_rsa = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcvbb8PXGgOhb/T8qHun2JcBjWVJnHepDyQnlfjjqrwpsjqJQ8a0qQ8+dxXuO+B3fYc22Gt1Nr4t3fNSU21sRmxrR/em1WRh6Wc+7Nj/tFv9nsFh0tvYP5pDPsI+sFRt1mnxGaHy5EXwuxkPgDr/AkdvCaicwzuxXpsdwQQ+6om0NXiCjfp9qhd80TnQdmlrATJTXdYyFaysIf8HWQRxGUSQzwheJ6nU+eOmTqpMVlfQ03LM676OZAztDiqbONg3xQb07n/BK2UY3OZtmebqZgsUw4Ajg+LMxIO1fCTSVFI+GEvhW0ZmaXtFw2N8NveRKJ3gfM9ugVY7YvXdVdNYfJ test@test.local"
        self._run_openssh_pub_test(enc_rsa)



    def test_vec3(self):
        dsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsgAAAAdzc2gtZH
    NzAAAAgQD1nGVTU+kg+SRS3TMnEIAOkZLJi3OxU7vvawqEFPV4RKPnU9awDNhvH8+CJ7Jg
    C8UOcffNSLG87ub6Nk5YjGbCQ1W+pjLrc4Aq7tsk0mqmSGyWGijPOP7Y+rSDEmjDxZIapX
    2hqV+Ltd456Ekg1hgun9LQJP+w/luKVcV7PRA3VQAAABUAmw7YiVhxmDj2l1iKL8tdgsPY
    nGsAAACBAJITiWx8YggPTAmt6QbFRilem81b8X9ZTeXrXBm6dGc9qRymuxrTGk7pgfHJMD
    C+xGORlokb8arbalwS7+mn2vBs2ju/nr5uOvCP6VdzLx/btZWwIGbBYv1hfoSXVyt/I4Xf
    y/8aCYFetK+g/3yoRuXht8oZ4zIwyoaFbFmh5EQ/AAAAgDKE2F8m0DEkJ7DP9tc/PSqid7
    jkE/9CiunJKg0/lbohIq/ohwRVs3fFj/bsMkG+7fhZc0dsRZ2bjKAvLF2jS2WkHcz0fNGk
    ZOlKn9rK5BEBtKGpjoenI46SP5V0j/xyAKgJcqtdOdcq2XmM3d1cwKWJ/7BHkNaX6FLEJR
    Ml+4uzAAAB6N1Cm3PdQptzAAAAB3NzaC1kc3MAAACBAPWcZVNT6SD5JFLdMycQgA6RksmL
    c7FTu+9rCoQU9XhEo+dT1rAM2G8fz4InsmALxQ5x981Isbzu5vo2TliMZsJDVb6mMutzgC
    ru2yTSaqZIbJYaKM84/tj6tIMSaMPFkhqlfaGpX4u13jnoSSDWGC6f0tAk/7D+W4pVxXs9
    EDdVAAAAFQCbDtiJWHGYOPaXWIovy12Cw9icawAAAIEAkhOJbHxiCA9MCa3pBsVGKV6bzV
    vxf1lN5etcGbp0Zz2pHKa7GtMaTumB8ckwML7EY5GWiRvxqttqXBLv6afa8GzaO7+evm46
    8I/pV3MvH9u1lbAgZsFi/WF+hJdXK38jhd/L/xoJgV60r6D/fKhG5eG3yhnjMjDKhoVsWa
    HkRD8AAACAMoTYXybQMSQnsM/21z89KqJ3uOQT/0KK6ckqDT+VuiEir+iHBFWzd8WP9uwy
    Qb7t+FlzR2xFnZuMoC8sXaNLZaQdzPR80aRk6Uqf2srkEQG0oamOh6cjjpI/lXSP/HIAqA
    lyq1051yrZeYzd3VzApYn/sEeQ1pfoUsQlEyX7i7MAAAAUPPaYXG06+mjRlqnkrbQO9Toe
    V60AAAARZG9uYWxkQERvbmFsZC1NQlAB
    -----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(dsa_key)



    def test_vec3_pub(self):
        dsa_key = b"ssh-dss AAAAB3NzaC1kc3MAAACBAPWcZVNT6SD5JFLdMycQgA6RksmLc7FTu+9rCoQU9XhEo+dT1rAM2G8fz4InsmALxQ5x981Isbzu5vo2TliMZsJDVb6mMutzgCru2yTSaqZIbJYaKM84/tj6tIMSaMPFkhqlfaGpX4u13jnoSSDWGC6f0tAk/7D+W4pVxXs9EDdVAAAAFQCbDtiJWHGYOPaXWIovy12Cw9icawAAAIEAkhOJbHxiCA9MCa3pBsVGKV6bzVvxf1lN5etcGbp0Zz2pHKa7GtMaTumB8ckwML7EY5GWiRvxqttqXBLv6afa8GzaO7+evm468I/pV3MvH9u1lbAgZsFi/WF+hJdXK38jhd/L/xoJgV60r6D/fKhG5eG3yhnjMjDKhoVsWaHkRD8AAACAMoTYXybQMSQnsM/21z89KqJ3uOQT/0KK6ckqDT+VuiEir+iHBFWzd8WP9uwyQb7t+FlzR2xFnZuMoC8sXaNLZaQdzPR80aRk6Uqf2srkEQG0oamOh6cjjpI/lXSP/HIAqAlyq1051yrZeYzd3VzApYn/sEeQ1pfoUsQlEyX7i7M= test@test.local"
        self._run_openssh_pub_test(dsa_key)



    def test_vec4(self):
        dsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABsQAAAAdzc2gtZH
NzAAAAgQCEeZFwyJ4M1QEL251l+mo/dmUo9GXmPpfr8EA44uUuM4m6Gi2KnLugNCIaFanT
356VvWIetrFf38rKs8GpoBbdA1S9oilhs7pmL4TQf+zLv/a/pVo7xPmSNj0y9wEEaaPC/9
xu+tqxaCAt+lV3QtRrbjotEscT1WWyABJtyiZtPQAAABUAp/CKxPlh1CJ+wflQMNMX1nZ9
RwcAAACAUs5bKq4/BKjwPBNsjKpReBYohjdUb6PimWmPjsoAMrKTy1rMXHq+lX8wmxwEIU
XB1Con0QrSN3TuqUih0uGfC9mV1T2bBCrJRmW/qlyqqg5R0JnJb3wnZQR9QBsAac8w8vcZ
TYD8k7pKuvaz/UvDyfjeryshmwqkcDXUdtcTgzgAAACAMsp9fPlf+ePJ1Zn+DgUKHlGZqJ
rhKV7cnGNN69bptFwKntPTdxBZxPiYcuJC9NqdIYf1K/v53ovpIiHqwLB0Jq0HpAhwX3q0
+gjhsNWrCXvGXUrL3/Yg///dlLp3legH/4qmU+sql5I8jwdXr2ODdkzSdy0mI7MWv2TfA7
S5vtQAAAHojUae2o1GntoAAAAHc3NoLWRzcwAAAIEAhHmRcMieDNUBC9udZfpqP3ZlKPRl
5j6X6/BAOOLlLjOJuhotipy7oDQiGhWp09+elb1iHraxX9/KyrPBqaAW3QNUvaIpYbO6Zi
+E0H/sy7/2v6VaO8T5kjY9MvcBBGmjwv/cbvrasWggLfpVd0LUa246LRLHE9VlsgASbcom
bT0AAAAVAKfwisT5YdQifsH5UDDTF9Z2fUcHAAAAgFLOWyquPwSo8DwTbIyqUXgWKIY3VG
+j4plpj47KADKyk8tazFx6vpV/MJscBCFFwdQqJ9EK0jd07qlIodLhnwvZldU9mwQqyUZl
v6pcqqoOUdCZyW98J2UEfUAbAGnPMPL3GU2A/JO6Srr2s/1Lw8n43q8rIZsKpHA11HbXE4
M4AAAAgDLKfXz5X/njydWZ/g4FCh5Rmaia4Sle3JxjTevW6bRcCp7T03cQWcT4mHLiQvTa
nSGH9Sv7+d6L6SIh6sCwdCatB6QIcF96tPoI4bDVqwl7xl1Ky9/2IP//3ZS6d5XoB/+Kpl
PrKpeSPI8HV69jg3ZM0nctJiOzFr9k3wO0ub7UAAAAFEEnPct/4v9ju0UrGrltlvYMHcfv
AAAAEWRvbmFsZEBEb25hbGQtTUJQAQI=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(dsa_key)


    def test_vec4_pub(self):
        dsa_key = b"ssh-dss AAAAB3NzaC1kc3MAAACBAIR5kXDIngzVAQvbnWX6aj92ZSj0ZeY+l+vwQDji5S4ziboaLYqcu6A0IhoVqdPfnpW9Yh62sV/fysqzwamgFt0DVL2iKWGzumYvhNB/7Mu/9r+lWjvE+ZI2PTL3AQRpo8L/3G762rFoIC36VXdC1GtuOi0SxxPVZbIAEm3KJm09AAAAFQCn8IrE+WHUIn7B+VAw0xfWdn1HBwAAAIBSzlsqrj8EqPA8E2yMqlF4FiiGN1Rvo+KZaY+OygAyspPLWsxcer6VfzCbHAQhRcHUKifRCtI3dO6pSKHS4Z8L2ZXVPZsEKslGZb+qXKqqDlHQmclvfCdlBH1AGwBpzzDy9xlNgPyTukq69rP9S8PJ+N6vKyGbCqRwNdR21xODOAAAAIAyyn18+V/548nVmf4OBQoeUZmomuEpXtycY03r1um0XAqe09N3EFnE+Jhy4kL02p0hh/Ur+/nei+kiIerAsHQmrQekCHBferT6COGw1asJe8ZdSsvf9iD//92UuneV6Af/iqZT6yqXkjyPB1evY4N2TNJ3LSYjsxa/ZN8DtLm+1A== test@test.local"
        self._run_openssh_pub_test(dsa_key)


    def test_vec5(self):
        ecdsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSg72tZM8/K9MdojLaDTbvkoYVXpKOy
1uApmrsxCZvlCUSY5oTbO6dLX4CfHBRBIyYozxBfgcfmFt/t4XI/lLLYAAAAsL4zYeO+M2
HjAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKDva1kzz8r0x2iM
toNNu+ShhVeko7LW4CmauzEJm+UJRJjmhNs7p0tfgJ8cFEEjJijPEF+Bx+YW3+3hcj+Ust
gAAAAhAIlhbJgLqbWvSMoc8DLRfjFxwMD+IsVUJVJh9d/dyIlaAAAAEWRvbmFsZEBEb25h
bGQtTUJQAQIDBAUG
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(ecdsa_key)


    def test_vec5_pub(self):
        ecdsa_key = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKDva1kzz8r0x2iMtoNNu+ShhVeko7LW4CmauzEJm+UJRJjmhNs7p0tfgJ8cFEEjJijPEF+Bx+YW3+3hcj+Ustg= test@test.local"
        self._run_openssh_pub_test(ecdsa_key)


    def test_vec6(self):
        ecdsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTEvVHDHpdd5FO9kDK3NGvYrELv/xz8
TkyilsxSun696P6JGfALwGekYR3vZCVbx8jpadYepm43qCo3A/K+f41cAAAAsA50iCsOdI
grAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMS9UcMel13kU72Q
Mrc0a9isQu//HPxOTKKWzFK6fr3o/okZ8AvAZ6RhHe9kJVvHyOlp1h6mbjeoKjcD8r5/jV
wAAAAgGGwMBSyO8je/vgMA03iw0Ss+H6bbWJ5yArOBP/cauq8AAAARZG9uYWxkQERvbmFs
ZC1NQlABAgMEBQYH
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(ecdsa_key)


    def test_vec6_pub(self):
        ecdsa_key = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMS9UcMel13kU72QMrc0a9isQu//HPxOTKKWzFK6fr3o/okZ8AvAZ6RhHe9kJVvHyOlp1h6mbjeoKjcD8r5/jVw= test@test.local"
        self._run_openssh_pub_test(ecdsa_key)


    def test_vec7(self):
        eddsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAZQYey20n5vfzDpBfgpREtBbgm3nausKMUPWxGJOvLygAAAJh8qQ7jfKkO
4wAAAAtzc2gtZWQyNTUxOQAAACAZQYey20n5vfzDpBfgpREtBbgm3nausKMUPWxGJOvLyg
AAAEA9dyAbkQ9SYMduePMZX2oDsNxrAp8eqL4b2LZ5k33q7xlBh7LbSfm9/MOkF+ClES0F
uCbedq6woxQ9bEYk68vKAAAAEWRvbmFsZEBEb25hbGQtTUJQAQIDBA==
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(eddsa_key)


    def test_vec7_pub(self):
        eddsa_key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBlBh7LbSfm9/MOkF+ClES0FuCbedq6woxQ9bEYk68vK test@test.local"
        self._run_openssh_pub_test(eddsa_key)


    def test_vec8(self):
        eddsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBy8UrwPjpDfsvoXEaW9bXPqokbsMeRg+aVpCrQpYYDngAAAJhY0rPxWNKz
8QAAAAtzc2gtZWQyNTUxOQAAACBy8UrwPjpDfsvoXEaW9bXPqokbsMeRg+aVpCrQpYYDng
AAAEAsbUCaK45d4/w/FEkq70q8cCH1Azd9cM/5ndnuAQ4Sx3LxSvA+OkN+y+hcRpb1tc+q
iRuwx5GD5pWkKtClhgOeAAAAEWRvbmFsZEBEb25hbGQtTUJQAQIDBA==
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(eddsa_key)


    def test_vec8_pub(self):
        eddsa_key = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHLxSvA+OkN+y+hcRpb1tc+qiRuwx5GD5pWkKtClhgOe test@test.local"
        self._run_openssh_pub_test(eddsa_key)



    def test_vec9(self):
        dsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBUtpRfG6
7bmXSNa99+1qkVAAAAEAAAAAEAAAGxAAAAB3NzaC1kc3MAAACBAJGqgLb7OTx+iIRfdeGP
R91YrKaNeu1cbedUZeDJP5m4g9P6i0knlgGpwqz5rC6Y5wTl2CMEd8HrobwKR0X/66aHuX
yosa4AEQqXILqkYq/Z6Qwy3MI12tE6UsguE5iKhvAMOQ6g3Io8QN6x2i5LLg6aH075sJYF
ECXOoBOTcQKzAAAAFQC7rpiLroOV9K2zWNfZz5FJPADu2wAAAIAp2ePOJyf8jscDRcFsMd
Gz1SC9qUM57sNfy1v9DQV4M/BSJhkbLKXFW7n2Gaw/36fd0vNU4NVAu2v1+bXnr/dyEYm5
nJDGIMrpXN8w/b89K9w6Asm7svWEkkM3orRuqw8LdQX6FMvlaRMLZBxmkcgHPm6PlOEkLX
i1Ehq16r7X6gAAAIBFWZBp6DD/ZlteflZq36BzH8IztA7EHuNvq6QDPpc9lor4prWAwAd7
UjqZ8sCpxJUCTAoz0Sl+B6JUYsADq6dJfRXHU90czL3mDBjtFPPz0tdRSnuxAe6hAHkd2g
93DuvSw4ntLwllAyeN6hYfLhMlC3uTWXyv0AGBEDdu9CC1xgAAAfBm3gGitDdmyTDBIin9
BISIw6Rwrrn52UkLN1mhXnX4Q+VJt/wafnCkDfhtmhwgOV23wWMCPR7g5pJS2DwzC5DrM8
P+W7Vuu2EHzMWs2ppa/6j9xZv3YYBojTt7WL3ZyJm3h/5QJxiGuklERpfxkelSsJxiqR8r
+PDSpZEx420cAGUoLXDBtHyC5kflseKmXdgAE+r5PCpllHxZYIa0Ri+KKGJKoURmXE2ZBi
X7ubMWNHmJoXQdPg/oxErS3HkT5WtDsy/TKvQPECZUoFunsmC9DceyosxnDIXGeHL9CMW5
fgfsiLyG8yrAwCyz9cuyQHu2jZh3apErYeZPQi+MOqtZeaazZitsBGNB1BXV4eIbavAluR
oiMsvUx2ifGnMws+EEjfWIbHSZ+BXgFS1lo8TViVHUmtW0z6jFUz491rdpaEOpeusG06Uu
GAE+GAQBXvCHOloGfosUCsO+MA/cs5QnkqGNMBmi1XNOmQElSHt8Tphkwm5JngIDdCjFA6
nOEpbEg/sp9CCeVJxpgSxyoFYixGLW85Ss+QrMub+nXIOYXyQksx6PJDzCQ0OR1N1WuH25
vuA2jstQZQOQfgqFdWlqFNWIG13kDahuNyun1RZiU3Io3i6rNkcgUfiG2UBd7TWZYmuE43
TAYnB9YyPCGphG
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(dsa_key, b'bad password')



    def test_vec10(self):
        ecdsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDeR5QLZu
OJR5459267526tAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBExcYjymvITWMgT+46+Q2HW32mGDiGHh04Db0dQBGPGIMiTUaQjTc2ypy4
mYClvKWK6cWyJpS2c+sxJsjNvVgO0AAACwC4nQ9eI7nwZaccUcNvPnLdEKdDJVkqowQqkV
6ELOXek4CxM/Zjcn/zFOJ4CzsOOkbyxMM8b3++WDvo0rl2Mh5GBNYNzTlGI3xyWG9aIymN
dKe54rrd6Vthc8FWa+QJGMM7iW40wH3X8I0Bma3/QeepSjk7d4i6yqyGUdOJUw/6LY81c8
POk1CjRmYABH3Nx4ZOyM0DQUr60xJ3p+DK0r2JuJag6NlfHah6RlmwsJKLQ=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(ecdsa_key, b'ab62b682b7e52bd2')



    def test_vec11(self):
        ecdsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDbKkOvUD
+n9Wd6aD/Di+kPAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBKVtI+4WuK2ADIne2450En/Rx0kvYTsYa1/Pxv4fWWbMclGUDcM5GCUDj3
MOswiPcHjIvI4tTEEATVznwVO+IlgAAACw2IsDbaNLemAvulO0Rghu174rE2UtGPMAk/4y
Cv6E3BAccLLe6XkCC3Tplb0/bF0Xlb46jSiWBdXoFF8DU8o6sUVP925noq2PyU5z3oKbgG
AxTLP7peowIUVuhYTxEm+UjbHKffmZqpcl7NjmXZne3mBQ0ER2leJYbCMSOIFCjfvHcUYS
QkIhI9KAdhuATMcnJAGE+AZWb7kc5e5DCjzcmXwiwgyziX87684XLJkabl4=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(ecdsa_key, b'1234567890')



    def test_vec12(self):
        eddsa_key = b"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBWby+4bc
EsmEWj6fq6SQUPAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHP1W2usseyTiIU1
XYSZmJpLud3rQIaIK4Sz+kvD4htlAAAAoMltuZETjKT60Af4ZafuGcyGOmRFZxeww2Q8cW
pR+EL8sH4Xv59v/xSbfdtQ//b/nKe3l2O9ctzyxKHplQtuhxnZyKieLrevtm0WYB04Y6CM
no7OAzxRjL6EEP1tjS+BODjLzSl65RA/xs+in7isGuKdoIRNsjuTFkv5dpSPNxnt7XTCoD
MjVf9IZeisieJJYf/NF2ttJ+JRkUlWZhx7xHM=
-----END OPENSSH PRIVATE KEY-----"""

        self._run_openssh_priv_test(eddsa_key, b'49a4b3b86a7a51758ec37e3a0a503add1dc867a6ebace796134a8078687c607b982cca76e488a7010067e52c2c2adcf3f18a129f6e47b80b1b0aea6a73810e76')


    def test_vec13(self):
        cert = b'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgYqJn21KRTR9C/I6IP+AxOflBqEK+ixD0baJMLY9ztbsAAAAIbmlzdHAyNTYAAABBBLmpGfjtVOSZZzXO0hVmB/K7BmWFTX8p5HmrdhcObIgC1kPIi+3vICDw0ecKIY966u+xFADhEFxyL5oA+5bl2HMAAAAAAAAAAAAAAAEAAAALYm9iYW5pYm9rYXkAAAAPAAAAC2JvYmFuaWJva2F5AAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDAIxzdxyEFWIhRW23uRDT9TqP6pmgiede4Nfk89/fYC5S3Lj2zcM0r0Gin+zM041/MabZtftwoyeYLAncLr3jodLVHWRf4TKdD1bUwcSfPQRiuTDFKpzfggP14xddFJf3JjIR7itCNNjg//6ogBlIdsn8k5SvAXOY5TB5HfwcXrEbvhuHbAQYaKe3BxSdXVc+b5XdLNDzttqIvLRUBLPqUthRwK9+3dd2ZWVFtXZQDgsI3sDvyTpgzw9N0sdnLF57X4XNCR3mGNkXHjgr9F6ArkLhvtlmz9Lav1PZMNtRt3JhyDmyej+Ltn0a8FF08qKMymGV6C0xVIMPnDpU2jh4Co4tBMbUNfv2vhlPJS5+aKYdzB807QUnNlpcdph0JTLgmyX8fplkH5RPOJ7yxgXFUR2tXne26SJUiIN6528XUTJgYlHluv+DAW7NjPO9pMh6oj6yr4Hl09apLcjwGSvgNiVqm9uGGIoXcRZS7ix7M4e8TNux3MKJQZcAw947qXx8AAAGUAAAADHJzYS1zaGEyLTUxMgAAAYAJro5Akp/CSAGBnzeskR0Gt7/t2BqsegcZXQ6oY3fQYpxvrkvcDqamg7V81sAKD3qbXwFw/R8jwPCC1dtanz2WGRiqKUU/9CpDiInW7UK0eqy/If1YAz0D5/3RSx99OW4/iHJis3+JnEyvJygo+rDHXP7KZ3kEUlLhSBR5MDvKqktgaPdJoNqDhekBgokV+qwZFb/gIiPKhEhQ/YjOUDSEwKCvo4I9wnL+yYwLmrq9vbYPd+75wGJsmj/ZbmOkwXql9wGXrn1is6MR69hsxH/S4BW3G5qZJgQncu9Xb6FYuzKEHXJTw/DNtkzlbRCX8LFWDPTdkdxIZFkSDWrYdEVOKCa4U7mRZANdQ/zCXD74+5JEF7xNyHGWaSvMwO+a+Z9rleEg17IcVWlPjaziHLfWZWN/vbD2v/p5Is1oZx6cppKRFsF95b2JsHPTKVSZ4JLyEZaeu7sL8LXpkHucnVC6M4lcH6GPjDxmNsEkQUl5cbYN+pGNUie7/zmj+VqPeLw= kali@LSG-AZ0038709'
        self._run_openssh_pub_test(cert)


    def test_vec14(self):
        cert = b'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAghMmhdf9lEGM/po666FoHhOgEKuG8Tu8jsdWKCg+2XQwAAAAIbmlzdHAyNTYAAABBBLmpGfjtVOSZZzXO0hVmB/K7BmWFTX8p5HmrdhcObIgC1kPIi+3vICDw0ecKIY966u+xFADhEFxyL5oA+5bl2HMAAAAAAAAAAAAAAAEAAAALYm9iYW5pYm9rYXkAAAAPAAAAC2JvYmFuaWJva2F5AAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAcKJf384hf6wjGNMzfu5Kn8hpz9XRvg5J4iItXMbS+XIGCBUwjfcMRbbxkEp92oy1I2x3/jX1+S7Dly1proSdUAAABjAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABIAAAAICu1WkyInGzMZh8DJHfrwXzNRlEG8ArsoaK2P2pzFtr2AAAAIARthsnv5jUk+glncXG0Z5Pd+2Yzzj0DdjMC0Ouzn2Ny kali@LSG-AZ0038709'
        self._run_openssh_pub_test(cert)

    def test_vec15(self):
        cert = b'ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgBIwxIVNy+FYcia8y+eentDzmIL8FhKNL2uDuzQT4BrkAAAAIbmlzdHAyNTYAAABBBLmpGfjtVOSZZzXO0hVmB/K7BmWFTX8p5HmrdhcObIgC1kPIi+3vICDw0ecKIY966u+xFADhEFxyL5oA+5bl2HMAAAAAAAAAAAAAAAEAAAALYm9iYW5pYm9rYXkAAAAPAAAAC2JvYmFuaWJva2F5AAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJofjrP/2lrZALvX9ZlWBLlhSylKTSBrklur+vNECkOeAAAAUwAAAAtzc2gtZWQyNTUxOQAAAECvJ/kRqSkyq/ZDuf/HlwzRZQLshakJ6eNiS3P0ibVDhKqkUn6RaZezmFCD9kVfntddXevva8muL9JB8K42dQAN kali@LSG-AZ0038709'
        self._run_openssh_pub_test(cert)


    def test_vec16(self):
        cert = b'ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgzOfF3/f7wgGG1ooyGIo3tIXwtDgYMrRlUS5PX/mOfCIAAAADAQABAAABgQDE2888o13hm3qVt39n7ulU98j3/yNNQdk6vIE/oQpLUj8h5awcTTRiz7VXXFX6vre/CwzG+jW9UNdnuLMfPcAXaIv+iE2gVhOEFQi6RezhV6cTn6GFsKMIJEjfHFj9S039QkibSxf9bPeUwpnyW7yQiR50I5es0RIl/VgsZICUjFtiYJusncpA3MxSXb7d8gYl2k+MvpMk3SPFYNWxp4WC0ieUzvB3KkDC5nu4hEqSZzgwDl8H9zLwcZUbX0Ho1Xbqjeeha/TstrqurDTH9ytjX6XVc0sWqGTmcFd/z5BYDaGYGvy0/peY8qGpmFyyghpLDZJSR0aR5dl53UvDlfNqomiRsa5Kf82TQMfwOgH9IzjLAYVOKtL2GfKKUzkfRbg+oWpqo6dmpyxlxMbNyM8uS6x1dlVE6GyY9GFu4kVZTS+FtFcvLSTmngjsELy2Zp0v//qM//fDjts1odHfhgwSn1SnQgduKs2O3y7mQ04HtZ4X44lQTTG+CkvcdjkpAxkAAAAAAAAAAAAAAAEAAAALYm9iYW5pYm9rYXkAAAAPAAAAC2JvYmFuaWJva2F5AAAAAAAAAAD//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJofjrP/2lrZALvX9ZlWBLlhSylKTSBrklur+vNECkOeAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEB7FM8nceeWRdDLdtBO6zsNHs6+kRabUHuTdkeUFD7exvEAEAzrv3ZNGdT6M6Yg93eBCP6F8JxEoyxkzcIELYwA kali@LSG-AZ0038709'
        self._run_openssh_pub_test(cert)


    def test_vec17(self):
        cert = b'ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFtZb0ysOwnd3whyIBHt0ZUrS5KSsBba80YioS2ugPu2AAAAIGEdUcPU2IqxIMhf5rhcnzIMs36WSgly/ZTZ65c0r2BAAAAAAAAAAAAAAAABAAAAC2JvYmFuaWJva2F5AAAADwAAAAtib2Jhbmlib2theQAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAABsgAAAAdzc2gtZHNzAAAAgQDYP2UpmlqWasH+ZJfv6r6qYlPZvh/xD9QFD01w424GsM+93gqbtR2TWZ5nVV4ywGfjNAxHl8KX+N8xAxukWvj10L+59yBTotjUqiD7BTDseOkVoWtKZ3wZaAVLjxm3XQhGnCgR1EhsM+UBEkJ4P+ewIsUo0SMZFjlBAUg3Z5OwoQAAABUA+Ai1Pq1kk9Qn6T9IL4fgAkgYZZcAAACAP6zuIElDNtBjIU5FwaAtLIjeHmwFJ30NIg/El+U+SkbeBg0PcYTobf6x/io2OFqldSJCdjxzfogRP3nWYveyEC+J/YW4tOkfCVkHcDKZyzqt1WeoTooHDqj57xPqxpwaZgeHsov09TQq2Ztzupiz6UpbTDr1DWmn8hmx+XpAgVUAAACBAKDkfaP9sP/gselQgw2fVdELXVlUl1i2Z7N7Q+oueuMgR3qCYjX1wP0yHOzgcIDLkkBYnWbnFs+QP06yAhSv1v67nCRPAYKL7ac7SLp7evFIOSR2nBZ3vwXG6qlB1dhnA1TGyhj3TdYrJ/hLC08ueHwBeZUdEwXIriB8OBFUCH2iAAAANwAAAAdzc2gtZHNzAAAAKEETou5Xl5WsUtZ/YgMeZxggOpim3/pZekurctU21fnwcEyjs/7u61c= kali@LSG-AZ0038709'
        self._run_openssh_pub_test(cert)
