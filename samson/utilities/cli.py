from samson.auxiliary.console_colors import AUTO_SHIM
start_exec = """
import logging
logging.getLogger().setLevel(logging.WARNING)
logging.getLogger("samson").setLevel(logging.INFO)

from samson.all import *
from tqdm import trange
from samson.auxiliary.autodoc import autodoc
import samson
autodoc(globals())
x = Symbol('x')
y = Symbol('y')
z = Symbol('z')
ZZ[x]

logger = logging.getLogger("samson.repl")
""" + AUTO_SHIM

LOGO = """
                                                                
  /$$$$$$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$ 
 /$$_____/ |____  $$| $$_  $$_  $$ /$$_____/ /$$__  $$| $$__  $$
|  $$$$$$   /$$$$$$$| $$ \ $$ \ $$|  $$$$$$ | $$  \ $$| $$  \ $$
 \____  $$ /$$__  $$| $$ | $$ | $$ \____  $$| $$  | $$| $$  | $$
 /$$$$$$$/|  $$$$$$$| $$ | $$ | $$ /$$$$$$$/|  $$$$$$/| $$  | $$
|_______/  \_______/|__/ |__/ |__/|_______/  \______/ |__/  |__/
                                                                
                                                                
                                                                """.replace("$", "%")


def apply_logo_theme(colors):
    from samson.utilities.manipulation import stretch_key
    from samson.auxiliary.console_colors import color_format
    lines = LOGO.splitlines()
    color_map = stretch_key(colors, 6)
    
    logo  = '\n'.join(lines[:2]) + '\n'
    logo += '\n'.join(color_format(color, line) for color, line in zip(color_map, lines[2:8]))
    logo += '\n'.join(lines[8:])
    return logo


def start_repl(additional_exec: list=None):
    """
    Executes the samson REPL.
    """
    import IPython
    import sys
    from samson import VERSION
    from samson.auxiliary.console_colors import ConsoleColors
    from samson.auxiliary.samson_prompt import SamsonPrompt
    from traitlets.config import Config


    logo_theme = [ConsoleColors.BRIGHT_WHITE]


    banner = f"""
{apply_logo_theme(logo_theme)}
    v{VERSION} -- https://github.com/wildcardcorp/samson

Python {sys.version}
IPython {IPython.__version__}
"""

    conf = Config()
    conf.TerminalIPythonApp.display_banner = False
    conf.InteractiveShellApp.exec_lines = [
        start_exec,
        f'print("""{banner}""")'
    ] + (additional_exec or [])

    conf.TerminalInteractiveShell.prompts_class = SamsonPrompt

    conf.InteractiveShell.confirm_exit = False
    conf.TerminalInteractiveShell.term_title_format = f"samson v{VERSION}"

    IPython.start_ipython(config=conf)


from samson.hashes.all import MD4, MD5, BLAKE2b, BLAKE2s, Keccak, RIPEMD160, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256, Whirlpool
from samson.public_key.all import RSA, DSA, ECDSA, EdDSA
from samson.protocols.diffie_hellman import DiffieHellman
from samson.math.algebra.curves.named import EdwardsCurve25519, EdwardsCurve448
from samson.encoding.general import PKIEncoding, PKIAutoParser
from samson.math.algebra.curves.named import P192, P224, P256, P384, P521, GOD521, secp192k1, secp224k1, secp256k1, brainpoolP160r1, brainpoolP192r1, brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1

HASHES = {
    'blake2b': BLAKE2b,
    'blake2s': BLAKE2s,
    'keccak': Keccak,
    'md4': MD4,
    'md5': MD5,
    'ripemd160': RIPEMD160,
    'sha1': SHA1,
    'sha224': SHA224,
    'sha256': SHA256,
    'sha384': SHA384,
    'sha512': SHA512,
    'sha3_224': SHA3_224,
    'sha3_256': SHA3_256,
    'sha3_384': SHA3_384,
    'sha3_512': SHA3_512,
    'shake128': SHAKE128,
    'shake256': SHAKE256,
    'whirlpool': Whirlpool
}

PKI = {
    'rsa': RSA,
    'dsa': DSA,
    'ecdsa': ECDSA,
    'eddsa': EdDSA,
    'dh': DiffieHellman,
    'auto': PKIAutoParser
}


EC_CURVES = {curve.name.lower():curve for curve in [P192, P224, P256, P384, P521, secp192k1, secp224k1, secp256k1, brainpoolP160r1, brainpoolP192r1, brainpoolP224r1, brainpoolP256r1, brainpoolP320r1, brainpoolP384r1, brainpoolP512r1]}
EC_CURVES.update({
    'secp192r1': P192,
    'secp224r1': P224,
    'secp256r1': P256,
    'secp384r1': P384,
    'secp521r1': P521,
    'nistp192': P192,
    'nistp224': P224,
    'nistp256': P256,
    'nistp384': P384,
    'nistp521': P521,
    'god521': GOD521
})

ED_CURVES = {
    'ed25519': EdwardsCurve25519,
    'ed448': EdwardsCurve448
}


ENCODING_MAPPING = {
    'JWK': PKIEncoding.JWK,
    'OPENSSH': PKIEncoding.OpenSSH,
    'PKCS1': PKIEncoding.PKCS1,
    'PKCS8': PKIEncoding.PKCS8,
    'SSH2': PKIEncoding.SSH2,
    'X509': PKIEncoding.X509,
    'X509_CERT': PKIEncoding.X509_CERT,
    'DNS_KEY': PKIEncoding.DNS_KEY,
    'X509_CSR': PKIEncoding.X509_CSR
}
