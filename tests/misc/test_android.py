from samson.encoding.android.secure_key_wrapper import SecureKeyWrapper
from samson.encoding.android.key_description import KeyDescription
from samson.encoding.android.transformations import RSA_OAEP_ECB
from samson.encoding.android.authorization_list import AuthorizationList
from samson.encoding.android.keymaster_def import KMKeyFormat, KMAlgorithm, KMPurpose, KMBlockMode, KMPadding, KMDigest, KMTag
from samson.encoding.general import PKIAutoParser
from samson.utilities.bytes import Bytes
from pyasn1.codec.der import encoder, decoder
import unittest


class AndroidTestCase(unittest.TestCase):
    def test_symmetric(self):
        auth_list = AuthorizationList([
            (KMTag.KM_TAG_ALGORITHM, KMAlgorithm.KM_ALGORITHM_AES),
            (KMTag.KM_TAG_PURPOSE, [
                KMPurpose.KM_PURPOSE_ENCRYPT,
                KMPurpose.KM_PURPOSE_DECRYPT
            ]),
            (KMTag.KM_TAG_KEY_SIZE, 256),
            (KMTag.KM_TAG_BLOCK_MODE, [
                KMBlockMode.KM_MODE_CBC,
                KMBlockMode.KM_MODE_ECB
            ]),
            (KMTag.KM_TAG_PADDING, [
                KMPadding.KM_PAD_PKCS7,
                KMPadding.KM_PAD_NONE
            ]),
            (KMTag.KM_TAG_NO_AUTH_REQUIRED,)
        ])

        key_desc = KeyDescription(KMKeyFormat.KM_KEY_FORMAT_RAW, auth_list)
        pub      = Bytes(0x30820122300D06092A864886F70D01010105000382010F003082010A02820101009399FB6DA27B1C838F0D319DD651349BD4E6A7951678A33A3664A06D8F516448FEAB70EF05A4F26C971A8FA0F81C50DB40AA76E743A52C2742BEC3786EDF077D4CAFF1DECDBF383B58F052DE5404E0E0787F9BC0800C4687967480FA74E4AB9B641EE202E1343496EA4D4ACB76485201BC1A9BDB0AC34BAB261B8C9A22F074DF0D98318D6F2276B29772A53768DBC1FCE635FC7517B1913C686F5953F1E14E58F732A88AF8DEC6DC66B78D2DB23BB315E2487F1D04F486F78973492C0B100ADDFB8FF308BE24991100F00C05F2A3E909C8D3B1DFC3744C2E0635B9E4DDC1287429CFD16A65E2F30E09001E9AFDB4FCC521BF2D6E8F03687036950D305164128D0203010001)
        pub      = PKIAutoParser.import_key(pub)
        trans    = RSA_OAEP_ECB(pub.key)

        secure_wrapper = SecureKeyWrapper.create(Bytes.random(32), trans, key_desc)
        data           = encoder.encode(secure_wrapper.build())

        self.assertEqual(SecureKeyWrapper.parse(data), secure_wrapper)
