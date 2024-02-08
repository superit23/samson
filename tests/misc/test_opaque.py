from samson.protocols.opaque.rfc9380 import P256_XMD_SHA_256_SSWU_RO, P256
import unittest


class OPAQUETestCase(unittest.TestCase):

    # https://datatracker.ietf.org/doc/html/rfc9380#name-p256_xmdsha-256_sswu_ro_
    def _test_rfc9380(self, ciphersuite, dst, msg, ref_P, ref_u0, ref_u1, ref_Q0, ref_Q1):
        suite  = ciphersuite(dst)
        u0, u1 = suite.encoding.hash_to_field(msg, 2)
        Q0, Q1 = [suite.encoding.map_to_curve(u) for u in (u0, u1)]
        P      = suite(msg)

        self.assertEqual(P, ref_P)
        self.assertEqual(u0[0], ref_u0)
        self.assertEqual(u1[0], ref_u1)
        self.assertEqual(Q0, ref_Q0)
        self.assertEqual(Q1, ref_Q1)


    def test_P256_XMD_SHA_256_SSWU_RO_0(self):
        msg = b''
        P = P256(
            0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4,
            0x8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415
        )
        u0 = 0xad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009
        u1 = 0x8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a
        Q0 = P256(
            0xab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5,
            0xdccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1
        )
        Q1 = P256(
            0x51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5,
            0xb45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac
        )

        self._test_rfc9380(P256_XMD_SHA_256_SSWU_RO, b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_', msg, P, u0, u1, Q0, Q1)



    def test_P256_XMD_SHA_256_SSWU_RO_1(self):
        msg = b'abc'
        P = P256(
            0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f,
            0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e
        )
        u0 = 0xafe47f2ea2b10465cc26ac403194dfb68b7f5ee865cda61e9f3e07a537220af1
        u1 = 0x379a27833b0bfe6f7bdca08e1e83c760bf9a338ab335542704edcd69ce9e46e0
        Q0 = P256(
            0x5219ad0ddef3cc49b714145e91b2f7de6ce0a7a7dc7406c7726c7e373c58cb48,
            0x7950144e52d30acbec7b624c203b1996c99617d0b61c2442354301b191d93ecf
        )
        Q1 = P256(
            0x019b7cb4efcfeaf39f738fe638e31d375ad6837f58a852d032ff60c69ee3875f,
            0x589a62d2b22357fed5449bc38065b760095ebe6aeac84b01156ee4252715446e
        )

        self._test_rfc9380(P256_XMD_SHA_256_SSWU_RO, b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_', msg, P, u0, u1, Q0, Q1)


    def test_P256_XMD_SHA_256_SSWU_RO_2(self):
        msg = b'abcdef0123456789'
        P = P256(
            0x65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80,
            0xcad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3
        )
        u0 = 0x0fad9d125a9477d55cf9357105b0eb3a5c4259809bf87180aa01d651f53d312c
        u1 = 0xb68597377392cd3419d8fcc7d7660948c8403b19ea78bbca4b133c9d2196c0fb
        Q0 = P256(
            0xa17bdf2965eb88074bc01157e644ed409dac97cfcf0c61c998ed0fa45e79e4a2,
            0x4f1bc80c70d411a3cc1d67aeae6e726f0f311639fee560c7f5a664554e3c9c2e
        )
        Q1 = P256(
            0x7da48bb67225c1a17d452c983798113f47e438e4202219dd0715f8419b274d66,
            0xb765696b2913e36db3016c47edb99e24b1da30e761a8a3215dc0ec4d8f96e6f9
        )

        self._test_rfc9380(P256_XMD_SHA_256_SSWU_RO, b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_', msg, P, u0, u1, Q0, Q1)


    def test_P256_XMD_SHA_256_SSWU_RO_3(self):
        msg = b'q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'
        P = P256(
            0x4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d,
            0x98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e
        )
        u0 = 0x3bbc30446f39a7befad080f4d5f32ed116b9534626993d2cc5033f6f8d805919
        u1 = 0x76bb02db019ca9d3c1e02f0c17f8baf617bbdae5c393a81d9ce11e3be1bf1d33
        Q0 = P256(
            0xc76aaa823aeadeb3f356909cb08f97eee46ecb157c1f56699b5efebddf0e6398,
            0x776a6f45f528a0e8d289a4be12c4fab80762386ec644abf2bffb9b627e4352b1
        )
        Q1 = P256(
            0x418ac3d85a5ccc4ea8dec14f750a3a9ec8b85176c95a7022f391826794eb5a75,
            0xfd6604f69e9d9d2b74b072d14ea13050db72c932815523305cb9e807cc900aff
        )

        self._test_rfc9380(P256_XMD_SHA_256_SSWU_RO, b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_', msg, P, u0, u1, Q0, Q1)



def test():
    # Input
    oprf_seed = bytes(Bytes(0x62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2))
    credential_identifier = bytes(Bytes(0x31323334))
    password = bytes(Bytes(0x436f7272656374486f72736542617474657279537461706c65))
    envelope_nonce = bytes(Bytes(0xa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f))
    masking_nonce = bytes(Bytes(0x38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d))
    server_private_key = 0xc36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5
    server_public_key = bytes(Bytes(0x035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874))
    server_nonce = bytes(Bytes(0x71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1))
    client_nonce = bytes(Bytes(0xab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1))
    client_keyshare_seed = bytes(Bytes(0x633b875d74d1556d2a2789309972b06db21dfcc4f5ad51d7e74d783b7cfab8dc))
    server_keyshare_seed = bytes(Bytes(0x05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f))
    blind_registration = 0x411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153
    blind_login = 0xc497fddf6056d241e6cf9fb7ac37c384f49b357a221eb0a802c989b9942256c1

    # Intermediate
    client_public_key = bytes(Bytes(0x03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214))
    auth_key = bytes(Bytes(0x5bd4be1602516092dc5078f8d699f5721dc1720a49fb80d8e5c16377abd0987b))
    randomized_password = bytes(Bytes(0x06be0a1a51d56557a3adad57ba29c5510565dcd8b5078fa319151b9382258fb0))
    envelope = bytes(Bytes(0xa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8))
    handshake_secret = bytes(Bytes(0x83a932431a8f25bad042f008efa2b07c6cd0faa8285f335b6363546a9f9b235f))
    server_mac_key = bytes(Bytes(0x13e928581febfad28855e3e7f03306d61bd69489686f621535d44a1365b73b0d))
    client_mac_key = bytes(Bytes(0xafdc53910c25183b08b930e6953c35b3466276736d9de2e9c5efaf150f4082c5))
    oprf_key = 0x2dfb5cb9aa1476093be74ca0d43e5b02862a05f5d6972614d7433acdc66f7f31

    # Outeput
    ref_registration_request = 0x029e949a29cfa0bf7c1287333d2fb3dc586c41aa652f5070d26a5315a1b50229f8
    ref_registration_response = 0x0350d3694c00978f00a5ce7cd08a00547e4ab5fb5fc2b2f6717cdaa6c89136efef035f40ff9cf88aa1f5cd4fe5fd3da9ea65a4923a5594f84fd9f2092d6067784874
    ref_registration_upload = 0x03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae52147f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aafa921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51fad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8
    ref_KE1 = 0x037342f0bcb3ecea754c1e67576c86aa90c1de3875f390ad599a26686cdfee6e07ab3d33bde0e93eda72392346a7a73051110674bbf6b1b7ffab8be4f91fdaeeb1022ed3f32f318f81bab80da321fecab3cd9b6eea11a95666dfa6beeaab321280b6
    ref_KE2 = 0x0246da9fe4d41d5ba69faa6c509a1d5bafd49a48615a47a8dd4b0823cc1476481138fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d2f0c547f70deaeca54d878c14c1aa5e1ab405dec833777132eea905c2fbb12504a67dcbe0e66740c76b62c13b04a38a77926e19072953319ec65e41f9bfd2ae26837b6ce688bf9af2542f04eec9ab96a1b9328812dc2f5c89182ed47fead61f09f71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a103c1701353219b53acf337bf6456a83cefed8f563f1040b65afbf3b65d3bc9a19b50a73b145bc87a157e8c58c0342e2047ee22ae37b63db17e0a82a30fcc4ecf7b
    ref_KE3 = 0xe97cab4433aa39d598e76f13e768bba61c682947bdcf9936035e8a3a3ebfb66e
    ref_export_key = 0xc3c9a1b0e33ac84dd83d0b7e8af6794e17e7a3caadff289fbd9dc769a853c64b
    ref_session_key = 0x484ad345715ccce138ca49e4ea362c6183f0949aaaa1125dc3bc3f80876e7cd1


    from samson.protocols.opaque.opaque import *
    from samson.protocols.opaque.rfc9380 import P256_XMD_SHA_256_SSWU_RO

    context = Bytes(0x4f50415155452d504f43)
    G       = OPRF(P256_XMD_SHA_256_SSWU_RO)
    client  = OPAQUEClient(G)
    server  = OPAQUEServer(G)

    ake_server = ThreeDHAKEServer(server, context)
    ake_client = ThreeDHAKEClient(client, context)

    # Registration
    reg_req, blind = ake_client.opaque_client.CreateRegistrationRequest(password, blind_registration)
    reg_resp       = ake_server.opaque_server.CreateRegistrationResponse(reg_req, server_public_key, credential_identifier, oprf_seed)

    record, export_key = ake_client.opaque_client.FinalizeRegistrationRequest(password, blind, reg_resp, envelope_nonce=envelope_nonce)

    assert Bytes(reg_req).int() == ref_registration_request
    assert Bytes(reg_resp).int() == ref_registration_response
    assert Bytes(record).int() == ref_registration_upload
    assert Bytes(export_key).int() == ref_export_key


    # Online Authenticated Key-Exchange
    ke1 = ake_client.GenerateKE1(password, blind_login, client_nonce=client_nonce, client_keyshare_seed=client_keyshare_seed)
    ke2 = ake_server.GenerateKE2(server_public_key, server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1, client_public_key, server_nonce=server_nonce, server_keyshare_seed=server_keyshare_seed, masking_nonce=masking_nonce)
    (ke3, session_key_c, export_key_c) = ake_client.GenerateKE3(client_public_key, server_public_key, ke2)
    session_key_s = ake_server.ServerFinish(ke3)

    assert Bytes(ke1).int() == ref_KE1
    assert Bytes(ke2).int() == ref_KE2
    assert Bytes(ke3).int() == ref_KE3
    assert Bytes(session_key_s).int() == ref_session_key
    assert Bytes(session_key_c).int() == ref_session_key
    assert Bytes(export_key_c).int() == ref_export_key
