from samson.protocols.tls.messages import *
from samson.protocols.tls.tls_client import TLSState, TLSConfiguration
from samson.protocols.tls.ciphersuite import Ciphersuite
from samson.protocols.tls.key_schedule import KeySchedule

#################################################
#                   RFC8448                     #
# https://datatracker.ietf.org/doc/html/rfc8448 #
#################################################

# Configure objects
kex = ECDHE(G=P256.G)

def aes_gcm(key):
    rij = Rijndael(key)
    gcm = GCM(rij)
    return gcm


cs           = Ciphersuite(aes_gcm, SHA256())
config       = TLSConfiguration(kex, cs)
server_state = TLSState(config)
client_state = TLSState(config)




####################
# 0-RTT RESUMPTION #
####################



# client_state.key_schedule[KeySchedule.RESUMPTION]

# client_hello_prefix_bytes = Bytes(0x010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb)
# binder_hash = server_state.config.ciphersuite.hash_obj.hash(client_hello_prefix_bytes)
# assert binder_hash == Bytes(0x63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14)


config       = TLSConfiguration(kex, cs, psk=Bytes(0x4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3))
server_state = TLSState(config)
client_state = TLSState(config)


#####################
# CLIENT PROCESSING #
#####################

client_state.key_schedule.process_binder_secret()
assert client_state.key_schedule[KeySchedule.EARLY_SECRET] == Bytes(0x9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c)
assert client_state.key_schedule[KeySchedule.BINDER_KEY] == Bytes(0x69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256)


client_hello_bytes = Bytes(0x010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d)
client_hello       = Handshake.deserialize(client_hello_bytes)[1]
assert client_hello.serialize() == client_hello_bytes

# Build PSK Client Hello
psk_hello      = client_hello.message.val.val.deepcopy()
psk_identities = psk_hello.extensions.val.val[-1].extension_data.val.val.offered_psks.identities.val.val
del psk_hello.extensions.val.val[-1]

psk_hello = client_state.psk_client_hello(psk_hello, psk_identities)
assert psk_hello.serialize() == client_hello_bytes



client_state.sent_messages.append(client_hello)
client_state.key_schedule.process_early_secret(client_state.calculate_transcript_hash())
assert client_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET] == Bytes(0x3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62)
assert client_state.key_schedule[KeySchedule.EARLY_EXPORTER_MASTER_SECRET] == Bytes(0xb2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df)

assert client_state.get_traffic_key(client_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET]) == (Bytes(0x920205a5b7bf2115e6fc5c2942834f54), Bytes(0x6d475f0993c8e564610db2b9))

enc_application_record_bytes = Bytes(0x1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0)
enc_application_record       = TLSPlaintext.deserialize(enc_application_record_bytes)[1]
dec_application_record       = client_state.decrypt_application_data(client_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET], enc_application_record)

assert dec_application_record.content[0].val == Bytes(0x414243444546)


reenc_application_record = client_state.encrypt_application_data(client_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET], dec_application_record)
assert reenc_application_record.serialize() == enc_application_record_bytes


#####################
# SERVER PROCESSING #
#####################

server_state.key_schedule.process_binder_secret()
assert server_state.key_schedule[KeySchedule.EARLY_SECRET] == Bytes(0x9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c)
assert server_state.key_schedule[KeySchedule.BINDER_KEY] == Bytes(0x69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256)


server_state.sent_messages.append(client_hello)
server_state.key_schedule.process_early_secret(server_state.calculate_transcript_hash())
assert server_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET] == Bytes(0x3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62)
assert server_state.key_schedule[KeySchedule.EARLY_EXPORTER_MASTER_SECRET] == Bytes(0xb2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df)

server_hello_bytes = Bytes(0x0200005c03033ccfd2dec890222763472ae8136777c9d7358777bb66e91ea5122495f559ea2d00130100003400290002000000330024001d0020121761ee42c333e1b9e77b60dd57c2053cd94512ab47f115e86eff50942cea31002b00020304)
server_hello       = Handshake.deserialize(server_hello_bytes)[1]

assert server_hello.serialize() == server_hello_bytes


server_state.sent_messages.append(server_hello)


shared_secret = Bytes(0xf44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e)
server_state.key_schedule.process_handshake_secret(shared_secret, server_state.calculate_transcript_hash())
assert server_state.key_schedule[KeySchedule.HANDSHAKE_SECRET] == Bytes(0x005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6).zfill(32)
assert server_state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET] == Bytes(0x2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f)
assert server_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET] == Bytes(0xfe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803)
assert server_state.get_traffic_key(server_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET]) == (Bytes(0x27c6bdc0a3dcea39a47326d79bc9e4ee), Bytes(0x9569ecdd4d0536705e9ef725))

enc_extensions_bytes = Bytes(0x080000280026000a00140012001d00170018001901000101010201030104001c0002400100000000002a0000)
enc_exts = Handshake.deserialize(enc_extensions_bytes)[1]
assert enc_exts.serialize() == enc_extensions_bytes

server_state.sent_messages.append(enc_exts)
server_finished = server_state.finished(server_state.key_schedule[KeySchedule.SERVER_FINISHED])
server_state.sent_messages.append(server_finished)

assert server_finished.serialize() == Bytes(0x1400002048d3e0e1b3d907c6acff145e16090388c77b05c050b634ab1a88bbd0dd1a34b2)

server_state.key_schedule.process_master_secret(server_state.calculate_transcript_hash())
assert server_state.key_schedule[KeySchedule.MASTER_SECRET] == Bytes(0xe2d32d4ed66dd37897a0e80c84107503ce58bf8aad4cb55a5002d77ecb890ece).zfill(32)
assert server_state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0] == Bytes(0x2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1)
assert server_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0] == Bytes(0xcc21f1bf8feb7dd5fa505bd9c4b468a9984d554a993dc49e6d285598fb672691)
assert server_state.key_schedule[KeySchedule.EXPORTER_MASTER_SECRET] == Bytes(0x3fd93d4ffddc98e64b14dd107aedf8ee4add23f4510f58a4592d0b201bee56b4)

assert server_state.get_traffic_key(server_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0]) == (Bytes(0xe857c690a34c5a9129d833619684f95e), Bytes(0x0685d6b561aab9ef1013faf9))

enc_server_exts_finshed_bytes = Bytes(0x1703030061dc48237b4b879f50d0d4d262ea8b4716eb40ddc1eb957e11126e8a7149c2d012d37a7115957e64ce30008b9e0323f2c05a9c1c77b4f37849a695ab255060a33fee770ca95cb8486bfd0843b87024865ca35cc41c4e515c64dcb1369f98635bc7a5)
enc_server_exts_finshed       = TLSPlaintext.deserialize(enc_server_exts_finshed_bytes)[1]
dec_server_exts_finished      = server_state.decrypt_application_data(server_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET], enc_server_exts_finshed)
reenc_server_exts_finished    = server_state.encrypt_application_data(server_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET], dec_server_exts_finished)
assert reenc_server_exts_finished.serialize() == enc_server_exts_finshed_bytes


#####################
# CLIENT PROCESSING #
#####################

client_state.sent_messages.append(server_hello)

client_state.key_schedule.process_handshake_secret(shared_secret, client_state.calculate_transcript_hash())
assert client_state.key_schedule[KeySchedule.HANDSHAKE_SECRET] == Bytes(0x005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6).zfill(32)
assert client_state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET] == Bytes(0x2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f)
assert client_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET] == Bytes(0xfe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803)
assert client_state.get_traffic_key(client_state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET]) == (Bytes(0x27c6bdc0a3dcea39a47326d79bc9e4ee), Bytes(0x9569ecdd4d0536705e9ef725))

client_state.sent_messages.append(enc_exts)
client_state.sent_messages.append(server_finished)

client_state.key_schedule.process_master_secret(client_state.calculate_transcript_hash())
assert client_state.key_schedule[KeySchedule.MASTER_SECRET] == Bytes(0xe2d32d4ed66dd37897a0e80c84107503ce58bf8aad4cb55a5002d77ecb890ece).zfill(32)
assert client_state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0] == Bytes(0x2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1)
assert client_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0] == Bytes(0xcc21f1bf8feb7dd5fa505bd9c4b468a9984d554a993dc49e6d285598fb672691)
assert client_state.key_schedule[KeySchedule.EXPORTER_MASTER_SECRET] == Bytes(0x3fd93d4ffddc98e64b14dd107aedf8ee4add23f4510f58a4592d0b201bee56b4)

assert client_state.get_traffic_key(client_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0]) == (Bytes(0xe857c690a34c5a9129d833619684f95e), Bytes(0x0685d6b561aab9ef1013faf9))
assert client_state.get_traffic_key(client_state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET]) == (Bytes(0xb1530806f4adfeac83f1413032bbfa82), Bytes(0xeb50c16be7654abf99dd06d9))

client_early_data_bytes = Bytes(0x05000000)
client_early_data       = Handshake.deserialize(client_early_data_bytes)[1]
assert client_early_data.serialize() == client_early_data_bytes

enc_early_data_bytes    = Bytes(0x1703030015aca6fc944841298df99593725f9bf9754429b12f09)
enc_early_data          = TLSPlaintext.deserialize(enc_early_data_bytes)[1]
assert enc_early_data.serialize() == enc_early_data_bytes

client_state.sent_messages.append(client_early_data)

client_finished_bytes = Bytes(0x140000207230a9c952c25cd6138fc5e6628308c41c5335dd81b9f96bcea50fd32bda416d)
client_finished = client_state.finished(client_state.key_schedule[KeySchedule.CLIENT_FINISHED])
assert client_finished.serialize() == client_finished_bytes

enc_client_finished_bytes = Bytes(0x170303003500f8b467d14cf22a4b3f0b6ae0d8e6cc8d08e0db3515ef5c2bdf1922eafbb70009964716d834fb70c3d2a56c5b1f5f6bdba6c333cf)
enc_client_finished       = TLSPlaintext.deserialize(enc_client_finished_bytes)[1]
dec_client_finished       = server_state.decrypt_application_data(server_state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET], enc_client_finished)
reenc_client_finished     = server_state.encrypt_application_data(server_state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET], dec_client_finished)
assert reenc_client_finished.serialize() == enc_client_finished_bytes


client_state.sent_messages.append(client_finished)
client_state.key_schedule.process_resumption_secret(client_state.calculate_transcript_hash())

assert client_state.get_traffic_key(client_state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0]) == (Bytes(0x3cf122f301c6358ca7989553250efd72), Bytes(0xab1aec26aa78b8fc1176b9ac))
assert client_state.key_schedule[KeySchedule.RESUMPTION_MASTER_SECRET] == Bytes(0x5e95bdf1f89005ea2e9aa0ba85e728e3c19c5fe0c699e3f5bee59faebd0b5406)


####################
# APPLICATION DATA #
####################

def run_encrypted_gauntlet(state, key: bytes, enc_data_bytes: bytes):
    enc_data = TLSPlaintext.deserialize(enc_data_bytes)[1]
    assert enc_data.serialize() == enc_data_bytes
    print("HELLO")

    dec_data   = state.decrypt_application_data(key, enc_data)
    reenc_data = state.encrypt_application_data(key, dec_data)
    assert reenc_data.serialize() == enc_data_bytes



# Data Exchange
client_state.write_seq_num = 0
server_state.write_seq_num = 0
client_state.read_seq_num  = 0
server_state.read_seq_num  = 0

enc_client_application_data_bytes = Bytes(0x1703030043b1cebce242aa201be9ae5e1cb2a9aa4b33d4e866af1edb068919237741aa031d7a74d491c99b9d4e232b74206bc6fbaa04fe78be44a9b4f54320a17eb76992afac3103)
run_encrypted_gauntlet(server_state, server_state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0], enc_client_application_data_bytes)

enc_server_application_data_bytes = Bytes(0x1703030043275e9f20acff57bc000657d3867df039cccf79047884cf75771746f740b5a83f462a0954c3581393a203a25a7dd14141ef1a37900cdb62ff62dee1ba39ab2590cbf194)
run_encrypted_gauntlet(client_state, client_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0], enc_server_application_data_bytes)


# Alert Close
client_state.write_seq_num = 1
server_state.write_seq_num = 1
client_state.read_seq_num  = 1
server_state.read_seq_num  = 1

enc_client_alert = Bytes(0x17030300130facce3246bdfc6369838d6a82ae6de5d422dc)
run_encrypted_gauntlet(server_state, server_state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET_0], enc_client_alert)

enc_server_alert = Bytes(0x17030300135b18af444e8e1eec7158fb62d8f2577d37ba5d)
run_encrypted_gauntlet(client_state, client_state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET_0], enc_server_alert)
