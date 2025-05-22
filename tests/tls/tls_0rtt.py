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



#####################
# CLIENT PROCESSING #
#####################

# client_state.key_schedule[KeySchedule.RESUMPTION]

# client_hello_prefix_bytes = Bytes(0x010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb)
# binder_hash = server_state.config.ciphersuite.hash_obj.hash(client_hello_prefix_bytes)
# assert binder_hash == Bytes(0x63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14)


config       = TLSConfiguration(kex, cs, psk=Bytes(0x4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3))
server_state = TLSState(config)
client_state = TLSState(config)

server_state.key_schedule.process_binder_secret()
assert server_state.key_schedule[KeySchedule.EARLY_SECRET] == Bytes(0x9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c)
assert server_state.key_schedule[KeySchedule.BINDER_KEY] == Bytes(0x69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256)


client_hello_bytes = Bytes(0x010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020e4ffb68ac05f8d96c99da26698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d)
client_hello       = Handshake.deserialize(client_hello_bytes)[1]
assert client_hello.serialize() == client_hello_bytes

# Build PSK Client Hello
psk_hello      = client_hello.message.val.val.deepcopy()
psk_identities = psk_hello.extensions.val.val[-1].extension_data.val.val.offered_psks.identities.val.val
del psk_hello.extensions.val.val[-1]

psk_hello = server_state.psk_client_hello(psk_hello, psk_identities)
assert psk_hello.serialize() == client_hello_bytes



server_state.sent_messages.append(client_hello)
server_state.key_schedule.process_early_secret(server_state.calculate_transcript_hash())
assert server_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET] == Bytes(0x3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62)
assert server_state.key_schedule[KeySchedule.EARLY_EXPORTER_MASTER_SECRET] == Bytes(0xb2026866610937d7423e5be90862ccf24c0e6091186d34f812089ff5be2ef7df)

assert server_state.get_traffic_key(server_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET]) == (Bytes(0x920205a5b7bf2115e6fc5c2942834f54), Bytes(0x6d475f0993c8e564610db2b9))

enc_application_record_bytes = Bytes(0x1703030017ab1df420e75c457a7cc5d2844f76d5aee4b4edbf049be0)
enc_application_record       = TLSPlaintext.deserialize(enc_application_record_bytes)[1]
dec_application_record       = server_state.decrypt_application_data(server_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET], enc_application_record)

assert dec_application_record.content[0].val == Bytes(0x414243444546)


reenc_application_record = server_state.encrypt_application_data(server_state.key_schedule[KeySchedule.CLIENT_EARLY_TRAFFIC_SECRET], dec_application_record)
assert reenc_application_record.serialize() == enc_application_record_bytes

