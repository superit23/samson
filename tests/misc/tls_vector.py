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


cs     = Ciphersuite(aes_gcm, SHA256())
config = TLSConfiguration(kex, cs)
state  = TLSState(config)



# Send and process ClientHello
client_hello_data = Bytes(0x16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001)
client_hello      = TLSPlaintext.deserialize(client_hello_data)[1]

assert client_hello.serialize() == client_hello_data

state.sent_messages.append(client_hello.fragment.val.val)
state.write_seq_num += 1

state.key_schedule.process_early_secret(state.calculate_transcript_hash())
assert state.key_schedule[KeySchedule.EARLY_SECRET] == Bytes(0x33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a)



# Send and process Server Hello
server_hello_bytes = Bytes(0x160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304)
info = Bytes(0x00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855).zfill(49)
shared_secret = Bytes(0x8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d)

server_hello = TLSPlaintext.deserialize(server_hello_bytes)[1]
assert server_hello.serialize() == server_hello_bytes


state.sent_messages.append(server_hello.fragment.val.val)

state.key_schedule.process_handshake_secret(shared_secret, state.calculate_transcript_hash())
assert state.key_schedule[KeySchedule.HANDSHAKE_SECRET] == Bytes(0x1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac)
assert state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET] ==Bytes(0xb67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38)
assert state.get_traffic_key(state.key_schedule[KeySchedule.SERVER_HANDSHAKE_TRAFFIC_SECRET]) == (Bytes(0x3fce516009c21727d0f2e4e86ee403bc), Bytes(0x5d313eb2671276ee13000b30))



# Send Application Data (Handshake)
enc_exts = Bytes(0x080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000)
_, deser = Handshake.deserialize(enc_exts)
assert deser.serialize() == enc_exts
state.sent_messages.append(deser)

cert_hs = Bytes(0x0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000)
_, deser = Handshake.deserialize(cert_hs)
assert deser.serialize() == cert_hs
state.sent_messages.append(deser)

cert_verify = Bytes(0x0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3)
_, deser = Handshake.deserialize(cert_verify)
assert deser.serialize() == cert_verify
state.sent_messages.append(deser)



assert state.finished().serialize() == Bytes(0x140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718)
state.sent_messages.append(state.finished())

state.key_schedule.process_master_secret(state.calculate_transcript_hash())

assert state.key_schedule[KeySchedule.MASTER_SECRET] == Bytes(0x18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919)
assert state.calculate_transcript_hash() == Bytes(0x9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13)
assert state.key_schedule[KeySchedule.CLIENT_APPLICATION_TRAFFIC_SECRET][0] == Bytes(0x9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5)
assert state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET][0] == Bytes(0xa11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643)
assert state.key_schedule[KeySchedule.EXPORTER_MASTER_SECRET] == Bytes(0xfe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50)
assert state.get_traffic_key(state.key_schedule[KeySchedule.SERVER_APPLICATION_TRAFFIC_SECRET][0]) == (Bytes(0x9f02283b6c9c07efc26bb9f2ac92e356), Bytes(0xcf782b88dd83549aadf1e984))
assert state.get_traffic_key(state.key_schedule[KeySchedule.CLIENT_HANDSHAKE_TRAFFIC_SECRET]) == (Bytes(0xdbfaa693d1762c5b666af5d950258d01), Bytes(0x5bd3c71b836e0b76bb73265f))

# `plaintext_records` is the concantenation of the previous three records
plaintext_records = Bytes(b'\x08\x00\x00$\x00"\x00\n\x00\x14\x00\x12\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04\x00\x1c\x00\x02@\x01\x00\x00\x00\x00\x0b\x00\x01\xb9\x00\x00\x01\xb5\x00\x01\xb00\x82\x01\xac0\x82\x01\x15\xa0\x03\x02\x01\x02\x02\x01\x020\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000\x0e1\x0c0\n\x06\x03U\x04\x03\x13\x03rsa0\x1e\x17\r160730012359Z\x17\r260730012359Z0\x0e1\x0c0\n\x06\x03U\x04\x03\x13\x03rsa0\x81\x9f0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x81\x8d\x000\x81\x89\x02\x81\x81\x00\xb4\xbbI\x8f\x82y0=\x98\x0869\x9b6\xc6\x98\x8c\x0ch\xdeU\xe1\xbd\xb8&\xd3\x90\x1a$a\xea\xfd-\xe4\x9a\x91\xd0\x15\xab\xbc\x9a\x95\x13z\xcel\x1a\xf1\x9e\xaaj\xf9\x8c|\xedC\x12\t\x98\xe1\x87\xa8\x0e\xe0\xcc\xb0RK\x1b\x01\x8c>\x0bc&MD\x9am8\xe2*_\xdaC\x08Ft\x800S\x0e\xf0F\x1c\x8c\xa9\xd9\xef\xbf\xae\x8e\xa6\xd1\xd0>+\xd1\x93\xef\xf0\xab\x9a\x80\x02\xc4t(\xa6\xd3Z\x8d\x88\xd7\x9f\x7f\x1e?\x02\x03\x01\x00\x01\xa3\x1a0\x180\t\x06\x03U\x1d\x13\x04\x020\x000\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x05\xa00\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x81\x81\x00\x85\xaa\xd2\xa0\xe5\xb9\'k\x90\x8ce\xf7:rg\x17\x06\x18\xa5L_\x8a{3}-\xf7\xa5\x946T\x17\xf2\xea\xe8\xf8\xa5\x8c\x8f\x81r\xf91\x9c\xf3k\x7f\xd6\xc5[\x80\xf2\x1a\x03\x01QVr`\x96\xfd3^^g\xf2\xdb\xf1\x02p.`\x8c\xca\xe6\xbe\xc1\xfcc\xa4*\x99\xbe\\>\xb7\x10|<T\xe9\xb9\xeb+\xd5 ;\x1c;\x84\xe0\xa8\xb2\xf7Y@\x9b\xa3\xea\xc9\xd9\x1d@-\xcc\x0c\xc8\xf8\x96\x12)\xac\x91\x87\xb4+M\xe1\x00\x00\x0f\x00\x00\x84\x08\x04\x00\x80Zt|]\x88\xfa\x9b\xd2\xe5Z\xb0\x85\xa6\x10\x15\xb7!\x1f\x82L\xd4\x84\x14Z\xb3\xffR\xf1\xfd\xa8G{\x0bz\xbc\x90\xdbx\xe2\xd3:\\\x14\x1a\x07\x86S\xfak\xefx\x0c^\xa2H\xee\xaa\xa7\x85\xc4\xf3\x94\xca\xb6\xd3\x0b\xbe\x8dHY\xeeQ\x1f`)W\xb1T\x11\xac\x02vqE\x9eFD\\\x9e\xa5\x8c\x18\x1e\x81\x8e\x95\xb8\xc3\xfb\x0b\xf3\'\x84\t\xd3\xbe\x15*=\xa5\x04>\x06=\xdae\xcd\xf5\xae\xa2\rS\xdf\xac\xd4/t\xf3\x14\x00\x00 \x9b\x9b\x14\x1d\x90c7\xfb\xd2\xcb\xdc\xe7\x1d\xf4\xde\xdaJ\xb4,0\x95r\xcb\x7f\xff\xeeTT\xb7\x8f\x07\x18')
full_enc_rec = Bytes(0x17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b)
_, full_rec = TLSPlaintext.deserialize(full_enc_rec)


# server_write_key, server_write_iv = state.get_traffic_key(state.key_schedule[secret])
# encrypted_data  = full_rec.fragment.val.val
# additional_data = ContentType.application_data.serialize() + ProtocolVersion.TLSv12.serialize() + Bytes(674).zfill(2)


state.decrypt_server_application_data(TLSPlaintext.deserialize(full_enc_rec)[1])
