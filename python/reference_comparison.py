import binascii

import lmots
import lms
import hss


message = "The powers not delegated to the United States by the Constitution, nor prohibited by it to the States, are reserved to the States respectively, or to the people.\n"

msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )
msg_hex = binascii.hexlify( bytearray( msg_bytearray ))

reference_enc = "54686520706f77657273206e6f742064" \
                "656c65676174656420746f2074686520" \
                "556e6974656420537461746573206279" \
                "2074686520436f6e737469747574696f" \
                "6e2c206e6f722070726f686962697465" \
                "6420627920697420746f207468652053" \
                "74617465732c20617265207265736572" \
                "76656420746f20746865205374617465" \
                "7320726573706563746976656c792c20" \
                "6f7220746f207468652070656f706c65" \
                "2e0a"

print( binascii.hexlify( bytearray.fromhex( reference_enc ) ) == \
       binascii.hexlify( bytearray( msg_bytearray )) )




### HSS public key

hss_pub = {
    "L": 2,
    "pub0": {
        "typecode" : 5, 
        "ots_typecode" : 4,
        "I" :  bytearray.fromhex( "61a5d57d37f5e46bfb7520806b07a1b8" ),    
        "T1" : bytearray.fromhex( "50650e3b31fe4a773ea29a07f09cf2ea" + \
                                  "30e579f0df58ef8e298da0434cb2b878" ),
        "serialized": None        
    },
    "serialized": None
}
hss_pub["pub0"]["serialized"] = lms.lms_serialize_pub_key( hss_pub["pub0"]["typecode"],
                                                           hss_pub["pub0"]["ots_typecode"],
                                                           hss_pub["pub0"]["I"],
                                                           hss_pub["pub0"]["T1"] )
hss_pub["serialized"] = hss.hss_serialize_public_key( hss_pub["L"],
                                                      hss_pub["pub0"] )





### HSS signature

hss_sig1_lmots_C = "0703c491e7558b35011ece3592eaa5da" + \
                   "4d918786771233e8353bc4f62323185c"

hss_sig1_lmots_y = [
    "95cae05b899e35dffd71705470620998" + \
    "8ebfdf6e37960bb5c38d7657e8bffeef",
    "9bc042da4b4525650485c66d0ce19b31" + \
    "7587c6ba4bffcc428e25d08931e72dfb",
    "6a120c5612344258b85efdb7db1db9e1" + \
    "865a73caf96557eb39ed3e3f426933ac",
    "9eeddb03a1d2374af7bf771855774562" + \
    "37f9de2d60113c23f846df26fa942008",
    "a698994c0827d90e86d43e0df7f4bfcd" + \
    "b09b86a373b98288b7094ad81a0185ac",
    "100e4f2c5fc38c003c1ab6fea479eb2f" + \
    "5ebe48f584d7159b8ada03586e65ad9c",
    "969f6aecbfe44cf356888a7b15a3ff07" + \
    "4f771760b26f9c04884ee1faa329fbf4",
    "e61af23aee7fa5d4d9a5dfcf43c4c26c" + \
    "e8aea2ce8a2990d7ba7b57108b47dabf",
    "beadb2b25b3cacc1ac0cef346cbb90fb" + \
    "044beee4fac2603a442bdf7e507243b7",
    "319c9944b1586e899d431c7f91bcccc8" + \
    "690dbf59b28386b2315f3d36ef2eaa3c",
    "f30b2b51f48b71b003dfb08249484201" + \
    "043f65f5a3ef6bbd61ddfee81aca9ce6",
    "0081262a00000480dcbc9a3da6fbef5c" + \
    "1c0a55e48a0e729f9184fcb1407c3152",
    "9db268f6fe50032a363c9801306837fa" + \
    "fabdf957fd97eafc80dbd165e435d0e2",
    "dfd836a28b354023924b6fb7e48bc0b3" + \
    "ed95eea64c2d402f4d734c8dc26f3ac5",
    "91825daef01eae3c38e3328d00a77dc6" + \
    "57034f287ccb0f0e1c9a7cbdc828f627",
    "205e4737b84b58376551d44c12c3c215" + \
    "c812a0970789c83de51d6ad787271963",
    "327f0a5fbb6b5907dec02c9a90934af5" + \
    "a1c63b72c82653605d1dcce51596b3c2",
    "b45696689f2eb382007497557692caac" + \
    "4d57b5de9f5569bc2ad0137fd47fb47e",
    "664fcb6db4971f5b3e07aceda9ac130e" + \
    "9f38182de994cff192ec0e82fd6d4cb7",
    "f3fe00812589b7a7ce51544045643301" + \
    "6b84a59bec6619a1c6c0b37dd1450ed4",
    "f2d8b584410ceda8025f5d2d8dd0d217" + \
    "6fc1cf2cc06fa8c82bed4d944e71339e",
    "ce780fd025bd41ec34ebff9d4270a322" + \
    "4e019fcb444474d482fd2dbe75efb203",
    "89cc10cd600abb54c47ede93e08c114e" + \
    "db04117d714dc1d525e11bed8756192f",
    "929d15462b939ff3f52f2252da2ed64d" + \
    "8fae88818b1efa2c7b08c8794fb1b214",
    "aa233db3162833141ea4383f1a6f120b" + \
    "e1db82ce3630b3429114463157a64e91",
    "234d475e2f79cbf05e4db6a9407d72c6" + \
    "bff7d1198b5c4d6aad2831db61274993",
    "715a0182c7dc8089e32c8531deed4f74" + \
    "31c07c02195eba2ef91efb5613c37af7",
    "ae0c066babc69369700e1dd26eddc0d2" + \
    "16c781d56e4ce47e3303fa73007ff7b9",
    "49ef23be2aa4dbf25206fe45c20dd888" + \
    "395b2526391a724996a44156beac8082",
    "12858792bf8e74cba49dee5e8812e019" + \
    "da87454bff9e847ed83db07af3137430",
    "82f880a278f682c2bd0ad6887cb59f65" + \
    "2e155987d61bbf6a88d36ee93b6072e6",
    "656d9ccbaae3d655852e38deb3a2dcf8" + \
    "058dc9fb6f2ab3d3b3539eb77b248a66",
    "1091d05eb6e2f297774fe6053598457c" + \
    "c61908318de4b826f0fc86d4bb117d33",
    "e865aa805009cc2918d9c2f840c4da43" + \
    "a703ad9f5b5806163d7161696b5a0adc" ]
    
hss_sig1_lmots = {
    "typecode": 4,
    "C": bytearray.fromhex( hss_sig1_lmots_C ),
    "y": [ bytearray.fromhex(x) for x in hss_sig1_lmots_y ],
    "serialized": None
}
hss_sig1_lmots["serialized"] = lmots.lmots_serialize_signature(
    hss_sig1_lmots["typecode"],
    hss_sig1_lmots["C"],
    hss_sig1_lmots["y"] )


hss_sig1_lms_leaf_to_root = [
    "d5c0d1bebb06048ed6fe2ef2c6cef305" + \
    "b3ed633941ebc8b3bec9738754cddd60",
    "e1920ada52f43d055b5031cee6192520" + \
    "d6a5115514851ce7fd448d4a39fae2ab",
    "2335b525f484e9b40d6a4a969394843b" + \
    "dcf6d14c48e8015e08ab92662c05c6e9",
    "f90b65a7a6201689999f32bfd368e5e3" + \
    "ec9cb70ac7b8399003f175c40885081a",
    "09ab3034911fe125631051df0408b394" + \
    "6b0bde790911e8978ba07dd56c73e7ee" ]

hss_sig1_lms = {
        "q": 10, # 0xa
        "typecode": 5,
        "ots_signature": hss_sig1_lmots,
        "leaf_to_root_path": [ bytearray.fromhex(x) for x in hss_sig1_lms_leaf_to_root ],
        "serialized": None
}
hss_sig1_lms["serialized"] = lms.lms_serialize_signature(
    hss_sig1_lms["q"],
    hss_sig1_lms["typecode"],
    hss_sig1_lms["ots_signature"],
    hss_sig1_lms["leaf_to_root_path"] )




hss_pub1 =  {
    "typecode" : 5, 
    "ots_typecode" : 4,
    "I" :  bytearray.fromhex( "d2f14ff6346af964569f7d6cb880a1b6" ),    
    "T1" : bytearray.fromhex( "6c5004917da6eafe4d9ef6c6407b3db0" + \
                              "e5485b122d9ebe15cda93cfec582d7ab" ),
    "serialized": None
}
hss_pub1["serialized"] = lms.lms_serialize_pub_key( hss_pub1["typecode"],
                                                    hss_pub1["ots_typecode"],
                                                    hss_pub1["I"],
                                                    hss_pub1["T1"] )





hss_sig0_lmots_C = "d32b56671d7eb98833c49b433c272586" + \
                   "bc4a1c8a8970528ffa04b966f9426eb9"

hss_sig0_lmots_y = [
    "965a25bfd37f196b9073f3d4a232feb6" + \
    "9128ec45146f86292f9dff9610a7bf95",
    "a64c7f60f6261a62043f86c70324b770" + \
    "7f5b4a8a6e19c114c7be866d488778a0",
    "e05fd5c6509a6e61d559cf1a77a970de" + \
    "927d60c70d3de31a7fa0100994e162a2",
    "582e8ff1b10cd99d4e8e413ef469559f" + \
    "7d7ed12c838342f9b9c96b83a4943d16",
    "81d84b15357ff48ca579f19f5e71f184" + \
    "66f2bbef4bf660c2518eb20de2f66e3b",
    "14784269d7d876f5d35d3fbfc7039a46" + \
    "2c716bb9f6891a7f41ad133e9e1f6d95",
    "60b960e7777c52f060492f2d7c660e14" + \
    "71e07e72655562035abc9a701b473ecb",
    "c3943c6b9c4f2405a3cb8bf8a691ca51" + \
    "d3f6ad2f428bab6f3a30f55dd9625563",
    "f0a75ee390e385e3ae0b906961ecf41a" + \
    "e073a0590c2eb6204f44831c26dd768c",
    "35b167b28ce8dc988a3748255230cef9" + \
    "9ebf14e730632f27414489808afab1d1",
    "e783ed04516de012498682212b078105" + \
    "79b250365941bcc98142da13609e9768",
    "aaf65de7620dabec29eb82a17fde35af" + \
    "15ad238c73f81bdb8dec2fc0e7f93270",
    "1099762b37f43c4a3c20010a3d72e2f6" + \
    "06be108d310e639f09ce7286800d9ef8",
    "a1a40281cc5a7ea98d2adc7c7400c2fe" + \
    "5a101552df4e3cccfd0cbf2ddf5dc677",
    "9cbbc68fee0c3efe4ec22b83a2caa3e4" + \
    "8e0809a0a750b73ccdcf3c79e6580c15",
    "4f8a58f7f24335eec5c5eb5e0cf01dcf" + \
    "4439424095fceb077f66ded5bec73b27",
    "c5b9f64a2a9af2f07c05e99e5cf80f00" + \
    "252e39db32f6c19674f190c9fbc506d8",
    "26857713afd2ca6bb85cd8c107347552" + \
    "f30575a5417816ab4db3f603f2df56fb",
    "c413e7d0acd8bdd81352b2471fc1bc4f" + \
    "1ef296fea1220403466b1afe78b94f7e",
    "cf7cc62fb92be14f18c2192384ebceaf" + \
    "8801afdf947f698ce9c6ceb696ed70e9",
    "e87b0144417e8d7baf25eb5f70f09f01" + \
    "6fc925b4db048ab8d8cb2a661ce3b57a",
    "da67571f5dd546fc22cb1f97e0ebd1a6" + \
    "5926b1234fd04f171cf469c76b884cf3",
    "115cce6f792cc84e36da58960c5f1d76" + \
    "0f32c12faef477e94c92eb75625b6a37",
    "1efc72d60ca5e908b3a7dd69fef02491" + \
    "50e3eebdfed39cbdc3ce9704882a2072",
    "c75e13527b7a581a556168783dc1e975" + \
    "45e31865ddc46b3c957835da252bb732",
    "8d3ee2062445dfb85ef8c35f8e1f3371" + \
    "af34023cef626e0af1e0bc017351aae2",
    "ab8f5c612ead0b729a1d059d02bfe18e" + \
    "fa971b7300e882360a93b025ff97e9e0",
    "eec0f3f3f13039a17f88b0cf808f4884" + \
    "31606cb13f9241f40f44e537d302c64a",
    "4f1f4ab949b9feefadcb71ab50ef27d6" + \
    "d6ca8510f150c85fb525bf25703df720",
    "9b6066f09c37280d59128d2f0f637c7d" + \
    "7d7fad4ed1c1ea04e628d221e3d8db77",
    "b7c878c9411cafc5071a34a00f4cf077" + \
    "38912753dfce48f07576f0d4f94f42c6",
    "d76f7ce973e9367095ba7e9a3649b7f4" + \
    "61d9f9ac1332a4d1044c96aefee67676",
    "401b64457c54d65fef6500c59cdfb69a" + \
    "f7b6dddfcb0f086278dd8ad0686078df",
    "b0f3f79cd893d314168648499898fbc0" + \
    "ced5f95b74e8ff14d735cdea968bee74" ]
    
hss_sig0_lmots = {
    "typecode": 4,
    "C": bytearray.fromhex( hss_sig0_lmots_C ),
    "y": [ bytearray.fromhex(x) for x in hss_sig0_lmots_y ],
    "serialized": None
}
hss_sig0_lmots["serialized"] = lmots.lmots_serialize_signature(
    hss_sig0_lmots["typecode"],
    hss_sig0_lmots["C"],
    hss_sig0_lmots["y"] )



hss_sig0_lms_leaf_to_root = [
    "d8b8112f9200a5e50c4a262165bd342c" + \
    "d800b8496810bc716277435ac376728d",
    "129ac6eda839a6f357b5a04387c5ce97" + \
    "382a78f2a4372917eefcbf93f63bb591",
    "12f5dbe400bd49e4501e859f885bf073" + \
    "6e90a509b30a26bfac8c17b5991c157e",
    "b5971115aa39efd8d564a6b90282c316" + \
    "8af2d30ef89d51bf14654510a12b8a14",
    "4cca1848cf7da59cc2b3d9d0692dd2a2" + \
    "0ba3863480e25b1b85ee860c62bf5136" ]
hss_sig0_lms = {
        "q": 5,
        "typecode": 5,
        "ots_signature": hss_sig0_lmots,
        "leaf_to_root_path": [ bytearray.fromhex(x) for x in hss_sig0_lms_leaf_to_root ],
        "serialized": None
}
hss_sig0_lms["serialized"] = lms.lms_serialize_signature(
    hss_sig0_lms["q"],
    hss_sig0_lms["typecode"],
    hss_sig0_lms["ots_signature"],
    hss_sig0_lms["leaf_to_root_path"] )



hss_sig = {
    "Npsk": 1,
    "signed_pub_keys": [{
        "sig": hss_sig0_lms,
        "pub": hss_pub1,
        "serialized" : hss_sig0_lms["serialized"] + hss_pub1["serialized"]
    }],
    "msg_sig": hss_sig1_lms, 
    "serialized": None
}
hss_sig["serialized"] = hss.hss_serialize_signature(
    hss_sig["Npsk"],
    hss_sig["signed_pub_keys"],
    hss_sig["msg_sig"] )



### Verification

reference_verication = hss.hss_verify( msg_bytearray, hss_sig, hss_pub )
print( "Reference verification:", reference_verication )
