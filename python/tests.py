import lmots
import lms

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

typestring = "lmots_sha256_n32_w1"
prv, pub = lmots.lmots_gen_keypair( typestring )
sign = lmots.lmots_sign( msg_bytearray, prv )
correct = lmots.lmots_verify( msg_bytearray, sign, pub )
print( correct )


