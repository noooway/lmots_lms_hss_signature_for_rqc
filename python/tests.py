import lmots
import lms
import hss

### LMOTS

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

lmots_typestring = "lmots_sha256_n32_w2"
lmots_prv, lmots_pub = lmots.lmots_gen_keypair( lmots_typestring )
lmots_sign = lmots.lmots_sign( msg_bytearray, lmots_prv )
lmots_correct = lmots.lmots_verify( msg_bytearray, lmots_sign, lmots_pub )
print( lmots_correct )


### LMS 

# message = []
# message.append[ "only" ]
# message.append[ "way" ]
# message.append[ "to" ]
# message.append[ "feel" ]
# message.append[ "the" ]
# message.append[ "noise" ]
message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )


lms_typestring = "lms_sha256_m32_h5"
lms_prv, lms_pub = lms.lms_gen_keypair( lms_typestring )
lms_sign = lms.lms_sign( msg_bytearray, lms_prv )
lms_correct = lms.lms_verify( msg_bytearray, lms_sign, lms_pub )
print( lms_correct )


### HSS

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

L = 3
hss_prv, hss_pub = hss.hss_gen_keypair( L )
hss_sign = hss.hss_sign( msg_bytearray, hss_prv )
hss_correct = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
print( hss_correct )

