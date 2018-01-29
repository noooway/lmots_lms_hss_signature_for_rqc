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

# test exhaustion
print( "LMOTS signing 2'nd time" ) 
lmots_sign = lmots.lmots_sign( msg_bytearray, lmots_prv )
lmots_correct = lmots.lmots_verify( msg_bytearray, lmots_sign, lmots_pub )
print( lmots_correct )


### LMS 

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )


lms_typestring = "lms_sha256_m32_h5"
lms_prv, lms_pub = lms.lms_gen_keypair( lms_typestring )
lms_sign = lms.lms_sign( msg_bytearray, lms_prv )
lms_correct = lms.lms_verify( msg_bytearray, lms_sign, lms_pub )
print( lms_correct )

# test exhaustion
lms_h = 5
for i in range( 2**lms_h + 3 ):
    print( "LMS signing {}'th time".format( i + 1 ) ) 
    msg_bytearray = bytearray()
    msg_bytearray.extend( str(i).encode() )
    lms_sign = lms.lms_sign( msg_bytearray, lms_prv )
    lms_correct = lms.lms_verify( msg_bytearray, lms_sign, lms_pub )
    print( lms_correct )


### HSS

message = "go to hell"
msg_bytearray = bytearray()
msg_bytearray.extend( message.encode() )

L = 2
hss_prv, hss_pub = hss.hss_gen_keypair( L )
hss_sign = hss.hss_sign( msg_bytearray, hss_prv )
hss_correct = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
print( hss_correct )

# test exhaustion
default_lms_h = 5
n_of_keys = ( 2 ** default_lms_h ) ** L
for i in range( 1, n_of_keys + 3 ):
    print( "HSS signing {}'th time".format( i + 1 ) ) 
    msg_bytearray = bytearray()
    msg_bytearray.extend( str(i).encode() )
    hss_sign = hss.hss_sign( msg_bytearray, hss_prv )
    hss_correct = hss.hss_verify( msg_bytearray, hss_sign, hss_pub )
    print( hss_correct )
